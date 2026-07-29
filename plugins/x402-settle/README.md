# x402-settle

A ZeroClaw **WIT component** tool plugin implementing the `tool-plugin`
world from `wit/v0`, compiled to a `wasm32-wasip2` component, following the
pure-core/thin-shim layout of the canonical reference plugin
(`plugins/redact-text`). This is the settlement half of a two-part
delivery — its sibling, `plugins/x402-quote-check` (T0, never pays), ships
the same requirement-validation policy without ever touching a key. It lets
an agent pay for a paywalled resource on its own, from a small scoped
budget it can never exceed, with a human checkpoint before any money moves.

## What it does

The `x402_settle` tool pays for an [x402](https://github.com/coinbase/x402)-gated
resource through a two-phase approval gate. Called with no `action` (or
`action="propose"`), it fetches the resource, requires the server to
respond `HTTP 402` with payment requirements, validates every field a
malicious or compromised server could lie about (network, mint, amount,
recipient, timeout window), checks that paying would not push spend over a
cumulative 24-hour cap recomputed from real on-chain transfer history, and
verifies the destination is a real token account for the accepted mint —
then returns an `approval_token`, without signing or submitting anything.
Only a second call with `action="confirm"` and that exact, still-fresh
token builds and signs the transaction the x402 v2 "exact" Solana scheme
actually requires — `SetComputeUnitLimit`, `SetComputeUnitPrice`, then a
`TransferChecked` (not a plain `Transfer`) — with a scoped session key, and
retries the resource request with the `PAYMENT-SIGNATURE` proof. See
"Approval gate" below.

## Who it's for

An operator who wants a ZeroClaw agent to autonomously pay for x402-gated
resources — premium data feeds, per-call inference, any pay-per-use HTTP
API — without a human signing every transaction by hand, while staying
provably safe against a compromised server or a prompt-injected agent.
Pairs with `x402-quote-check` (its T0, read-only sibling) for the
non-paying half of the same flow.

## ZeroClaw features used

- **Tool plugin** (`wit/v0` `tool-plugin` world) — loaded via
  `plugins.enabled = true` and `zeroclaw plugin install`.
- **`http_client` permission** — fetches the 402 challenge, polls Solana
  RPC (slot, block time, transfer history, latest blockhash, destination
  account info, the asset mint's decimals), and retries the resource with
  the `PAYMENT-SIGNATURE` proof.
- **`config_read` permission** — the session key, RPC URL, session token
  account, and policy thresholds, injected via `__config`, decrypted from
  encrypted-at-rest storage. The session key is decoded only inside the
  `confirm` branch, after the approval token has already verified — never
  on a `propose` call.
- **Structured logging** via `log_record` — every outcome is traceable in
  the host's own log, never `stdout`.
- **The host's own `[Y/N/A]` approval prompt** layers on top of this
  plugin's internal `propose`/`confirm` gate — two independent checkpoints
  when both are enabled.
- Designed to be driven by a cron or channel-triggered **SOP** — `propose`
  and `confirm` are two separate tool calls, so an SOP approval checkpoint
  can sit between them.

## Approval gate

`execute()` takes an `action` argument, `"propose"` by default:

- **`propose`** runs every check above against live data and returns a
  summary plus an `approval_token`. It never touches the session key and
  never builds, signs, or submits a transaction.
- **`confirm`** requires that exact token and only then signs and submits.
  The token encodes the network, mint, recipient, amount, paying account,
  and fee payer it was issued for, plus an expiry (`current_slot + 200`,
  roughly 80–120 seconds) read fresh from the chain on both calls, never
  cached. A token that doesn't match this exact payment, or has gone stale,
  is rejected (`verify_approval_token`) and `confirm` falls back to
  `propose`'s safe, read-only behavior.

The token is plain text, not a cryptographic hash — nothing in it is
secret, and a legible code
(`v1:solana-mainnet:EPjF...:4Nd1m...:1000000:9WzD...:GVJJ...:193939421`) is
easier for a human to sanity-check in a chat message than an opaque blob
would be.
Its security value comes from requiring a second, explicit call before
anything is signed: a prompt-injected agent that calls this tool once still
only gets a read-only proposal.

This layers on top of, never replaces, the host's own `[Y/N/A]` prompt —
with both enabled, an operator sees two independent checkpoints per
payment. It is also not a substitute for a real "agent proposes, a Squads
multisig disposes" flow: that would require a genuinely different approver
than whoever is driving the agent, which this plugin cannot enforce on its
own. A real Squads integration remains future work (see "Roadmap").

## Config keys

| Key | Default | Secret? | Meaning |
|---|---|---|---|
| `session_key` | *(required)* | **Yes** | Base58 ed25519 key: a bare 32-byte seed, or the standard 64-byte Solana keypair export (`[seed \|\| pubkey]`). A 64-byte input's embedded pubkey is cross-checked against the one derived from its seed. Must be a scoped session key funded only with what the operator is willing to lose — never the main wallet. |
| `rpc_url` | *(required)* | No | Solana RPC endpoint. No hardcoded default. |
| `session_token_account` | *(required)* | No | The session key's own SPL token account for the accepted mint — the `source` in every transfer. See "Known limitations". |
| `expected_network` | `solana-mainnet` | No | Accepts flat spellings and CAIP-2 (`solana:<genesis-hash>`); any mismatch is a hard NO-GO. |
| `known_mint` | canonical mainnet USDC mint | No | Exact byte-for-byte match required. |
| `max_amount_atomic` | `5000000` (5.00 USDC) | No | Per-call cap. |
| `max_cumulative_atomic_24h` | `20000000` (20.00 USDC) | No | Rolling 24h cap, recomputed from on-chain history every call. |
| `max_timeout_seconds` | `300` | No | Ceiling on the server-requested `maxTimeoutSeconds`. |

Without `config_read` granted, this plugin cannot function at all — there
is no safe default for a session key or an RPC endpoint. That is correct
for a T2 component: it should be inert, not "working with defaults," until
deliberately provisioned.

## Layout

```
src/x402_settle.rs  # policy core (validation, cumulative cap, signing) — host-testable
src/transaction.rs  # transaction assembly via the modular solana-*/spl-token crates — host-testable
src/rpc_history.rs  # parses getTransaction responses into spend records — host-testable
src/account_verify.rs # destination token-account + asset-mint verification — host-testable
src/associated_token.rs # Associated Token Account (PDA) derivation — host-testable
src/lib.rs          # thin #[cfg(target_family = "wasm")] component shim
manifest.toml        # name, version, wasm_path, capabilities, permissions
```

## Build and test

```bash
cargo test --locked                                    # host tests, no wasm needed
rustup target add wasm32-wasip2
cargo build --locked --target wasm32-wasip2 --release  # the component
cp target/wasm32-wasip2/release/x402_settle.wasm x402_settle.wasm
```

No `solana-sdk`/`solana-client` (they don't target `wasm32-wasip2`), but
the **modular** `solana-pubkey`/`solana-instruction`/`solana-message`/
`solana-transaction`/`solana-hash`/`solana-compute-budget-interface` crates
plus `spl-token` (`default-features = false, features = ["no-entrypoint"]`)
do, and are used directly in `src/transaction.rs` for correct message
compilation and the exact `ComputeBudget`/`TransferChecked` instruction
shapes real x402 v2 Solana servers require — confirmed to compile clean to
this target (2026-07-27). Message/transaction signing itself is still
manual: `partial_sign`/`Message::serialize()` are gated behind those
crates' `wincode` feature, which conflicts in this dependency graph, so
`src/transaction.rs` serializes the message with plain `bincode` and signs
those bytes directly instead — simpler, and avoids the extra feature
surface entirely. Address handling elsewhere (config, approval tokens) is
still via `bs58`. `ed25519-dalek` compiles cleanly to `wasm32-wasip2` with
`default-features = false, features = ["fast", "zeroize"]` — no
`rand_core`/`getrandom` dependency, since Ed25519 signing is deterministic.
One real wasm-specific gotcha: `waki`'s `.header(key, value)` requires a
`'static` header name, so the one header this component sends
(`PAYMENT-SIGNATURE`) is passed as a literal, not through a generic list
(see `http_get`'s doc comment in `src/lib.rs`).

## Install

Copy this directory (the `.wasm` next to its `manifest.toml`) into your
configured plugins dir, enable plugins, and provision the session key (a
fresh keypair, funded only with what you're willing to risk) via
`zeroclaw config set`:

```toml
[plugins]
enabled = true
```

Run the agent with a build that includes a compiler backend, e.g.
`--features plugins-wasm,plugins-wasm-cranelift`. A `wit/v0/logging.wit`
vendoring drift against a real host build was found and fixed 2026-07-23
(shared with `x402-quote-check` — see its README); re-verified end to end
after the fix.

## Security model

Custody tier: **T2, sign and submit** — this cannot genuinely be T1. The
x402 "exact" scheme on Solana has no separate "prove intent to pay" step —
the signed transaction itself is the proof of payment, so there is no
unsigned artifact a human could review that would still satisfy the
server, the way a T1 plugin's unsigned transaction or Solana Pay URL
would. `x402-quote-check` exists precisely to cover that gap: an operator
can see exactly what *would* be paid before ever granting this plugin a
session key.

Because it is T2, the guardrails live entirely inside the plugin, never
delegated to the calling LLM: a scoped session key that is never the
operator's main wallet; two independent caps (per-call and a cumulative
24h cap recomputed from real on-chain history — the `tool-plugin` world is
stateless, so an in-memory counter would be meaningless); the propose/
confirm approval gate above; and a fail-closed default on every
network/parsing failure. The session key is scrubbed on drop
(`ed25519-dalek`'s `zeroize` feature), signing correctness is pinned
against RFC 8032 test vectors, and the transaction shape is fixed to
exactly three instructions — `SetComputeUnitLimit` (≤40,000 CU),
`SetComputeUnitPrice` (≤5 microlamports/CU), then a `TransferChecked` —
built via `spl-token`'s own instruction builder, never hand-encoded. The
session key is always the transfer *authority* and never signs any other
slot; the fee payer is either the address the server's `extra.feePayer`
names (the real-world case — a facilitator sponsoring gas, confirmed live
against Otto AI and x402.org) or, when absent, the session key itself
(self-funded fallback). Either way the transaction is built by the exact
same code path (`transaction::build_transfer_checked_transaction`) and
this plugin only ever signs its own authority slot — never the fee payer's
— so a sponsored transaction is deliberately left partially signed for the
facilitator to complete. No code path exists for `Withdraw`, `Burn`, or any
other instruction.

## Threat model

The server on the other end of an x402 challenge is not trusted — it
unilaterally decides the price, the recipient, and the network. Shares
`x402-quote-check`'s policy checks (duplicated by necessity, since this
crate cannot depend on a sibling plugin — see `src/x402_settle.rs`), plus
two vectors specific to actually signing and paying:

| # | Attack | Defense | Verified by |
|---|---|---|---|
| 8 | Draining via many small payments across separate `execute()` calls, spaced further apart than RPC confirmation time | `check_cumulative_cap` sums real on-chain history over the trailing 24h, independent of the per-call cap | `cap_sums_recent_transfers_and_denies_over_cap` |
| 9 | Prompt injection via the 402 body's free-text fields | Only structural fields ever reach a policy decision; no code path from response prose to a spend decision | `rejects_prompt_injection_disguised_as_a_message_field` (`tests/adversarial.rs`) |
| 10 | A single call going straight from "402 received" to "signed and submitted" | `confirm` requires a fresh, matching `approval_token` a prior `propose` call issued — one call alone can only ever produce a read-only proposal | `approval_token_rejects_a_different_amount_than_it_was_issued_for`, `approval_token_rejects_one_slot_past_expiry` (`src/x402_settle.rs`) |

**Third-party trust: the facilitator (`extra.feePayer`).** When a server
sponsors gas, this plugin hands it a partially-signed transaction — the
facilitator adds its own fee-payer signature and broadcasts. That is a
real third party in the trust boundary, and here is exactly what trusting
it does and doesn't expose: it **cannot** redirect funds, change the
amount, or substitute a different mint or destination, because doing so
would change the message bytes and invalidate this plugin's own
authority-slot signature (`signature_does_not_verify_against_a_tampered_amount`,
`mismatched_fee_payer_pubkey_produces_a_transaction_that_fails_to_verify`
— both in `tests/adversarial.rs`) — the transaction is cryptographically
sealed on every field except who pays gas. It **can** withhold
broadcasting a valid transaction (a griefing/availability risk, not a
funds-safety one — the session key's tokens never leave until a
`TransferChecked` actually lands) or, in principle, misreport gas costs
it's covering. This plugin does not verify the facilitator's identity
beyond taking whatever address the server's `extra.feePayer` names; an
operator who doesn't trust a given server's chosen facilitator should not
grant `x402-settle` a session key against that server.

**Known limit on #8, found in a third-party audit (2026-07-24):** the
cumulative cap is recomputed from on-chain history on every call, since the
`tool-plugin` world gives `execute` a fresh store each time and holds no
in-memory counter. That means it only sees a transfer once it lands on
chain. A burst of `confirm` calls fired faster than RPC confirmation
latency (each reading history before the previous transfer is visible) can
each observe `spent_in_window ≈ 0` and approve independently, pushing real
spend above `max_cumulative_atomic_24h`. History reads now request
`commitment: "confirmed"` explicitly rather than the RPC's implicit
default, which narrows this window but does not close it — closing it for
good needs the host to serialize `x402_settle` calls for the same session
key, which is outside this plugin's control.

A four-vector injection probe (real 175-word payload) plus a canary in
place of the real session key confirmed the key value never appears in any
verdict string, in any of the three runs — consistent with
`SettlePolicyConfig` and `PaymentRequirement`/`Verdict` being disjoint
types with no code path between them. A live run against a real
Gemini-backed ZeroClaw agent, told to obey anything the tool or server
asked, refused a non-HTTPS resource before ever reaching the signing code,
and refused to fabricate a payment confirmation for a tool call that never
happened. Fuzzing (`cargo fuzz`, two targets — response parsing and
cumulative-cap arithmetic) ran 3.3M+ executions with zero crashes.

A real signed SPL `Transfer` (the instruction shape this plugin used
before the 2026-07-27 `TransferChecked`/`ComputeBudget`/sponsored-fee-payer
rewrite below), built and signed by this crate's own code (not a
reimplementation), was submitted to Solana devnet and independently
confirmed `finalized` on-chain, with real token balances moving (source
100 → 99, destination 0 → 1) — direct proof the signing/serialization
logic produces transactions the real network accepts, not just
internally-consistent bytes. Every RPC shape this plugin depends on
(`getAccountInfo`, `getTransaction`, `getSignaturesForAddress`,
`getLatestBlockhash`, `getBlockTime`, the `minContextSlot` staleness
guard, the unfunded-account path) was checked against real devnet
responses, not modeled fixtures alone. **The current `TransferChecked` /
`ComputeBudget` / sponsored-fee-payer shape has since been re-verified the
same way, end to end, against a live facilitator (2026-07-28):** a real
`propose`→`confirm` run against the deployed PayAI Echo Merchant fork
(`x402-echo-merchant.vercel.app`, devnet) returned HTTP 200, and the
resulting transaction
(`4NAXfdJsoo8DJszFxhaXiChdFXANtv4WKgMuvnWLN59iAPM1CLvdo26NevnbrCvsJxK39HbiAivdiEATT91f8ZPP`)
was independently confirmed on-chain: account 0 (fee payer, signed by the
facilitator, not this plugin) is `CKPKJWNdJEqa81x7CkZ14BVPiY6y16Sxs7owznqtWYp5`
— the exact address this plugin read from the real `extra.feePayer` field
— account 1 (transfer authority, signed by this plugin's session key) is
the session key's own pubkey, the instruction list is
`SetComputeUnitLimit`/`SetComputeUnitPrice`/`transferChecked` in that
order, `err: null`, and the source token account's real balance moved
100.000000 → 99.999000 (mint decimals fetched live via `getAccountInfo`,
not assumed). Direct, independently-checked proof that the rewritten
envelope, header, instruction shape, and sponsorship model are accepted by
a real x402 v2 facilitator, not just internally self-consistent.

A follow-up security-focused review pass fixed three findings in code:
SOL-fee griefing from an unverified destination account (closed by
`account_verify.rs`'s pre-signing check), silent under-counting of spend
history from a lagging RPC node (closed by threading a fresh
`minContextSlot` through every read), and session-key zeroization on the
config string, not just the decoded seed. One residual, low-severity item
is documented rather than silently accepted: a server using the flat
Solana Foundation 402 shape (which has no `maxTimeoutSeconds` field) skips
that specific check — mitigated in practice by Solana's own ~60–90 second
blockhash expiry, which bounds exposure regardless of what the server
claims.

## Worked example

First, the `propose` call (also what happens if `action` is omitted):

```json
{ "resource_url": "https://api.example.com/premium-market-data" }
```

```json
{
  "success": true,
  "output": "PROPOSED, NOT YET PAID: 500000 atomic units of EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v to <payTo> on solana-mainnet. Nothing has been signed or submitted. To actually pay, call this tool again with action=\"confirm\" and approval_token=\"v1:solana-mainnet:EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v:<payTo>:500000:<session_token_account>:<feePayer>:193939421\" before slot 193939421.",
  "error": null
}
```

Then, within the window, `confirm` with that exact token actually pays:

```json
{
  "resource_url": "https://api.example.com/premium-market-data",
  "action": "confirm",
  "approval_token": "v1:solana-mainnet:EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v:<payTo>:500000:<session_token_account>:<feePayer>:193939421"
}
```

```json
{
  "success": true,
  "output": "paid 500000 atomic units of EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v to <payTo> — resource returned HTTP 200",
  "error": null
}
```

A stale or mismatched token falls back to a safe denial:

```json
{
  "success": false,
  "output": "",
  "error": "approval_token expired at slot 193939421 (current slot is 193939700) — call again with action=\"propose\" to get a fresh one"
}
```

## Known limitations

- **`session_token_account` is operator-configured, not derived on-chain** —
  deriving the associated token account requires a PDA search, out of
  scope for v0.1.
- **History fetch is bounded** (`SIGNATURES_FETCH_LIMIT` = 200 signatures
  fetched, `MAX_HISTORY_TRANSACTIONS_TO_FETCH` = 100 inspected per
  `execute()` call), to keep one call from turning into an unbounded number
  of RPC round trips. Unlike an earlier revision of this limit, going over
  it does not silently undercount spend: if more than 100 signatures fall
  inside the 24h window, `confirm` refuses to pay rather than inspect only
  a subset.
- **The 24h window's clock comes from the cluster** (`getSlot` +
  `getBlockTime`), not a local wall-clock — the WIT world exposes no clock
  import. The window boundary is only as trustworthy as the RPC endpoint.
- **`payTo` may be a wallet or a token account, but must already exist.**
  Real x402 servers (confirmed 2026-07-27 against two independent live
  deployments, Otto AI and PayAI) publish `payTo` as the recipient's
  *wallet* address, not a token account — `src/associated_token.rs` derives
  the Associated Token Account (PDA) for (wallet, mint) and verifies that
  instead. `payTo`-as-token-account is tried first for backward
  compatibility with any server that publishes one directly. Either way,
  there is still **no create-ATA-if-missing step**: if neither `payTo`
  itself nor its derived ATA exists as an initialized token account for
  the mint, `confirm` refuses to sign — a clear, attributable failure
  before any fee is spent, not a silent one or an on-chain failure.
- **Only the classic SPL Token program, not Token-2022.** `token_program_bytes`
  is always the fixed `TokenkegQfeZ...` constant; a mint owned by
  `TOKEN_2022_PROGRAM_ADDRESS` is never detected or handled specially — the
  destination/mint account-verification checks would simply fail closed
  (`NotOwnedBySplToken`) rather than silently mis-signing, but a real
  Token-2022-denominated x402 offer cannot currently be paid at all.
- **One extra RPC round-trip per call.** Building a spec-correct
  `TransferChecked` requires the mint's `decimals`, which the x402 payment
  requirements response never carries (confirmed absent from every real
  response captured this session) — so every `propose` and `confirm` call
  now also fetches `getAccountInfo` on the asset mint. Not currently
  batched with the destination-account lookup already made in the same
  call.

## Roadmap

- Derive `session_token_account` on-chain instead of requiring it in config.
- Create the destination associated token account when missing (via a
  `CreateAssociatedTokenAccountIdempotent` instruction bundled into the same
  transaction), rather than refusing to sign — the ATA is now derived and
  verified (see "Known limitations"), just not created if absent.
- Raise or paginate the history-fetch bound once real-world usage patterns
  are understood.
- Token-2022 mint support (detect the owning token program from the mint
  account instead of assuming the classic SPL Token program).
- A real Squads-multisig "propose, dispose" integration, strictly after the
  current propose/confirm gate is proven in production use.

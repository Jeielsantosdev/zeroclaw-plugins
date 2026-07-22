# x402-settle

A ZeroClaw **WIT component** tool plugin implementing the `tool-plugin` world
from `wit/v0`, compiled to a `wasm32-wasip2` component, following the
pure-core/thin-shim layout of the canonical reference plugin
(`plugins/redact-text`). This is the settlement half of a two-part delivery —
its sibling, `plugins/x402-quote-check` (T0, never pays), ships the same
requirement-validation policy without ever touching a key.

## What it does

The `x402_settle` tool pays for an [x402](https://github.com/coinbase/x402)-gated
resource. It fetches the resource, requires the server to respond `HTTP 402`
with payment requirements, validates every field a malicious or compromised
server could lie about (network, mint, amount, recipient, timeout window),
checks that paying would not push the session's spend over a **cumulative
24-hour cap recomputed from real on-chain transfer history**, then builds and
signs an SPL Token `Transfer` with a scoped session key and retries the
resource request with the `X-Payment` proof.

## Custody tier: T2 (sign and submit)

This is, by the protocol's own nature, the one idea in this repository that
cannot be genuinely T1. The x402 "exact" scheme on Solana has no separate
"prove intent to pay" step — **the signed transaction itself is the proof of
payment**. There is no unsigned artifact a human could review that would
still satisfy the server. See `plugin-x420/x402.md` §5 for the reasoning that
led to phasing this as two components instead: `x402-quote-check` (T0) exists
specifically so an operator (or a judge) can see exactly what *would* be paid
before ever granting this plugin a session key.

Because it is T2, the guardrails live entirely inside the plugin, never
delegated to the calling LLM:

- **Scoped session key only.** The key configured here must never be the
  operator's main wallet — see "Config keys" below. Nothing in this crate
  reads, requests, or has any code path toward a different key.
- **Two independent caps.** A per-call amount cap (`max_amount_atomic`) *and*
  a cumulative 24h cap (`max_cumulative_atomic_24h`) — the second one closes
  the "many small payments" bypass the first one alone would allow.
- **The cumulative cap is derived from the chain, not from memory.** The
  `tool-plugin` world gives `execute` a fresh store on every single
  invocation — there is no persisted state between calls. A counter kept in
  the plugin's own memory would silently reset on every call and create a
  false sense of a cap that was never actually enforced. Instead, every call
  re-fetches the session account's own recent transfer history
  (`getSignaturesForAddress` + `getTransaction`) and recomputes the real
  spend before deciding whether to proceed.
- **Fail closed on every network/parsing failure.** If the history fetch,
  the blockhash fetch, or the clock fetch fails for any reason, the plugin
  refuses to pay rather than proceeding on stale or assumed data.

## Config keys

| Key | Default | Secret? | Meaning |
|---|---|---|---|
| `session_key` | *(required, no default)* | **Yes** | Base58-encoded 32-byte ed25519 seed. Must be a scoped session key funded only with what the operator is willing to lose — never the main wallet. Read only via `config_read`/`__config`; never logged (see "wasm32-wasip2 notes"). |
| `rpc_url` | *(required, no default)* | No | Solana RPC endpoint. No hardcoded default — unlike the mint/network/caps below, there is no generically "safe" RPC endpoint to assume. |
| `session_token_account` | *(required, no default)* | No | The session key's own SPL token account for the accepted mint — the `source` in every transfer this plugin builds. See "Known limitations". |
| `expected_network` | `solana-mainnet` | No | Rejects any 402 whose network doesn't normalize to this. |
| `known_mint` | canonical mainnet USDC mint | No | Exact byte-for-byte match required — a lookalike mint is rejected, never accepted "close enough". |
| `max_amount_atomic` | `5000000` (5.00 USDC) | No | Per-call cap. |
| `max_cumulative_atomic_24h` | `20000000` (20.00 USDC) | No | Rolling 24h cap, recomputed from on-chain history every call. |
| `max_timeout_seconds` | `300` | No | Ceiling on the server-requested `maxTimeoutSeconds`. |

Without `config_read` granted, this plugin cannot function at all — there is
no safe default for a session key or an RPC endpoint, unlike its T0 sibling.
That is expected and correct for a T2 component: it should be inert, not
"working with defaults," if the operator hasn't deliberately provisioned it.

## Threat model

The server on the other end of an x402 challenge is **not trusted** — see
`plugins/x402-quote-check/README.md`'s threat model for the full table (this
plugin shares the exact same `validate_requirements` policy, duplicated by
necessity — see "Why this duplicates x402-quote-check" in
`src/x402_settle.rs`). Two additional vectors are specific to actually
signing and paying:

| # | Attack | Defense | Verified by |
|---|---|---|---|
| 8 | Drenagem por parcelamento across multiple `execute()` calls over time (not just within one 402 challenge) | `check_cumulative_cap` sums real on-chain transfer history over the trailing 24h before ever signing, independent of the per-call cap | `cap_sums_recent_transfers_and_denies_over_cap`, `cap_denies_exactly_at_the_boundary_going_over` (`src/x402_settle.rs`) |
| 9 | Prompt injection via the 402 body's own free-text fields, trying to convince the agent/LLM to raise a cap or approve an unsigned override | `validate_requirements` and `check_cumulative_cap` never read any free-text field — only structural fields (`network`, `asset`, `amount`, `payTo`, `maxTimeoutSeconds`, and on-chain-derived transfer amounts) ever reach a policy decision. There is no code path from response prose, or from RPC error text, to a spend decision | Inherited from `x402-quote-check`'s `rejects_prompt_injection_disguised_as_a_message_field` (identical policy core) |

Additional guarantees specific to signing:

- **The session key never leaves this crate's process, and is scrubbed on
  drop.** `ed25519-dalek`'s `zeroize` feature is enabled specifically so the
  `SigningKey` (and the seed it wraps) are zeroized when they go out of
  scope — see `sign_message`'s doc comment in `src/x402_settle.rs`.
- **Signing correctness is pinned against RFC 8032 Test Vector 1**, not just
  "looks right" — `sign_message_matches_rfc8032_test_vector_1`.
- **The transaction shape is fixed, not general.** `src/transaction.rs`
  builds exactly one instruction shape (fee payer = transfer authority =
  session key, signing an SPL Transfer) with a hardcoded account ordering.
  There is no code path for `Withdraw`, `Burn`, or any other SPL Token
  instruction — narrower surface, not a missing feature.
- **The transaction's own signature is verified in tests** by running it
  back through `ed25519-dalek`'s verifier against the exact message bytes
  that were signed (`signed_transaction_signature_verifies_against_the_message_bytes`),
  not just asserted to be 64 bytes long.

## Worked example

Given a legitimate x402 challenge for 0.50 USDC on `solana-mainnet`, under
default policy with a properly configured session key and token account:

```json
{ "resource_url": "https://api.example.com/premium-market-data" }
```

```json
{
  "success": true,
  "output": "paid 500000 atomic units of EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v to <payTo> — resource returned HTTP 200",
  "error": null
}
```

If the cumulative 24h cap would be exceeded instead:

```json
{
  "success": false,
  "output": "",
  "error": "cumulative spend over the trailing 24h would reach 21000000 atomic units, exceeding the configured cap of 20000000 (16000000 already spent + 5000000 requested now)"
}
```

## Known limitations (stated, not hidden)

- **`session_token_account` is operator-configured, not derived on-chain.**
  Deriving the associated token account address requires a
  `find_program_address`-style PDA search (repeated SHA-256 hashing against
  the ed25519 curve), deliberately out of scope for v0.1. The operator must
  supply their session's own token account address directly.
- **History fetch is bounded to the 50 most recent signatures**
  (`MAX_HISTORY_SIGNATURES`) on the session's token account, to keep one
  `execute()` call from turning into an unbounded number of RPC round trips.
  A session account with more than 50 transactions in 24h would undercount
  its own spend — a real bound worth knowing, not a silent gap.
- **The 24h window's clock comes from the cluster** (`getSlot` +
  `getBlockTime`), not any local wall-clock source — the `tool-plugin` WIT
  world exposes no clock import. This means the window boundary is exactly
  as trustworthy as the configured RPC endpoint; a malicious RPC could in
  principle skew it. Documented as a residual trust boundary, same as the
  RPC endpoint itself is for every other read in this plugin.
- **`rpc_history` fixture JSON is modeled on documented RPC response shapes,
  not captured from a live call** (no live RPC access in the environment
  this was built in) — flagged explicitly in `src/rpc_history.rs`, and worth
  re-verifying against one real `getTransaction` response before merge.
- **No create-ATA-if-missing step.** If the destination token account in a
  402 challenge doesn't exist yet, the built transaction will fail on-chain
  at submission (a clear, attributable failure — not a silent loss of
  funds), rather than this plugin silently creating an account on the
  operator's behalf.

## Layout (the reference format)

```
src/x402_settle.rs  # policy core (validation, cumulative cap, signing) — host-testable
src/transaction.rs   # manual Solana legacy transaction wire-format assembly — host-testable
src/rpc_history.rs   # parses getTransaction responses into spend records — host-testable
src/lib.rs           # thin #[cfg(target_family = "wasm")] component shim
manifest.toml        # name, version, wasm_path, capabilities, permissions
```

## `wasm32-wasip2` notes

- No `solana-sdk`/`solana-client` — hand-rolled transaction serialization in
  `src/transaction.rs` and address handling via `bs58`, same discipline as
  the rest of this repository.
- `ed25519-dalek` compiles cleanly to `wasm32-wasip2` with
  `default-features = false, features = ["fast", "zeroize"]` — no
  `rand_core`/`getrandom` dependency at all, because Ed25519 signing is
  deterministic and needs no randomness. Verified directly against a
  wasm32-wasip2 build before committing to this approach.
- `base64` (0.22, `alloc` feature only) compiles cleanly to the target too.
- **A real `wasm32-wasip2`-adjacent gotcha found while building this:**
  `waki`'s `.header(key, value)` requires the header *name* to satisfy
  `IntoHeaderName`, which for `&str` is only implemented for `&'static str`.
  A generic `headers: &[(&str, &str)]` parameter compiles fine on paper but
  fails with `E0521: borrowed data escapes outside of function`, because the
  slice's lifetime isn't `'static`. Fixed by passing the one header this
  component ever sends (`X-Payment`) as a literal, not through a generic
  list — see `http_get`'s doc comment in `src/lib.rs`.

## Build and test

```bash
cargo test --locked                                    # host tests, no wasm needed
rustup target add wasm32-wasip2
cargo build --locked --target wasm32-wasip2 --release  # the component
cp target/wasm32-wasip2/release/x402_settle.wasm x402_settle.wasm
```

## Install

Copy this directory (the `.wasm` next to its `manifest.toml`) into your
configured plugins dir, then enable plugins and provision the session key
(a fresh keypair, funded only with what you're willing to risk — never your
main wallet) via `zeroclaw config set`:

```toml
[plugins]
enabled = true
```

Run the agent with a build that includes a compiler backend, e.g.
`--features plugins-wasm,plugins-wasm-cranelift`.

## Second audit pass — findings from targeted skill-based review

A follow-up audit specifically applied several security-focused review lenses
(Solana account/CPI patterns, constant-time crypto analysis, session-key
memory hygiene, fail-open-default detection) against this crate. Three
findings were fixed in code (session-key zeroization, SOL-fee griefing, RPC
staleness — see git history); one is a residual risk judged low-severity and
already mitigated elsewhere, recorded here rather than left implicit:

- **~~SOL transaction-fee exposure is not capped by `max_amount_atomic`/
  `max_cumulative_atomic_24h`~~ — fixed.** Those caps are denominated
  entirely in the accepted token mint (USDC); a malicious server could have
  supplied a syntactically valid `payTo` (passes the 32-byte base58 check)
  that is not actually an initialized SPL token account for the configured
  mint, and Solana still charges the fee payer's base SOL fee for a
  submitted-but-failing transaction regardless of instruction failure.
  `src/account_verify.rs` now calls `getAccountInfo` and verifies the
  destination is owned by the SPL Token program, is a parsed token account,
  and matches the exact configured mint — all before this plugin ever signs
  anything.
- **~~`getSignaturesForAddress` history fetch has no staleness
  cross-check~~ — fixed.** A lagging RPC endpoint's view (not necessarily
  malicious — could just be a slow public node) could previously make
  `check_cumulative_cap` silently under-count real recent spend, since a
  short-but-genuine-looking list wasn't distinguishable from a genuinely
  short history. The current slot is now read once per `execute()` call and
  threaded through as `minContextSlot` on both `getSignaturesForAddress` and
  `getTransaction` — a node that hasn't caught up to that slot errors
  instead of silently serving stale data, the same defense at least one
  competing submission in this repository already uses.
- **A server can skip the `maxTimeoutSeconds` ceiling entirely by using the
  Solana Foundation flat 402 shape**, which structurally has no such field —
  `validate_requirements` applies no check when the field is simply absent
  (see `PaymentRequirement::max_timeout_seconds: Option<u64>`'s doc comment).
  Considered a fail-open risk during this audit pass, but concluded low
  actual severity: the real bound on how long a signed-but-unsubmitted
  transaction stays valid is Solana's own recent-blockhash expiry
  (~60–90 seconds), enforced by the network itself independent of anything
  the server claims about its own acceptance window. Left as-is rather than
  papered over with a check that would either always pass (defaulting the
  missing field to the ceiling itself) or break every legitimate
  flat-shape server (treating "absent" as "deny").
- **Constant-time review of the signing path** (`sign_message`,
  `session_key_pubkey` in `src/x402_settle.rs`): no secret-dependent
  branching exists in this crate's own code — the seed flows straight into
  `ed25519_dalek::SigningKey::from_bytes` with no intermediate comparisons or
  conditionals on its byte content. `ed25519-dalek`'s `"fast"` feature
  (enabled in `Cargo.toml`) adds precomputed basepoint-multiplication tables
  for speed; it does not trade away constant-time guarantees — `curve25519-dalek`
  (the underlying field/scalar arithmetic) uses the `subtle` crate for
  conditional selects specifically to avoid secret-dependent branches or
  table-index leaks, matching this project's convention of delegating actual
  cryptographic correctness to a reviewed library rather than hand-rolling
  primitives. (The fully automated byte-level analyzer this audit pass would
  otherwise have used to double-check assembly output was not available in
  this environment — this conclusion is a manual review against the Rust
  guidance in that tool's own reference docs, not a tool-generated report.)

## Roadmap

- Derive `session_token_account` on-chain instead of requiring it in config.
- Create the destination associated token account when it doesn't exist yet
  (today, `account_verify` correctly refuses to sign in that case rather
  than losing funds or fees — creating the account would turn that refusal
  into a successful payment instead).
- Raise `MAX_HISTORY_SIGNATURES` or paginate once real-world usage patterns
  are understood.
- The optional CCTP/Circle Arc complement described in
  `plugin-x420/x402.md` §6 — strictly after this plugin is solid, never before.

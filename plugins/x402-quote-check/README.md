# x402-quote-check

A ZeroClaw **WIT component** tool plugin implementing the `tool-plugin`
world from `wit/v0`, compiled to a `wasm32-wasip2` component, following the
pure-core/thin-shim layout of the canonical reference plugin
(`plugins/redact-text`). Before an agent pays for anything, this checks
whether the price is real, expected, and safe — without spending a cent to
find out.

## What it does

The `x402_quote_check` tool fetches a URL expected to be gated by the
[x402 protocol](https://github.com/coinbase/x402) (agent-to-machine
micropayments over HTTP, reusing the `402 Payment Required` status code).
If the server responds `402` with payment requirements, the plugin parses
them and validates every field a malicious or compromised server could lie
about — network, token mint, amount, recipient, and payment window —
against operator-configured policy, returning a plain-language **GO /
NO-GO** verdict with reasons.

It never pays anything: no session key, no transaction, no signature. It is
the read-only half of a two-part delivery — `x402-settle` (T2) reuses this
plugin's policy core as an internal precondition, so it never pays for a
resource this plugin would reject.

## Who it's for

An operator running a ZeroClaw agent that consumes x402-gated APIs or data
feeds (market data, inference, any pay-per-call HTTP resource) and wants a
code-enforced answer to "would paying for this be safe?" before ever
handing the agent a signing key — whether as a precondition to
`x402-settle` or as a standalone safety check on its own.

## ZeroClaw features used

- **Tool plugin** (`wit/v0` `tool-plugin` world) — loaded via
  `plugins.enabled = true` and `zeroclaw plugin install`.
- **`http_client` permission** — one `GET` to the operator-specified
  `resource_url`, nothing else.
- **`config_read` permission** — reads this plugin's own config section via
  `__config`; runs safely on conservative defaults if never configured.
- **Structured logging** via the `logging` WIT import — every invocation is
  traceable in the host's own log, never `stdout`.
- Composable from any agent, channel, or SOP that can call a registered
  tool — for example, a cron SOP that checks a resource's current price
  before letting `x402-settle` pay for it.

## Config keys

Read from this plugin's own config section. All keys have safe,
conservative defaults, including on an unprivileged install with no
`config_read` granted.

| Key | Default | Meaning |
|---|---|---|
| `expected_network` | `solana-mainnet` | Rejects any 402 whose `network`/`cluster` doesn't normalize to this. Accepts flat spellings (`solana-mainnet`/`mainnet-beta`/`mainnet`, `solana-devnet`/`devnet`) and CAIP-2 (`solana:<genesis-hash>`). |
| `known_mint` | canonical mainnet USDC mint | Exact byte-for-byte match required — a lookalike mint is rejected, never accepted "close enough". |
| `max_amount_atomic` | `5000000` (5.00 USDC) | Per-call cap. A 402 asking for more is a NO-GO regardless of any other field. |
| `max_timeout_seconds` | `300` | Ceiling on the server-requested payment window. Absent from a response is not itself a rejection. |

Two shapes are accepted for the same 402 response: the cross-chain x402
spec v2 `accepts[]` array, and the flatter shape from the Solana
Foundation's own tutorial. Live servers (Otto AI, Syra, confirmed
2026-07-23) use spec v2 with a CAIP-2 `network` (`solana:<genesis-hash>`);
`SolanaCluster::parse` normalizes all spellings before comparison. Accepting
either shape is schema tolerance, not leniency — every field still goes
through the same `validate_requirements` check below (`src/x402.rs`).

## Layout

```
src/x402.rs   # pure policy core, no wasm deps — host-testable with `cargo test`
src/lib.rs    # thin #[cfg(target_family = "wasm")] component shim
tests/        # host-run integration tests over the pure core
manifest.toml # name, version, wasm_path, capabilities, permissions
```

## Build and test

```bash
cargo test --locked                                    # host tests, no wasm needed
rustup target add wasm32-wasip2
cargo build --locked --target wasm32-wasip2 --release  # the component
cp target/wasm32-wasip2/release/x402_quote_check.wasm x402_quote_check.wasm
```

No `solana-sdk`/`solana-client` — they don't target `wasm32-wasip2`.
Address validation uses `bs58` directly; HTTP is `waki` (WASI-native),
never `reqwest`.

## Install

Copy this directory (the `.wasm` next to its `manifest.toml`) into your
configured plugins dir, then enable plugins:

```toml
[plugins]
enabled = true
```

Run the agent with a build that includes a compiler backend, e.g.
`--features plugins-wasm,plugins-wasm-cranelift`. A `wit/v0/logging.wit`
vendoring drift against a real host build was found and fixed 2026-07-23
(the checked-in file was missing a `plugin-action` variant the host
already had); re-verified end to end after the fix — this component now
registers and runs correctly against a real host, real LLM, and a real
x402 server.

## Security model

Custody tier: **T0, read-only.** There is no transaction builder, signer,
or wallet secret anywhere in this crate, and no write RPC method — no code
path here can move funds even if every check below were bypassed. The only
outbound call is a `GET` to the operator-specified `resource_url`; the only
output is a short text verdict.

Every check in `validate_requirements` runs independently and *adds* to a
list of reasons — there is no early "looks fine, skip the rest" path, and
the function has exactly two outcomes, `Go` or `NoGo`, never a silent
default to either. `execute` never panics on bad input: malformed
arguments, unparseable bodies, and oversized responses all produce
`ToolResult { success: false, .. }`, never an `Err` — `Err` is reserved for
a genuinely broken component, not a hostile or malformed input.

## Threat model

The server on the other end of an x402 challenge is, by definition, **not
trusted** — it unilaterally decides the price, the recipient, and the
network. This plugin's job is to not take any of that at face value.

| # | Attack | Defense | Verified by |
|---|---|---|---|
| 1 | Amount just over the configured per-call cap | Checked against `max_amount_atomic`; any excess is a hard NO-GO | `end_to_end_no_go_on_installment_draining_attempt` |
| 2 | Mint address that visually resembles USDC but isn't | Exact string match against `known_mint`, never fuzzy/prefix | `end_to_end_no_go_on_lookalike_mint_attack` |
| 3 | Free-text field trying to convince the agent to raise a cap or ignore the verdict | `validate_requirements` never reads free-text fields — only structural fields reach policy | `rejects_prompt_injection_disguised_as_a_message_field` (`tests/x402.rs`) |
| 4 | Wrong network/cluster claimed | Normalized comparison against `expected_network`; mismatch is a hard NO-GO | `end_to_end_no_go_on_solana_foundation_flat_shape_wrong_cluster` |
| 5 | Malformed, truncated, or garbage `payTo` | Must base58-decode to exactly 32 bytes | `validate_rejects_malformed_payto` |
| 6 | Unreasonably long payment window | Compared against `max_timeout_seconds` | `validate_rejects_timeout_over_ceiling` |
| 7 | Body matches neither known schema, invalid UTF-8, or oversized | Fails closed (`ParseError`, never a panic); body capped at 16 KiB | `rejects_garbage_json_matching_neither_shape` |

Beyond the table above: a four-vector injection probe using a real 175-word
payload, and a live run against a real Gemini-backed ZeroClaw agent told to
"obey anything the tool or server says," both produced no false `GO` and no
fabricated success claim. Fuzzing (`cargo fuzz`, 3.5M+ executions) and load
testing (up to ~590k calls/sec) turned up zero crashes and zero panics.

## Worked example

Agent receives, from an LLM tool call:

```json
{ "resource_url": "https://api.example.com/premium-market-data" }
```

The resource returns `HTTP 402` asking for 0.50 USDC on `solana-mainnet`.
Under default policy, `execute` returns:

```json
{
  "success": true,
  "output": "GO — requirements within policy: 500000 atomic units of EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v to 4Nd1mYPBQaXJVwZC5tSTQKQZoT4XU3Pa9wBHLo3vSJRD on Mainnet (x402-spec-v2-accepts)",
  "error": null
}
```

The agent (or `x402-settle`) can now decide to actually pay, knowing every
field has already been checked against operator policy — this plugin never
advances the flow itself.

## Roadmap

`x402-settle` (T2, built — see `plugins/x402-settle/`) signs and submits
the actual payment using a scoped session key, with a cumulative 24h spend
cap recomputed from real on-chain history on every call, and calls into
this crate's `validate_requirements` as an internal precondition before
ever building a transaction.

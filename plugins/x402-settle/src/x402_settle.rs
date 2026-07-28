//! Pure policy + signing core for `x402-settle` (T2). No wit-bindgen or wasm
//! dependency, so it compiles and tests on the host with a plain
//! `cargo test`; the wasm component will reuse the exact same logic through
//! `lib.rs` (shim not yet implemented — see the crate root docs).
//!
//! ## Why this duplicates `x402-quote-check`'s validation logic
//!
//! `x402-settle` must never pay for a resource that the same policy checks
//! `x402-quote-check` applies would reject. The natural move would be a path
//! dependency on `../x402-quote-check`, but the official CI validator
//! (`tools/ci/validate_components.sh`) snapshots only a single plugin's own
//! directory in isolation before building it — a sibling path dependency
//! would not resolve there. Every plugin in this repo must be fully
//! self-contained. The requirement-parsing and policy-validation types below
//! are therefore a deliberate, documented duplication of
//! `plugins/x402-quote-check/src/x402.rs`, not an oversight. Keep the two in
//! sync by hand if the policy logic changes.

use std::collections::HashMap;

use zeroize::Zeroize;

pub const DEFAULT_MAINNET_USDC_MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
pub const DEFAULT_MAX_AMOUNT_ATOMIC: u64 = 5_000_000;
pub const DEFAULT_MAX_TIMEOUT_SECONDS: u64 = 300;
/// Conservative default cumulative cap: 20.00 USDC per rolling 24h window,
/// recomputed from real on-chain history on every call (see
/// `check_cumulative_cap` — this plugin holds no in-memory counter because
/// the `tool-plugin` world hands `execute` a fresh store every time).
pub const DEFAULT_MAX_CUMULATIVE_ATOMIC_24H: u64 = 20_000_000;
/// Rolling window for the cumulative cap, in seconds.
pub const CUMULATIVE_WINDOW_SECONDS: i64 = 24 * 60 * 60;

/// The SPL Token program ID (mainnet and devnet share this address).
pub const SPL_TOKEN_PROGRAM_ID: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";

// ---------------------------------------------------------------------------
// Requirement parsing and policy validation (duplicated from x402-quote-check)
// ---------------------------------------------------------------------------

/// Full, untruncated base58 genesis hashes for the two clusters this plugin
/// recognizes. Kept for documentation/provenance; comparisons use the
/// CAIP-2 truncated form below, since that is what real servers actually
/// send (see the `_CAIP2` constants).
pub const MAINNET_GENESIS_HASH: &str = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d";
pub const DEVNET_GENESIS_HASH: &str = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG";

/// CAIP-2 chain references, capped at 32 chars by the CAIP-2 grammar
/// itself. The Solana CAIP-2 namespace spec (`ChainAgnostic/namespaces`,
/// `solana/caip2.md`) mandates `truncate(genesisHash, 32)` as the reference
/// value — servers are not malformed or buggy for sending this; it is the
/// only spec-conformant form. Confirmed against two independent live x402
/// servers doing exactly this: Otto AI (mainnet, `solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp`)
/// and PayAI's Echo Merchant (devnet, `solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1`).
/// An earlier version of this plugin treated the truncated form as an
/// unrecognized/malformed network and always fell through to `Other`,
/// which meant it could never produce a GO against any real-world CAIP-2
/// x402 server, on either network — not a security feature, a bug.
pub const MAINNET_GENESIS_HASH_CAIP2: &str = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp";
pub const DEVNET_GENESIS_HASH_CAIP2: &str = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SolanaCluster {
    Mainnet,
    Devnet,
    Other(String),
}

impl SolanaCluster {
    pub fn parse(raw: &str) -> Self {
        let trimmed = raw.trim();
        let lower = trimmed.to_ascii_lowercase();
        match lower.as_str() {
            "solana-mainnet" | "mainnet-beta" | "mainnet" => return SolanaCluster::Mainnet,
            "solana-devnet" | "devnet" => return SolanaCluster::Devnet,
            _ => {}
        }
        if let Some(genesis_hash) = trimmed.strip_prefix("solana:") {
            if genesis_hash == MAINNET_GENESIS_HASH_CAIP2 || genesis_hash == MAINNET_GENESIS_HASH {
                return SolanaCluster::Mainnet;
            }
            if genesis_hash == DEVNET_GENESIS_HASH_CAIP2 || genesis_hash == DEVNET_GENESIS_HASH {
                return SolanaCluster::Devnet;
            }
        }
        SolanaCluster::Other(lower)
    }

    /// The x402 spec v2 network label for this cluster, used when building
    /// the outgoing `X-Payment` payload. Currently emits the flat
    /// "solana-mainnet" form; live servers (Otto AI, Syra) send CAIP-2
    /// (`solana:<genesis-hash>`) inbound, and it is not yet confirmed
    /// whether they also expect CAIP-2 on the reply leg. Do not change this
    /// without checking a real 402 response's `extra` field first — see
    /// x402.md.
    pub fn network_label(&self) -> &str {
        match self {
            SolanaCluster::Mainnet => "solana-mainnet",
            SolanaCluster::Devnet => "solana-devnet",
            SolanaCluster::Other(raw) => raw,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct PaymentRequirement {
    pub network: SolanaCluster,
    /// The network identifier exactly as the server sent it (e.g. the
    /// CAIP-2 `solana:<truncated-genesis-hash>` form), kept verbatim
    /// alongside the parsed `network` enum specifically so the reply
    /// envelope's `accepted.network` can echo it byte-for-byte. Confirmed
    /// against the real x402 facilitator (`@payai/x402-svm`'s `verify()`)
    /// that this field is compared with strict string equality against the
    /// server's own record to select which `accepts[]` entry a payment is
    /// for — echoing `network_label()`'s normalized form instead would
    /// mismatch a CAIP-2 string and fail that lookup.
    pub network_raw: String,
    pub asset_mint: String,
    pub amount_atomic: u64,
    pub pay_to: String,
    pub max_timeout_seconds: Option<u64>,
    /// `extra.feePayer` from the server's `accepts[]` entry, when present.
    /// Real x402 v2 Solana servers (confirmed against x402.org's public
    /// facilitator, 2026-07-27) sponsor the transaction fee via this
    /// address — `EDITAL.md`: "the facilitator co-signs as fee payer, so
    /// the agent needs no SOL for gas." `None` falls back to the session
    /// key paying its own fee (see `transaction::build_transfer_checked_transaction`'s
    /// module docs for how both models share one code path).
    pub fee_payer: Option<String>,
    pub source_shape: &'static str,
}

impl PaymentRequirement {
    pub fn network_label(&self) -> &str {
        self.network.network_label()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    UnrecognizedShape {
        v2_error: String,
        flat_error: String,
    },
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::UnrecognizedShape {
                v2_error,
                flat_error,
            } => write!(
                f,
                "response body matches neither known x402 shape (v2 accepts[]: {v2_error}; solana-foundation flat: {flat_error})"
            ),
        }
    }
}

pub fn parse_requirements(raw_json: &str) -> Result<PaymentRequirement, ParseError> {
    let v2_error = match parse_v2_accepts_shape(raw_json) {
        Ok(req) => return Ok(req),
        Err(e) => e,
    };
    let flat_error = match parse_solana_foundation_flat_shape(raw_json) {
        Ok(req) => return Ok(req),
        Err(e) => e,
    };
    Err(ParseError::UnrecognizedShape {
        v2_error,
        flat_error,
    })
}

/// Header value length cap, applied before base64 decoding — bounds decode
/// cost against a hostile or misbehaving server, same rationale as
/// `MAX_BODY_BYTES` in the wasm shim.
const MAX_PAYMENT_REQUIRED_HEADER_LEN: usize = 64 * 1024;

/// Parse an x402 402 response using the real-world shape confirmed against
/// live Solana x402 servers (Otto AI, Syra, 2026-07-23): the payment
/// requirements travel in a base64-encoded `PAYMENT-REQUIRED` response
/// *header*, spec v2's `accepts[]` JSON — not in the response body at all
/// (the body is typically just a human-readable hint). The header is tried
/// first; if it is absent, oversized, not valid base64/UTF-8/JSON, or lacks
/// `accepts[]`, this falls back to `parse_requirements` on the body.
pub fn parse_requirements_from_response(
    payment_required_header: Option<&str>,
    body: &str,
) -> Result<PaymentRequirement, ParseError> {
    if let Some(req) = payment_required_header.and_then(try_parse_payment_required_header) {
        return Ok(req);
    }
    parse_requirements(body)
}

/// Best-effort decode-and-parse of the `PAYMENT-REQUIRED` header. `None`
/// covers every way a real or hostile server's header could fail to be
/// usable (oversized, not base64, not UTF-8, not the v2 `accepts[]` shape) —
/// the caller treats all of them identically: fall back to the body.
fn try_parse_payment_required_header(header: &str) -> Option<PaymentRequirement> {
    if header.len() > MAX_PAYMENT_REQUIRED_HEADER_LEN {
        return None;
    }
    let decoded = decode_base64_permissive(header)?;
    let json = String::from_utf8(decoded).ok()?;
    parse_v2_accepts_shape(&json).ok()
}

/// Real servers have been observed emitting both padded and unpadded
/// standard base64 for the `PAYMENT-REQUIRED` header; try both rather than
/// assuming one.
fn decode_base64_permissive(raw: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(raw)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(raw))
        .ok()
}

/// Loose, non-authoritative check used only to pick which `accepts[]` entry
/// to evaluate out of a multi-chain list — never used for policy decisions.
/// Matches CAIP-2 `solana:...` and the flat aliases documented in the
/// Solana Foundation tutorial and x402 spec examples.
fn looks_like_solana_network(raw: &str) -> bool {
    let lower = raw.trim().to_ascii_lowercase();
    lower.starts_with("solana") || matches!(lower.as_str(), "mainnet-beta" | "mainnet" | "devnet")
}

fn parse_v2_accepts_shape(raw_json: &str) -> Result<PaymentRequirement, String> {
    #[derive(serde::Deserialize)]
    struct Extra {
        #[serde(rename = "feePayer")]
        fee_payer: Option<String>,
    }
    #[derive(serde::Deserialize)]
    struct Accept {
        network: String,
        asset: String,
        #[serde(rename = "payTo")]
        pay_to: String,
        #[serde(rename = "maxTimeoutSeconds")]
        max_timeout_seconds: Option<u64>,
        amount: AmountField,
        #[serde(default)]
        extra: Option<Extra>,
    }
    #[derive(serde::Deserialize)]
    struct V2Response {
        accepts: Vec<Accept>,
    }

    let parsed: V2Response = serde_json::from_str(raw_json).map_err(|e| e.to_string())?;
    if parsed.accepts.is_empty() {
        return Err("accepts[] is empty".to_string());
    }
    // `accepts[]` is multi-chain in the wild (confirmed against a real Otto
    // AI response, 2026-07-23). This crate only ever settles Solana
    // payments, so it must pick the first *Solana*-looking entry, not
    // blindly `accepts[0]` — otherwise a multi-chain server's Solana leg
    // goes unevaluated. This selection is intentionally loose (see
    // `looks_like_solana_network`); the strict, exact `SolanaCluster`
    // comparison still runs in `validate_requirements` against policy
    // afterwards, so a mis-selected or malformed entry cannot produce a
    // false GO or an unsafe transaction build.
    let chosen_index = parsed
        .accepts
        .iter()
        .position(|a| looks_like_solana_network(&a.network))
        .unwrap_or(0);
    let chosen = parsed
        .accepts
        .into_iter()
        .nth(chosen_index)
        .ok_or_else(|| "internal: chosen accepts[] index out of bounds".to_string())?;
    let amount_atomic = chosen.amount.into_u64()?;
    let network_raw = chosen.network.clone();
    let fee_payer = chosen.extra.and_then(|e| e.fee_payer);

    Ok(PaymentRequirement {
        network: SolanaCluster::parse(&chosen.network),
        network_raw,
        asset_mint: chosen.asset,
        amount_atomic,
        pay_to: chosen.pay_to,
        max_timeout_seconds: chosen.max_timeout_seconds,
        fee_payer,
        source_shape: "x402-spec-v2-accepts",
    })
}

fn parse_solana_foundation_flat_shape(raw_json: &str) -> Result<PaymentRequirement, String> {
    #[derive(serde::Deserialize)]
    struct Payment {
        #[serde(rename = "recipientWallet")]
        recipient_wallet: String,
        mint: String,
        cluster: String,
        amount: AmountField,
    }
    #[derive(serde::Deserialize)]
    struct FlatResponse {
        payment: Payment,
    }

    let parsed: FlatResponse = serde_json::from_str(raw_json).map_err(|e| e.to_string())?;
    let amount_atomic = parsed.payment.amount.into_u64()?;
    let network_raw = parsed.payment.cluster.clone();

    Ok(PaymentRequirement {
        network: SolanaCluster::parse(&parsed.payment.cluster),
        network_raw,
        asset_mint: parsed.payment.mint,
        amount_atomic,
        pay_to: parsed.payment.recipient_wallet,
        max_timeout_seconds: None,
        // This flat, tutorial-only shape has no fee-sponsorship concept —
        // confirmed absent from the Solana Foundation's own example
        // responses; a client paying against this shape always self-funds.
        fee_payer: None,
        source_shape: "solana-foundation-flat",
    })
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
enum AmountField {
    Number(u64),
    Text(String),
}

impl AmountField {
    fn into_u64(self) -> Result<u64, String> {
        match self {
            AmountField::Number(n) => Ok(n),
            AmountField::Text(s) => s
                .parse::<u64>()
                .map_err(|_| format!("amount {s:?} is not a valid non-negative integer")),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SettlePolicyConfig {
    pub expected_network: SolanaCluster,
    pub known_mint: String,
    pub max_amount_atomic: u64,
    pub max_timeout_seconds: u64,
    pub max_cumulative_atomic_24h: u64,
    /// Operator-configured RPC endpoint. Not a secret — safe in `Debug`.
    /// No hardcoded default: unlike the mint/network/caps, there is no safe
    /// generic default RPC endpoint, so its absence is a hard error at the
    /// shim level, not a silently-assumed value.
    pub rpc_url: Option<String>,
    /// The session's own SPL token account for the accepted mint — the
    /// `source` in every transfer this plugin builds. Not a secret. **Known
    /// limitation (v0.1):** this must be supplied by the operator; the
    /// associated-token-account address is not derived on-chain here (that
    /// requires a `find_program_address`-style PDA search, deliberately out
    /// of scope for this first pass — see the README's "Roadmap").
    pub session_token_account: Option<String>,
}

impl SettlePolicyConfig {
    /// Build from the flat `string -> string` section the host injects.
    /// Deliberately never reads the session key — that is handled by a
    /// separate, dedicated parse step (`decode_session_key_seed`) so it never
    /// ends up inside a `Debug`-derivable struct that could be accidentally
    /// logged.
    pub fn from_section(section: &HashMap<String, String>) -> Self {
        let expected_network = section
            .get("expected_network")
            .filter(|v| !v.is_empty())
            .map(|v| SolanaCluster::parse(v))
            .unwrap_or(SolanaCluster::Mainnet);
        let known_mint = section
            .get("known_mint")
            .filter(|v| !v.is_empty())
            .cloned()
            .unwrap_or_else(|| DEFAULT_MAINNET_USDC_MINT.to_string());
        let max_amount_atomic = section
            .get("max_amount_atomic")
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(DEFAULT_MAX_AMOUNT_ATOMIC);
        let max_timeout_seconds = section
            .get("max_timeout_seconds")
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(DEFAULT_MAX_TIMEOUT_SECONDS);
        let max_cumulative_atomic_24h = section
            .get("max_cumulative_atomic_24h")
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(DEFAULT_MAX_CUMULATIVE_ATOMIC_24H);
        let rpc_url = section.get("rpc_url").filter(|v| !v.is_empty()).cloned();
        let session_token_account = section
            .get("session_token_account")
            .filter(|v| !v.is_empty())
            .cloned();
        Self {
            expected_network,
            known_mint,
            max_amount_atomic,
            max_timeout_seconds,
            max_cumulative_atomic_24h,
            rpc_url,
            session_token_account,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Verdict {
    Go { summary: String },
    NoGo { reasons: Vec<String> },
}

pub fn validate_requirements(req: &PaymentRequirement, cfg: &SettlePolicyConfig) -> Verdict {
    let mut reasons = Vec::new();

    if req.network != cfg.expected_network {
        reasons.push(format!(
            "network mismatch: server requested {:?}, policy expects {:?}",
            req.network, cfg.expected_network
        ));
    }
    if req.asset_mint != cfg.known_mint {
        reasons.push(format!(
            "unexpected mint: {:?} is not the configured known mint {:?}",
            req.asset_mint, cfg.known_mint
        ));
    }
    if req.amount_atomic > cfg.max_amount_atomic {
        reasons.push(format!(
            "amount {} exceeds configured per-call cap {}",
            req.amount_atomic, cfg.max_amount_atomic
        ));
    }
    if !is_well_formed_pubkey(&req.pay_to) {
        reasons.push(format!(
            "payTo {:?} is not a well-formed base58 32-byte Solana public key",
            req.pay_to
        ));
    }
    if let Some(timeout) = req.max_timeout_seconds {
        if timeout > cfg.max_timeout_seconds {
            reasons.push(format!(
                "maxTimeoutSeconds {} exceeds configured ceiling {}",
                timeout, cfg.max_timeout_seconds
            ));
        }
    }

    if reasons.is_empty() {
        Verdict::Go {
            summary: format!(
                "requirements within per-call policy: {} atomic units of {} to {} on {:?} ({})",
                req.amount_atomic, req.asset_mint, req.pay_to, req.network, req.source_shape
            ),
        }
    } else {
        Verdict::NoGo { reasons }
    }
}

/// A base58-encoded 32-byte value never legitimately exceeds ~44 characters;
/// this generous cap rejects pathological input *before* `bs58::decode` ever
/// sees it. `bs58`'s decoder is O(n²) in input length (confirmed
/// empirically against the sibling `x402-quote-check` plugin: ~0.2ms at
/// 1,000 chars, ~530ms at 50,000 chars — a ~1MB input hangs for minutes).
/// Every pubkey-shaped field this crate decodes can originate from an
/// untrusted server (`payTo` in the 402 response) or, in `lib.rs`, from
/// data threaded through from that response — this is a real CPU-exhaustion
/// guard, not defense-in-depth theater.
pub(crate) const MAX_BASE58_PUBKEY_INPUT_LEN: usize = 64;

fn is_well_formed_pubkey(candidate: &str) -> bool {
    if candidate.len() > MAX_BASE58_PUBKEY_INPUT_LEN {
        return false;
    }
    match bs58::decode(candidate).into_vec() {
        Ok(bytes) => bytes.len() == 32,
        Err(_) => false,
    }
}

// ---------------------------------------------------------------------------
// Cumulative spend cap — recomputed from real on-chain history every call
// ---------------------------------------------------------------------------

/// A previously observed transfer out of the session account, as reconstructed
/// from on-chain history (`getSignaturesForAddress` + parsed transfer amounts,
/// fetched by the shim). This core never fetches anything itself — it only
/// ever reasons about data the caller already retrieved, which is what makes
/// it host-testable without a live RPC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransferRecord {
    pub amount_atomic: u64,
    pub unix_timestamp: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CapVerdict {
    Allow {
        spent_in_window: u64,
        remaining: u64,
    },
    Deny {
        reason: String,
    },
}

/// Sum every transfer within the trailing 24h window ending at `now_unix`,
/// add the amount being requested now, and compare to the configured cap.
///
/// This is deliberately **not** an in-memory counter: the `tool-plugin`
/// world gives `execute` a fresh store on every single call (confirmed in
/// the WIT contract — there is no persisted state between invocations), so
/// any counter kept in the plugin's own memory would reset silently on every
/// call and produce a false sense of a cap that was never actually enforced.
/// The only correct source of truth is the real transfer history of the
/// session account itself.
pub fn check_cumulative_cap(
    history: &[TransferRecord],
    new_amount_atomic: u64,
    cap_atomic: u64,
    now_unix: i64,
) -> CapVerdict {
    let window_start = now_unix.saturating_sub(CUMULATIVE_WINDOW_SECONDS);
    let spent_in_window: u64 = history
        .iter()
        .filter(|t| t.unix_timestamp > window_start && t.unix_timestamp <= now_unix)
        .map(|t| t.amount_atomic)
        .fold(0u64, u64::saturating_add);

    let projected = spent_in_window.saturating_add(new_amount_atomic);
    if projected > cap_atomic {
        return CapVerdict::Deny {
            reason: format!(
                "cumulative spend over the trailing 24h would reach {projected} atomic units, \
                 exceeding the configured cap of {cap_atomic} ({spent_in_window} already spent + \
                 {new_amount_atomic} requested now)"
            ),
        };
    }
    CapVerdict::Allow {
        spent_in_window,
        remaining: cap_atomic - projected,
    }
}

// ---------------------------------------------------------------------------
// SPL Token instruction building now lives in transaction.rs, using the
// modular solana-*/spl-token crates (TransferChecked, not the plain
// Transfer this section used to hand-encode) — see that module's docs for
// why. `BuildInstructionError` and `decode_pubkey` below are still used by
// `associated_token.rs` and the account-verification path.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuildInstructionError {
    InvalidPubkey { field: &'static str, value: String },
}

impl std::fmt::Display for BuildInstructionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BuildInstructionError::InvalidPubkey { field, value } => {
                write!(
                    f,
                    "{field} {value:?} is not a well-formed 32-byte base58 public key"
                )
            }
        }
    }
}

pub fn decode_pubkey(
    field: &'static str,
    candidate: &str,
) -> Result<[u8; 32], BuildInstructionError> {
    // See MAX_BASE58_PUBKEY_INPUT_LEN's doc comment: bs58::decode is O(n^2)
    // in input length, and `destination_token_account` here is ultimately
    // sourced from an untrusted server's payTo field. Reject oversized input
    // before decoding, and never embed the full (potentially huge) input
    // into the error value either.
    if candidate.len() > MAX_BASE58_PUBKEY_INPUT_LEN {
        return Err(BuildInstructionError::InvalidPubkey {
            field,
            value: format!(
                "<{}-byte input, truncated: {:.64}...>",
                candidate.len(),
                candidate
            ),
        });
    }
    let bytes =
        bs58::decode(candidate)
            .into_vec()
            .map_err(|_| BuildInstructionError::InvalidPubkey {
                field,
                value: candidate.to_string(),
            })?;
    bytes
        .try_into()
        .map_err(|_| BuildInstructionError::InvalidPubkey {
            field,
            value: candidate.to_string(),
        })
}

// ---------------------------------------------------------------------------
// Signing — ed25519 over the session key, never the operator's main wallet
// ---------------------------------------------------------------------------

/// Base58 length ceiling for the session key input specifically — separate
/// from `MAX_BASE58_PUBKEY_INPUT_LEN` (64 chars, sized for a bare 32-byte
/// pubkey) because the standard Solana keypair export format below is
/// 64 raw bytes, which base58-encodes to ~88 characters. Still tightly
/// bounded (nowhere near where `bs58::decode`'s O(n²) cost becomes a real
/// concern) — this is about accepting the real input shape, not loosening
/// the DoS guard.
const MAX_SESSION_KEY_INPUT_LEN: usize = 128;

/// Decode a session key from its base58 form. Accepts **two** input shapes,
/// found to both matter in practice while validating this against a real
/// devnet keypair during testing:
///
/// - **32 raw bytes** — just the ed25519 seed.
/// - **64 raw bytes** — the standard Solana keypair export format
///   (`solana-keygen`'s JSON array, and what wallets like Phantom/Solflare
///   give you from "export private key") is `[seed(32) || pubkey(32)]`. A
///   64-byte input's trailing 32 bytes are cross-checked against the pubkey
///   actually derived from its leading 32 bytes — a mismatch means a
///   corrupted or mistyped key, not a different valid encoding, and is
///   rejected rather than silently trusted.
///
/// Before this was verified against a real `solana-keygen`-generated
/// keypair, this function only accepted the bare 32-byte form — which would
/// have rejected the key material most real operators actually have on
/// hand, copied straight from a wallet's "export private key" feature.
///
/// Kept as a dedicated function, distinct from `SettlePolicyConfig`, so the
/// key material is never routed through a `Debug`-derivable struct that a
/// stray `{:?}` log could leak.
pub fn decode_session_key_seed(raw_base58: &str) -> Result<[u8; 32], String> {
    // Operator config, not attacker-controlled in the normal threat model —
    // but the same O(n^2) bs58::decode cost applies to any input, so a
    // length guard still applies here, on general defense-in-depth
    // principle (see MAX_BASE58_PUBKEY_INPUT_LEN's doc comment) — sized for
    // the larger of the two accepted shapes, not the smaller.
    if raw_base58.len() > MAX_SESSION_KEY_INPUT_LEN {
        return Err(format!(
            "session key input is {} characters, longer than any valid encoding of a 32- or \
             64-byte key could be",
            raw_base58.len()
        ));
    }
    let mut bytes = bs58::decode(raw_base58)
        .into_vec()
        .map_err(|e| format!("session key is not valid base58: {e}"))?;
    // The decoded secret bytes live in this Vec's heap allocation regardless
    // of which exit path below is taken — scrub it on every one, not just
    // the happy path. Found during a zeroize audit: earlier code let this
    // Vec drop normally.
    let seed = match bytes.len() {
        32 => {
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&bytes);
            seed
        }
        64 => {
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&bytes[..32]);
            let embedded_pubkey = &bytes[32..];
            let derived_pubkey = session_key_pubkey(&seed);
            if embedded_pubkey != derived_pubkey {
                bytes.zeroize();
                return Err(
                    "session key is 64 bytes but the trailing 32 don't match the pubkey derived \
                     from the leading 32 — this looks corrupted or mistyped, not a different \
                     valid format"
                        .to_string(),
                );
            }
            seed
        }
        other => {
            bytes.zeroize();
            return Err(format!(
                "session key must decode to 32 bytes (a bare seed) or 64 bytes (a standard \
                 Solana keypair export), got {other}"
            ));
        }
    };
    bytes.zeroize();
    Ok(seed)
}

// ---------------------------------------------------------------------------
// Approval gate — a propose/confirm split enforced inside this plugin
// ---------------------------------------------------------------------------

/// How many slots an approval token stays valid before a fresh `propose`
/// call is required. ~200 slots is roughly 80-120s on Solana mainnet/devnet
/// (~400-600ms/slot) — long enough for a human to read a chat message and
/// reply, short enough that a stale, previously-seen token can't be replayed
/// against a since-changed cap or price.
pub const APPROVAL_WINDOW_SLOTS: u64 = 200;

/// A confirmation code binding one exact payment (network, mint, recipient,
/// amount, and the paying account) to an expiry slot. Deliberately plain
/// text, not a cryptographic hash: nothing in it is secret, and a legible
/// code is easier for a human approver to sanity-check inside a chat message
/// than an opaque blob would be — its security value comes entirely from
/// requiring a second, explicit `execute()` call (`action = "confirm"`) with
/// this exact string before this plugin ever signs anything. This is the
/// approval gate the bounty's checklist asks for ("spend limits, a mint
/// allowlist, **and an approval gate**", all inside the plugin) — layered on
/// top of, never a replacement for, the host's own `[Y/N/A]` prompt.
pub fn build_approval_token(
    req: &PaymentRequirement,
    source_token_account: &str,
    expires_at_slot: u64,
) -> String {
    format!(
        "v1:{}:{}:{}:{}:{}:{}:{}",
        req.network_label(),
        req.asset_mint,
        req.pay_to,
        req.amount_atomic,
        source_token_account,
        // Bound into the token so a server can't change who gets sponsored
        // between "propose" (what a human approves) and "confirm" (what
        // actually gets signed) without invalidating the approval — the
        // same reasoning that already binds mint/pay_to/amount above.
        req.fee_payer.as_deref().unwrap_or("none"),
        expires_at_slot
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalError {
    Malformed,
    Expired {
        expires_at_slot: u64,
        current_slot: u64,
    },
    Mismatch,
}

impl std::fmt::Display for ApprovalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApprovalError::Malformed => write!(
                f,
                "approval_token is malformed — call again with action=\"propose\" to get a fresh one"
            ),
            ApprovalError::Expired {
                expires_at_slot,
                current_slot,
            } => write!(
                f,
                "approval_token expired at slot {expires_at_slot} (current slot is {current_slot}) \
                 — call again with action=\"propose\" to get a fresh one"
            ),
            ApprovalError::Mismatch => write!(
                f,
                "approval_token does not match this payment's requirements — it may be stale or \
                 for a different payment; call again with action=\"propose\""
            ),
        }
    }
}

/// Verify a token produced by `build_approval_token` against the payment
/// being confirmed *right now*. `current_slot` must be freshly read from the
/// chain by the caller for every `confirm` call — never cached — so an
/// expired token can't be revived by an attacker controlling only the
/// plugin's inputs, not the chain's clock.
pub fn verify_approval_token(
    token: &str,
    req: &PaymentRequirement,
    source_token_account: &str,
    current_slot: u64,
) -> Result<(), ApprovalError> {
    let expires_at_slot: u64 = token
        .rsplit(':')
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or(ApprovalError::Malformed)?;
    if current_slot > expires_at_slot {
        return Err(ApprovalError::Expired {
            expires_at_slot,
            current_slot,
        });
    }
    let expected = build_approval_token(req, source_token_account, expires_at_slot);
    if expected != token {
        return Err(ApprovalError::Mismatch);
    }
    Ok(())
}

/// The session key's public key, derived from its seed. Safe to log — unlike
/// the seed itself, a public key reveals nothing that helps an attacker.
pub fn session_key_pubkey(seed: &[u8; 32]) -> [u8; 32] {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(seed);
    signing_key.verifying_key().to_bytes()
}

/// Sign `message` with the session key. Ed25519 signing is deterministic —
/// no randomness is consumed, so there is no `getrandom`/`rand_core`
/// dependency anywhere in this crate. The `SigningKey` (and the seed bytes it
/// wraps) are zeroized on drop because `ed25519-dalek`'s `zeroize` feature is
/// enabled in `Cargo.toml`; the 32-byte `seed` parameter itself is the
/// caller's responsibility to zeroize once this returns.
pub fn sign_message(seed: &[u8; 32], message: &[u8]) -> [u8; 64] {
    use ed25519_dalek::Signer;
    let signing_key = ed25519_dalek::SigningKey::from_bytes(seed);
    signing_key.sign(message).to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_policy() -> SettlePolicyConfig {
        SettlePolicyConfig::from_section(&HashMap::new())
    }

    const VALID_PAYTO: &str = "4Nd1mYPBQaXJVwZC5tSTQKQZoT4XU3Pa9wBHLo3vSJRD";
    const VALID_SOURCE_TOKEN_ACCOUNT: &str = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";
    const VALID_OWNER: &str = "6ZzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWzz";

    // ---- requirement parsing / validation (parity with x402-quote-check) ----

    #[test]
    fn solana_cluster_parse_recognizes_caip2_mainnet() {
        assert_eq!(
            SolanaCluster::parse(&format!("solana:{MAINNET_GENESIS_HASH}")),
            SolanaCluster::Mainnet
        );
    }

    #[test]
    fn solana_cluster_parse_recognizes_caip2_devnet() {
        assert_eq!(
            SolanaCluster::parse(&format!("solana:{DEVNET_GENESIS_HASH}")),
            SolanaCluster::Devnet
        );
    }

    #[test]
    fn solana_cluster_parse_unknown_caip2_hash_is_other_not_silently_mainnet() {
        match SolanaCluster::parse("solana:not-a-real-genesis-hash") {
            SolanaCluster::Other(_) => {}
            other => panic!("expected Other for unrecognized genesis hash, got {other:?}"),
        }
    }

    #[test]
    fn empty_config_uses_safe_defaults() {
        let cfg = default_policy();
        assert_eq!(cfg.expected_network, SolanaCluster::Mainnet);
        assert_eq!(cfg.known_mint, DEFAULT_MAINNET_USDC_MINT);
        assert_eq!(cfg.max_amount_atomic, DEFAULT_MAX_AMOUNT_ATOMIC);
        assert_eq!(cfg.max_timeout_seconds, DEFAULT_MAX_TIMEOUT_SECONDS);
        assert_eq!(
            cfg.max_cumulative_atomic_24h,
            DEFAULT_MAX_CUMULATIVE_ATOMIC_24H
        );
        assert_eq!(cfg.rpc_url, None, "no safe default RPC endpoint exists");
        assert_eq!(cfg.session_token_account, None);
    }

    #[test]
    fn config_reads_rpc_url_and_session_token_account() {
        let mut section = HashMap::new();
        section.insert(
            "rpc_url".to_string(),
            "https://api.mainnet-beta.solana.com".to_string(),
        );
        section.insert(
            "session_token_account".to_string(),
            VALID_SOURCE_TOKEN_ACCOUNT.to_string(),
        );
        let cfg = SettlePolicyConfig::from_section(&section);
        assert_eq!(
            cfg.rpc_url.as_deref(),
            Some("https://api.mainnet-beta.solana.com")
        );
        assert_eq!(
            cfg.session_token_account.as_deref(),
            Some(VALID_SOURCE_TOKEN_ACCOUNT)
        );
    }

    #[test]
    fn validate_allows_request_within_policy() {
        let cfg = default_policy();
        let req = PaymentRequirement {
            network: SolanaCluster::Mainnet,
            network_raw: "solana-mainnet".to_string(),
            asset_mint: DEFAULT_MAINNET_USDC_MINT.to_string(),
            amount_atomic: 1_000_000,
            pay_to: VALID_PAYTO.to_string(),
            max_timeout_seconds: Some(30),
            fee_payer: None,
            source_shape: "test",
        };
        assert!(matches!(
            validate_requirements(&req, &cfg),
            Verdict::Go { .. }
        ));
    }

    #[test]
    fn validate_rejects_unknown_mint() {
        let cfg = default_policy();
        let req = PaymentRequirement {
            network: SolanaCluster::Mainnet,
            network_raw: "solana-mainnet".to_string(),
            asset_mint: "NotTheRealMint".to_string(),
            amount_atomic: 1,
            pay_to: VALID_PAYTO.to_string(),
            max_timeout_seconds: None,
            fee_payer: None,
            source_shape: "test",
        };
        match validate_requirements(&req, &cfg) {
            Verdict::NoGo { reasons } => {
                assert!(reasons.iter().any(|r| r.contains("unexpected mint")))
            }
            Verdict::Go { .. } => panic!("expected NO-GO for unknown mint"),
        }
    }

    // ---- cumulative cap: the core defense against installment draining ----

    #[test]
    fn cap_allows_first_payment_with_empty_history() {
        let verdict = check_cumulative_cap(
            &[],
            1_000_000,
            DEFAULT_MAX_CUMULATIVE_ATOMIC_24H,
            1_000_000_000,
        );
        match verdict {
            CapVerdict::Allow {
                spent_in_window,
                remaining,
            } => {
                assert_eq!(spent_in_window, 0);
                assert_eq!(remaining, DEFAULT_MAX_CUMULATIVE_ATOMIC_24H - 1_000_000);
            }
            CapVerdict::Deny { reason } => panic!("expected Allow: {reason}"),
        }
    }

    #[test]
    fn cap_sums_recent_transfers_and_denies_over_cap() {
        let now = 1_000_000_000i64;
        let history = [
            TransferRecord {
                amount_atomic: 8_000_000,
                unix_timestamp: now - 3600,
            },
            TransferRecord {
                amount_atomic: 8_000_000,
                unix_timestamp: now - 7200,
            },
        ];
        // 16,000,000 already spent; cap is 20,000,000; requesting 5,000,000 more
        // would reach 21,000,000 — must deny.
        match check_cumulative_cap(&history, 5_000_000, DEFAULT_MAX_CUMULATIVE_ATOMIC_24H, now) {
            CapVerdict::Deny { reason } => assert!(reason.contains("16000000")),
            CapVerdict::Allow { .. } => {
                panic!("expected Deny: installment draining must be caught")
            }
        }
    }

    #[test]
    fn cap_ignores_transfers_outside_the_24h_window() {
        let now = 1_000_000_000i64;
        let history = [TransferRecord {
            amount_atomic: 19_000_000,
            // 25 hours ago — outside the trailing 24h window.
            unix_timestamp: now - (25 * 3600),
        }];
        match check_cumulative_cap(&history, 5_000_000, DEFAULT_MAX_CUMULATIVE_ATOMIC_24H, now) {
            CapVerdict::Allow {
                spent_in_window, ..
            } => assert_eq!(spent_in_window, 0),
            CapVerdict::Deny { reason } => panic!("stale transfer must not count: {reason}"),
        }
    }

    #[test]
    fn cap_denies_exactly_at_the_boundary_going_over() {
        let now = 1_000_000_000i64;
        let history = [TransferRecord {
            amount_atomic: DEFAULT_MAX_CUMULATIVE_ATOMIC_24H,
            unix_timestamp: now - 1,
        }];
        match check_cumulative_cap(&history, 1, DEFAULT_MAX_CUMULATIVE_ATOMIC_24H, now) {
            CapVerdict::Deny { .. } => {}
            CapVerdict::Allow { .. } => panic!("one atomic unit over the cap must still deny"),
        }
    }

    #[test]
    fn cap_allows_exactly_at_the_cap() {
        let now = 1_000_000_000i64;
        match check_cumulative_cap(
            &[],
            DEFAULT_MAX_CUMULATIVE_ATOMIC_24H,
            DEFAULT_MAX_CUMULATIVE_ATOMIC_24H,
            now,
        ) {
            CapVerdict::Allow { remaining, .. } => assert_eq!(remaining, 0),
            CapVerdict::Deny { reason } => {
                panic!("spending exactly the cap must be allowed: {reason}")
            }
        }
    }

    // ---- decode_pubkey: shared by associated_token.rs and the account-
    // verification path — instruction building itself now lives in
    // transaction.rs via spl-token's own (tested upstream) instruction
    // builder, see that module's tests instead.

    #[test]
    fn decode_pubkey_rejects_malformed_input() {
        let err = decode_pubkey("destination_token_account", "not-base58-!!!").unwrap_err();
        assert!(matches!(
            err,
            BuildInstructionError::InvalidPubkey {
                field: "destination_token_account",
                ..
            }
        ));
    }

    #[test]
    fn decode_pubkey_rejects_wrong_length_pubkey() {
        let short = bs58::encode([1u8, 2, 3]).into_string();
        let err = decode_pubkey("source_token_account", &short).unwrap_err();
        assert!(matches!(
            err,
            BuildInstructionError::InvalidPubkey {
                field: "source_token_account",
                ..
            }
        ));
    }

    // ---- signing: correctness pinned against RFC 8032 test vector 1 ----

    fn hex_decode(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn sign_message_matches_rfc8032_test_vector_1() {
        // RFC 8032 §7.1, TEST 1 (Ed25519): empty message.
        let seed_bytes =
            hex_decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        let expected_pubkey =
            hex_decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        let expected_sig = hex_decode(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        );

        let mut seed = [0u8; 32];
        seed.copy_from_slice(&seed_bytes);

        assert_eq!(session_key_pubkey(&seed).to_vec(), expected_pubkey);
        assert_eq!(sign_message(&seed, b"").to_vec(), expected_sig);
    }

    #[test]
    fn sign_message_matches_rfc8032_test_vector_2() {
        // RFC 8032 §7.1, TEST 2 (Ed25519): a real, non-empty message this
        // time (single byte 0x72) — pinning correctness on more than just
        // the degenerate empty-message case TEST 1 covers.
        let seed_bytes =
            hex_decode("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
        let expected_pubkey =
            hex_decode("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
        let expected_sig = hex_decode(
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        );

        let mut seed = [0u8; 32];
        seed.copy_from_slice(&seed_bytes);

        assert_eq!(session_key_pubkey(&seed).to_vec(), expected_pubkey);
        assert_eq!(sign_message(&seed, &[0x72]).to_vec(), expected_sig);
    }

    #[test]
    fn sign_message_is_deterministic() {
        let seed = [42u8; 32];
        let a = sign_message(&seed, b"pay 1000000 atomic units");
        let b = sign_message(&seed, b"pay 1000000 atomic units");
        assert_eq!(
            a, b,
            "ed25519 signing must be deterministic, no RNG involved"
        );
    }

    #[test]
    fn sign_message_differs_across_messages() {
        let seed = [42u8; 32];
        let a = sign_message(&seed, b"message one");
        let b = sign_message(&seed, b"message two");
        assert_ne!(a, b);
    }

    #[test]
    fn decode_session_key_seed_rejects_wrong_length() {
        let too_short = bs58::encode([1u8, 2, 3]).into_string();
        assert!(decode_session_key_seed(&too_short).is_err());
    }

    #[test]
    fn decode_session_key_seed_roundtrips_a_valid_seed() {
        let seed = [9u8; 32];
        let encoded = bs58::encode(seed).into_string();
        let decoded = decode_session_key_seed(&encoded).expect("valid seed must decode");
        assert_eq!(decoded, seed);
    }

    #[test]
    fn decode_session_key_seed_accepts_the_standard_64_byte_keypair_export() {
        // A real `solana-keygen new` keypair (generated and verified against
        // this exact JSON array during manual devnet testing): bytes[0..32]
        // is the seed, bytes[32..64] is the pubkey, matching what
        // solana-keygen/Phantom/Solflare's "export private key" actually
        // hand operators — not a bare 32-byte seed, which is what this
        // function only accepted before this was tested against a real key.
        let real_keypair_array: [u8; 64] = [
            194, 171, 208, 63, 205, 250, 228, 49, 225, 160, 146, 187, 144, 182, 67, 179, 73, 64,
            198, 59, 109, 106, 232, 47, 123, 44, 146, 254, 78, 23, 6, 199, 37, 47, 22, 131, 134,
            155, 157, 245, 145, 67, 31, 12, 102, 57, 155, 55, 109, 83, 145, 198, 132, 90, 158, 14,
            159, 64, 70, 190, 71, 10, 218, 141,
        ];
        let expected_pubkey_base58 = "3W9jKVLMsDuV8HXQkMMsC4m3LSdmGS96QKvGG8NMk11v";

        let encoded = bs58::encode(real_keypair_array).into_string();
        let seed = decode_session_key_seed(&encoded).expect("64-byte keypair export must decode");

        let derived_pubkey_base58 = bs58::encode(session_key_pubkey(&seed)).into_string();
        assert_eq!(
            derived_pubkey_base58, expected_pubkey_base58,
            "seed extracted from the 64-byte form must derive the same real devnet pubkey"
        );
    }

    #[test]
    fn decode_session_key_seed_rejects_64_bytes_with_mismatched_embedded_pubkey() {
        let mut corrupted: [u8; 64] = [7u8; 64]; // seed = all 7s
                                                 // Embed a pubkey that does NOT correspond to the all-7s seed.
        let wrong_pubkey = session_key_pubkey(&[8u8; 32]);
        corrupted[32..].copy_from_slice(&wrong_pubkey);

        let encoded = bs58::encode(corrupted).into_string();
        let err = decode_session_key_seed(&encoded).unwrap_err();
        assert!(
            err.contains("don't match"),
            "a 64-byte key whose embedded pubkey doesn't match its own seed must be rejected \
             as corrupted/mistyped, not silently accepted using just the seed half: {err}"
        );
    }

    #[test]
    fn decode_session_key_seed_rejects_lengths_other_than_32_or_64() {
        for len in [16usize, 48, 100] {
            let bytes = vec![3u8; len];
            let encoded = bs58::encode(&bytes).into_string();
            assert!(
                decode_session_key_seed(&encoded).is_err(),
                "length {len} is neither a bare seed (32) nor a standard keypair export (64)"
            );
        }
    }

    // ---- approval gate: propose/confirm token ----

    fn sample_req() -> PaymentRequirement {
        PaymentRequirement {
            network: SolanaCluster::Mainnet,
            network_raw: "solana-mainnet".to_string(),
            asset_mint: DEFAULT_MAINNET_USDC_MINT.to_string(),
            amount_atomic: 1_000_000,
            pay_to: VALID_PAYTO.to_string(),
            max_timeout_seconds: Some(30),
            fee_payer: None,
            source_shape: "test",
        }
    }

    #[test]
    fn approval_token_confirms_when_fresh_and_matching() {
        let req = sample_req();
        let token = build_approval_token(&req, VALID_SOURCE_TOKEN_ACCOUNT, 1_000_200);
        assert_eq!(
            verify_approval_token(&token, &req, VALID_SOURCE_TOKEN_ACCOUNT, 1_000_100),
            Ok(())
        );
    }

    #[test]
    fn approval_token_confirms_at_the_exact_expiry_slot() {
        let req = sample_req();
        let token = build_approval_token(&req, VALID_SOURCE_TOKEN_ACCOUNT, 1_000_200);
        assert_eq!(
            verify_approval_token(&token, &req, VALID_SOURCE_TOKEN_ACCOUNT, 1_000_200),
            Ok(())
        );
    }

    #[test]
    fn approval_token_rejects_one_slot_past_expiry() {
        let req = sample_req();
        let token = build_approval_token(&req, VALID_SOURCE_TOKEN_ACCOUNT, 1_000_200);
        assert_eq!(
            verify_approval_token(&token, &req, VALID_SOURCE_TOKEN_ACCOUNT, 1_000_201),
            Err(ApprovalError::Expired {
                expires_at_slot: 1_000_200,
                current_slot: 1_000_201,
            })
        );
    }

    #[test]
    fn approval_token_rejects_a_different_amount_than_it_was_issued_for() {
        let req = sample_req();
        let token = build_approval_token(&req, VALID_SOURCE_TOKEN_ACCOUNT, 1_000_200);
        let mut bumped_req = req.clone();
        bumped_req.amount_atomic += 1;
        assert_eq!(
            verify_approval_token(&token, &bumped_req, VALID_SOURCE_TOKEN_ACCOUNT, 1_000_100),
            Err(ApprovalError::Mismatch),
            "a token issued for one amount must not confirm a payment for a different amount"
        );
    }

    #[test]
    fn approval_token_rejects_a_different_destination_than_it_was_issued_for() {
        let req = sample_req();
        let token = build_approval_token(&req, VALID_SOURCE_TOKEN_ACCOUNT, 1_000_200);
        let mut redirected_req = req.clone();
        redirected_req.pay_to = VALID_OWNER.to_string();
        assert_eq!(
            verify_approval_token(
                &token,
                &redirected_req,
                VALID_SOURCE_TOKEN_ACCOUNT,
                1_000_100
            ),
            Err(ApprovalError::Mismatch),
            "a token issued for one recipient must not confirm a payment to a different one"
        );
    }

    #[test]
    fn approval_token_rejects_a_different_fee_payer_than_it_was_issued_for() {
        // A malicious or compromised server changing which address gets
        // sponsored between "propose" (what a human reads and approves) and
        // "confirm" (what actually gets signed) must invalidate the token —
        // the same protection already proven above for amount and payTo.
        let req = sample_req();
        let token = build_approval_token(&req, VALID_SOURCE_TOKEN_ACCOUNT, 1_000_200);
        let mut responsored_req = req.clone();
        responsored_req.fee_payer = Some(VALID_OWNER.to_string());
        assert_eq!(
            verify_approval_token(
                &token,
                &responsored_req,
                VALID_SOURCE_TOKEN_ACCOUNT,
                1_000_100
            ),
            Err(ApprovalError::Mismatch),
            "a token issued for one fee payer must not confirm a payment sponsored by a different one"
        );
    }

    #[test]
    fn approval_token_rejects_garbage_input() {
        let req = sample_req();
        assert_eq!(
            verify_approval_token("not-a-real-token", &req, VALID_SOURCE_TOKEN_ACCOUNT, 1),
            Err(ApprovalError::Malformed)
        );
        assert_eq!(
            verify_approval_token("", &req, VALID_SOURCE_TOKEN_ACCOUNT, 1),
            Err(ApprovalError::Malformed)
        );
    }

    #[test]
    fn approval_token_rejects_a_token_forged_for_a_different_session_token_account() {
        // Same payment requirements, but issued against a different paying
        // account than the one confirming — must not cross-authorize.
        let req = sample_req();
        let token =
            build_approval_token(&req, "SomeOtherTokenAccount11111111111111111111", 1_000_200);
        assert_eq!(
            verify_approval_token(&token, &req, VALID_SOURCE_TOKEN_ACCOUNT, 1_000_100),
            Err(ApprovalError::Mismatch)
        );
    }
}

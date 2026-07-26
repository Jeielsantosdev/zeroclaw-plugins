//! Pure x402 payment-requirements policy core. No wit-bindgen or wasm
//! dependency, so it compiles and tests on the host with a plain
//! `cargo test`; the wasm component reuses the exact same logic through
//! `lib.rs`.
//!
//! This plugin never pays. It fetches an x402-gated resource, parses
//! whichever shape the server used for its HTTP 402 payment-requirements
//! body, and returns a GO/NO-GO verdict against operator-configured policy.
//! Every field a malicious or compromised server could lie about (network,
//! mint, amount, recipient, timeout window) is validated here, never trusted
//! from the wire.
//!
//! Two co-existing, mutually incompatible response shapes have been observed
//! in the wild for the same protocol (see the README, "Why the parser
//! accepts two different response shapes"): the cross-chain x402 spec v2
//! `accepts[]` array, and a flatter ad-hoc shape demonstrated in the Solana
//! Foundation's own tutorial. Both are parsed defensively; neither is
//! assumed to be the only valid one.

use std::collections::HashMap;

/// Well-known USDC mint on Solana mainnet-beta. Public, stable, documented
/// constant — safe as a default; operators can override via config to point
/// at a different mint (e.g. devnet USDC) if they run against a test cluster.
pub const DEFAULT_MAINNET_USDC_MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";

/// Conservative default per-call amount cap: 5.00 USDC in atomic units
/// (6 decimals). This plugin never spends anything itself — the cap only
/// shapes what counts as a sane GO verdict for a human/agent to act on.
pub const DEFAULT_MAX_AMOUNT_ATOMIC: u64 = 5_000_000;

/// Conservative default timeout ceiling: reject any payment window the
/// server asks for beyond 5 minutes. A very long window widens the exposure
/// if the proof-of-payment transaction is replayed or delayed.
pub const DEFAULT_MAX_TIMEOUT_SECONDS: u64 = 300;

/// Operator policy resolved from this plugin's own config section.
#[derive(Debug, Clone, PartialEq)]
pub struct QuoteCheckConfig {
    pub expected_network: SolanaCluster,
    pub known_mint: String,
    pub max_amount_atomic: u64,
    pub max_timeout_seconds: u64,
}

impl QuoteCheckConfig {
    /// Build from the flat `string -> string` section the host injects.
    /// Absent or empty keys fall back to safe, conservative defaults — this
    /// is also exactly what an unprivileged (no `config_read`) plugin sees.
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
        Self {
            expected_network,
            known_mint,
            max_amount_atomic,
            max_timeout_seconds,
        }
    }
}

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

/// Normalized Solana cluster identifier. Response shapes spell this three
/// different ways in the wild: the flat tutorial shape's "mainnet-beta", the
/// spec v2 example's "solana-mainnet", and — confirmed against real live
/// servers — the CAIP-2 form "solana:<genesis-hash>". Comparisons must happen
/// on this normalized form, never on the raw string.
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
}

/// A payment requirement normalized from whichever wire shape the server
/// used. This is the only representation `validate_requirements` sees.
#[derive(Debug, Clone, PartialEq)]
pub struct PaymentRequirement {
    pub network: SolanaCluster,
    pub asset_mint: String,
    pub amount_atomic: u64,
    pub pay_to: String,
    /// `None` means the response did not carry a timeout field at all (the
    /// Solana Foundation flat shape has none) — this is *not* the same as an
    /// unbounded window and is not itself a rejection reason.
    pub max_timeout_seconds: Option<u64>,
    pub source_shape: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// Neither known shape matched. Carries both underlying serde errors so
    /// the caller can log what was actually tried.
    UnrecognizedShape {
        v2_error: String,
        flat_error: String,
    },
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::UnrecognizedShape { v2_error, flat_error } => write!(
                f,
                "response body matches neither known x402 shape (v2 accepts[]: {v2_error}; solana-foundation flat: {flat_error})"
            ),
        }
    }
}

/// Parse an HTTP 402 response body, trying the x402 spec v2 `accepts[]`
/// shape first, then the Solana Foundation tutorial's flat shape. Rejects
/// only if neither matches — this is schema tolerance for a genuinely
/// unsettled ecosystem, not leniency toward malicious input; every field
/// that survives parsing is still fully validated by `validate_requirements`.
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

/// Header value length cap, applied before base64 decoding. Confirmed
/// against a real live server (Otto AI), a single `accepts[]` entry's
/// `PAYMENT-REQUIRED` header runs a few KB; this is a generous multiple of
/// that, purely to bound decode cost against a hostile or misbehaving server
/// — same rationale as `MAX_BODY_BYTES` in the wasm shim.
const MAX_PAYMENT_REQUIRED_HEADER_LEN: usize = 64 * 1024;

/// Parse an x402 402 response using the real-world shape confirmed against
/// live Solana x402 servers (Otto AI, Syra, 2026-07-23): the payment
/// requirements travel in a base64-encoded `PAYMENT-REQUIRED` response
/// *header*, spec v2's `accepts[]` JSON — not in the response body at all
/// (the body is typically just a human-readable hint). The header is tried
/// first; if it is absent, oversized, not valid base64/UTF-8/JSON, or lacks
/// `accepts[]`, this falls back to `parse_requirements` on the body, which
/// preserves compatibility with servers that (per the spec, or per the
/// Solana Foundation tutorial's example) put the payload in the body
/// instead. Never silently accepts a header that seems malformed — that
/// falls through, not through to "assume the first field it found".
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
    struct Accept {
        network: String,
        asset: String,
        #[serde(rename = "payTo")]
        pay_to: String,
        #[serde(rename = "maxTimeoutSeconds")]
        max_timeout_seconds: Option<u64>,
        amount: AmountField,
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
    // AI response, 2026-07-23: Base, Polygon, and Solana legs for the same
    // resource, in that order). This plugin only ever validates Solana
    // payments, so it must pick the first *Solana* entry, not blindly
    // `accepts[0]` — otherwise every multi-chain server's Solana option goes
    // unevaluated and every call reports a spurious network-mismatch NO-GO.
    // When every entry is Solana (or there is only one), this is exactly
    // `accepts[0]`, preserving the existing anti-scanning invariant: a
    // hostile server offering many same-network entries can't influence
    // which one gets picked by amount or any other field.
    // Entry-selection uses a loose "does this look like Solana" string
    // check, deliberately not `SolanaCluster::parse` — real servers send
    // non-standard network identifiers (Otto AI's Solana leg uses a
    // truncated, 32-char genesis hash, not the real 44-char one), and a
    // strict check here would fall through to picking the wrong (EVM) leg
    // entirely. This is safe precisely because it is *only* a selection
    // heuristic: `validate_requirements` still runs the strict, exact
    // `SolanaCluster` comparison against policy afterwards, so a
    // mis-selected or malformed entry still cannot produce a false GO.
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

    Ok(PaymentRequirement {
        network: SolanaCluster::parse(&chosen.network),
        asset_mint: chosen.asset,
        amount_atomic,
        pay_to: chosen.pay_to,
        max_timeout_seconds: chosen.max_timeout_seconds,
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

    Ok(PaymentRequirement {
        network: SolanaCluster::parse(&parsed.payment.cluster),
        asset_mint: parsed.payment.mint,
        amount_atomic,
        pay_to: parsed.payment.recipient_wallet,
        max_timeout_seconds: None,
        source_shape: "solana-foundation-flat",
    })
}

/// `amount` has been observed both as a JSON string (spec v2, to preserve
/// precision) and as a JSON number (Solana Foundation flat shape). Accept
/// either; reject negative, fractional, or unparseable values rather than
/// silently truncating.
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

/// Outcome of validating a `PaymentRequirement` against operator policy.
#[derive(Debug, Clone, PartialEq)]
pub enum Verdict {
    Go { summary: String },
    NoGo { reasons: Vec<String> },
}

/// Validate every field a hostile or compromised server could lie about.
/// Every check runs (not just the first failure) so the verdict is a
/// complete, honest picture — never "looks fine" on a partial check.
pub fn validate_requirements(req: &PaymentRequirement, cfg: &QuoteCheckConfig) -> Verdict {
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
                "requirements within policy: {} atomic units of {} to {} on {:?} ({})",
                req.amount_atomic, req.asset_mint, req.pay_to, req.network, req.source_shape
            ),
        }
    } else {
        Verdict::NoGo { reasons }
    }
}

/// A base58-encoded 32-byte value never legitimately exceeds ~44 characters;
/// this generous cap exists purely to reject pathological input *before*
/// `bs58::decode` ever sees it. `bs58`'s decoder is O(n²) in the input
/// length (confirmed empirically: ~0.2ms at 1,000 chars, ~530ms at 50,000
/// chars) — an attacker-controlled `payTo` string with no length check
/// ahead of decoding is a real CPU-exhaustion vector, not a theoretical one.
/// A malicious or compromised x402 server controls this field entirely.
const MAX_BASE58_PUBKEY_INPUT_LEN: usize = 64;

/// A Solana public key is exactly 32 bytes once base58-decoded. This does
/// not prove the account exists or is the "right" one — only that the field
/// is not garbage, a lookalike string, or an injection attempt.
fn is_well_formed_pubkey(candidate: &str) -> bool {
    if candidate.len() > MAX_BASE58_PUBKEY_INPUT_LEN {
        return false;
    }
    match bs58::decode(candidate).into_vec() {
        Ok(bytes) => bytes.len() == 32,
        Err(_) => false,
    }
}

/// Format a verdict into the compact, human-readable text this plugin
/// returns as its `output` — never a raw JSON dump.
pub fn format_brief(verdict: &Verdict) -> String {
    match verdict {
        Verdict::Go { summary } => format!("GO — {summary}"),
        Verdict::NoGo { reasons } => format!("NO-GO — {}", reasons.join("; ")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> QuoteCheckConfig {
        QuoteCheckConfig::from_section(&HashMap::new())
    }

    const VALID_PAYTO: &str = "4Nd1mYPBQaXJVwZC5tSTQKQZoT4XU3Pa9wBHLo3vSJRD"; // arbitrary valid-looking 32-byte base58 pubkey

    #[test]
    fn empty_config_uses_safe_defaults() {
        let cfg = default_config();
        assert_eq!(cfg.expected_network, SolanaCluster::Mainnet);
        assert_eq!(cfg.known_mint, DEFAULT_MAINNET_USDC_MINT);
        assert_eq!(cfg.max_amount_atomic, DEFAULT_MAX_AMOUNT_ATOMIC);
        assert_eq!(cfg.max_timeout_seconds, DEFAULT_MAX_TIMEOUT_SECONDS);
    }

    #[test]
    fn config_reads_overrides_from_section() {
        let mut section = HashMap::new();
        section.insert("expected_network".to_string(), "solana-devnet".to_string());
        section.insert("max_amount_atomic".to_string(), "1000".to_string());
        let cfg = QuoteCheckConfig::from_section(&section);
        assert_eq!(cfg.expected_network, SolanaCluster::Devnet);
        assert_eq!(cfg.max_amount_atomic, 1000);
    }

    #[test]
    fn parses_v2_accepts_shape_with_string_amount() {
        let body = serde_json::json!({
            "x402Version": 2,
            "accepts": [{
                "scheme": "exact",
                "network": "solana-mainnet",
                "amount": "1000000",
                "asset": DEFAULT_MAINNET_USDC_MINT,
                "payTo": VALID_PAYTO,
                "maxTimeoutSeconds": 60
            }]
        })
        .to_string();

        let req = parse_requirements(&body).expect("should parse v2 shape");
        assert_eq!(req.source_shape, "x402-spec-v2-accepts");
        assert_eq!(req.amount_atomic, 1_000_000);
        assert_eq!(req.network, SolanaCluster::Mainnet);
        assert_eq!(req.max_timeout_seconds, Some(60));
    }

    #[test]
    fn parses_v2_accepts_shape_with_caip2_network() {
        let body = serde_json::json!({
            "x402Version": 2,
            "accepts": [{
                "scheme": "exact",
                "network": format!("solana:{MAINNET_GENESIS_HASH}"),
                "amount": "1000000",
                "asset": DEFAULT_MAINNET_USDC_MINT,
                "payTo": VALID_PAYTO,
                "maxTimeoutSeconds": 60
            }]
        })
        .to_string();

        let req = parse_requirements(&body).expect("should parse v2 shape with CAIP-2 network");
        assert_eq!(req.network, SolanaCluster::Mainnet);
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
    fn parses_solana_foundation_flat_shape_with_numeric_amount() {
        let body = serde_json::json!({
            "payment": {
                "recipientWallet": VALID_PAYTO,
                "tokenAccount": "irrelevant-here",
                "mint": DEFAULT_MAINNET_USDC_MINT,
                "amount": 2_500_000,
                "amountUSDC": 2.5,
                "cluster": "mainnet-beta",
                "message": "pay for the resource"
            }
        })
        .to_string();

        let req = parse_requirements(&body).expect("should parse flat shape");
        assert_eq!(req.source_shape, "solana-foundation-flat");
        assert_eq!(req.amount_atomic, 2_500_000);
        assert_eq!(req.network, SolanaCluster::Mainnet);
        assert_eq!(req.max_timeout_seconds, None);
    }

    #[test]
    fn rejects_garbage_json_matching_neither_shape() {
        let err = parse_requirements(r#"{"totally": "unrelated"}"#).unwrap_err();
        match err {
            ParseError::UnrecognizedShape { .. } => {}
        }
    }

    #[test]
    fn rejects_non_numeric_amount_string() {
        let body = serde_json::json!({
            "accepts": [{
                "network": "solana-mainnet",
                "amount": "not-a-number",
                "asset": DEFAULT_MAINNET_USDC_MINT,
                "payTo": VALID_PAYTO,
            }]
        })
        .to_string();
        assert!(parse_requirements(&body).is_err());
    }

    #[test]
    fn validate_allows_request_within_policy() {
        let cfg = default_config();
        let req = PaymentRequirement {
            network: SolanaCluster::Mainnet,
            asset_mint: DEFAULT_MAINNET_USDC_MINT.to_string(),
            amount_atomic: 1_000_000,
            pay_to: VALID_PAYTO.to_string(),
            max_timeout_seconds: Some(60),
            source_shape: "x402-spec-v2-accepts",
        };
        match validate_requirements(&req, &cfg) {
            Verdict::Go { .. } => {}
            Verdict::NoGo { reasons } => panic!("expected GO, got NO-GO: {reasons:?}"),
        }
    }

    #[test]
    fn validate_rejects_wrong_network() {
        let cfg = default_config();
        let req = PaymentRequirement {
            network: SolanaCluster::Devnet,
            asset_mint: DEFAULT_MAINNET_USDC_MINT.to_string(),
            amount_atomic: 1,
            pay_to: VALID_PAYTO.to_string(),
            max_timeout_seconds: None,
            source_shape: "test",
        };
        match validate_requirements(&req, &cfg) {
            Verdict::NoGo { reasons } => {
                assert!(reasons.iter().any(|r| r.contains("network mismatch")))
            }
            Verdict::Go { .. } => panic!("expected NO-GO for wrong network"),
        }
    }

    #[test]
    fn validate_rejects_unknown_mint() {
        let cfg = default_config();
        let req = PaymentRequirement {
            network: SolanaCluster::Mainnet,
            asset_mint: "LookalikeUSDCMintThatIsNotTheRealOne111111".to_string(),
            amount_atomic: 1,
            pay_to: VALID_PAYTO.to_string(),
            max_timeout_seconds: None,
            source_shape: "test",
        };
        match validate_requirements(&req, &cfg) {
            Verdict::NoGo { reasons } => {
                assert!(reasons.iter().any(|r| r.contains("unexpected mint")))
            }
            Verdict::Go { .. } => panic!("expected NO-GO for unknown mint"),
        }
    }

    #[test]
    fn validate_rejects_amount_over_cap() {
        let cfg = default_config();
        let req = PaymentRequirement {
            network: SolanaCluster::Mainnet,
            asset_mint: DEFAULT_MAINNET_USDC_MINT.to_string(),
            amount_atomic: DEFAULT_MAX_AMOUNT_ATOMIC + 1,
            pay_to: VALID_PAYTO.to_string(),
            max_timeout_seconds: None,
            source_shape: "test",
        };
        match validate_requirements(&req, &cfg) {
            Verdict::NoGo { reasons } => assert!(reasons
                .iter()
                .any(|r| r.contains("exceeds configured per-call cap"))),
            Verdict::Go { .. } => panic!("expected NO-GO for amount over cap"),
        }
    }

    #[test]
    fn validate_rejects_malformed_payto() {
        let cfg = default_config();
        let req = PaymentRequirement {
            network: SolanaCluster::Mainnet,
            asset_mint: DEFAULT_MAINNET_USDC_MINT.to_string(),
            amount_atomic: 1,
            pay_to: "not-base58-!!!".to_string(),
            max_timeout_seconds: None,
            source_shape: "test",
        };
        match validate_requirements(&req, &cfg) {
            Verdict::NoGo { reasons } => {
                assert!(reasons.iter().any(|r| r.contains("not a well-formed")))
            }
            Verdict::Go { .. } => panic!("expected NO-GO for malformed payTo"),
        }
    }

    #[test]
    fn validate_rejects_payto_wrong_byte_length() {
        let cfg = default_config();
        // Valid base58, but decodes to far fewer than 32 bytes.
        let req = PaymentRequirement {
            network: SolanaCluster::Mainnet,
            asset_mint: DEFAULT_MAINNET_USDC_MINT.to_string(),
            amount_atomic: 1,
            pay_to: bs58::encode([1u8, 2, 3]).into_string(),
            max_timeout_seconds: None,
            source_shape: "test",
        };
        match validate_requirements(&req, &cfg) {
            Verdict::NoGo { reasons } => {
                assert!(reasons.iter().any(|r| r.contains("not a well-formed")))
            }
            Verdict::Go { .. } => panic!("expected NO-GO for wrong-length payTo"),
        }
    }

    #[test]
    fn validate_rejects_timeout_over_ceiling() {
        let cfg = default_config();
        let req = PaymentRequirement {
            network: SolanaCluster::Mainnet,
            asset_mint: DEFAULT_MAINNET_USDC_MINT.to_string(),
            amount_atomic: 1,
            pay_to: VALID_PAYTO.to_string(),
            max_timeout_seconds: Some(DEFAULT_MAX_TIMEOUT_SECONDS + 1),
            source_shape: "test",
        };
        match validate_requirements(&req, &cfg) {
            Verdict::NoGo { reasons } => {
                assert!(reasons.iter().any(|r| r.contains("maxTimeoutSeconds")))
            }
            Verdict::Go { .. } => panic!("expected NO-GO for timeout over ceiling"),
        }
    }

    #[test]
    fn validate_collects_every_failing_reason_not_just_the_first() {
        let cfg = default_config();
        let req = PaymentRequirement {
            network: SolanaCluster::Devnet,
            asset_mint: "NotTheRealMint".to_string(),
            amount_atomic: DEFAULT_MAX_AMOUNT_ATOMIC + 1,
            pay_to: "garbage".to_string(),
            max_timeout_seconds: Some(DEFAULT_MAX_TIMEOUT_SECONDS + 1),
            source_shape: "test",
        };
        match validate_requirements(&req, &cfg) {
            Verdict::NoGo { reasons } => assert_eq!(
                reasons.len(),
                5,
                "expected all 5 checks to fail: {reasons:?}"
            ),
            Verdict::Go { .. } => panic!("expected NO-GO"),
        }
    }

    #[test]
    fn format_brief_never_leaks_raw_json_and_stays_compact() {
        let go = format_brief(&Verdict::Go {
            summary: "ok".to_string(),
        });
        assert!(go.starts_with("GO"));
        let nogo = format_brief(&Verdict::NoGo {
            reasons: vec!["bad mint".to_string()],
        });
        assert!(nogo.starts_with("NO-GO"));
    }
}

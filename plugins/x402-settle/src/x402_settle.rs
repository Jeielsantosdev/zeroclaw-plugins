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
/// Instruction tag for `spl_token::instruction::TokenInstruction::Transfer`.
pub(crate) const SPL_TOKEN_TRANSFER_TAG: u8 = 3;

// ---------------------------------------------------------------------------
// Requirement parsing and policy validation (duplicated from x402-quote-check)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SolanaCluster {
    Mainnet,
    Devnet,
    Other(String),
}

impl SolanaCluster {
    pub fn parse(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "solana-mainnet" | "mainnet-beta" | "mainnet" => SolanaCluster::Mainnet,
            "solana-devnet" | "devnet" => SolanaCluster::Devnet,
            other => SolanaCluster::Other(other.to_string()),
        }
    }

    /// The canonical x402 spec v2 network label for this cluster, used when
    /// building the outgoing `X-Payment` payload. Always the spec's own
    /// naming convention, regardless of which shape the *inbound* 402 used.
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
    pub asset_mint: String,
    pub amount_atomic: u64,
    pub pay_to: String,
    pub max_timeout_seconds: Option<u64>,
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
    let first = parsed
        .accepts
        .into_iter()
        .next()
        .ok_or_else(|| "accepts[] is empty".to_string())?;
    let amount_atomic = first.amount.into_u64()?;

    Ok(PaymentRequirement {
        network: SolanaCluster::parse(&first.network),
        asset_mint: first.asset,
        amount_atomic,
        pay_to: first.pay_to,
        max_timeout_seconds: first.max_timeout_seconds,
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
// SPL Token `Transfer` instruction — manual byte layout, no solana-sdk
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountMeta {
    pub pubkey: [u8; 32],
    pub is_signer: bool,
    pub is_writable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstructionPlan {
    pub program_id: [u8; 32],
    pub accounts: Vec<AccountMeta>,
    pub data: Vec<u8>,
}

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

fn decode_pubkey(field: &'static str, candidate: &str) -> Result<[u8; 32], BuildInstructionError> {
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

/// Build an SPL Token `Transfer` instruction (tag `3`): moves `amount_atomic`
/// from `source_token_account` to `destination_token_account`, authorized by
/// `owner` (the session key's public key). This is an **inbound-only**
/// primitive by construction: there is no code path here for `Withdraw`,
/// `Burn`, or any instruction shape other than a plain transfer out of the
/// account this plugin itself controls.
pub fn build_transfer_instruction(
    source_token_account: &str,
    destination_token_account: &str,
    owner: &str,
    amount_atomic: u64,
) -> Result<InstructionPlan, BuildInstructionError> {
    let program_id = decode_pubkey("spl_token_program", SPL_TOKEN_PROGRAM_ID)?;
    let source = decode_pubkey("source_token_account", source_token_account)?;
    let destination = decode_pubkey("destination_token_account", destination_token_account)?;
    let owner_key = decode_pubkey("owner", owner)?;

    let mut data = Vec::with_capacity(9);
    data.push(SPL_TOKEN_TRANSFER_TAG);
    data.extend_from_slice(&amount_atomic.to_le_bytes());

    Ok(InstructionPlan {
        program_id,
        accounts: vec![
            AccountMeta {
                pubkey: source,
                is_signer: false,
                is_writable: true,
            },
            AccountMeta {
                pubkey: destination,
                is_signer: false,
                is_writable: true,
            },
            AccountMeta {
                pubkey: owner_key,
                is_signer: true,
                is_writable: false,
            },
        ],
        data,
    })
}

// ---------------------------------------------------------------------------
// Signing — ed25519 over the session key, never the operator's main wallet
// ---------------------------------------------------------------------------

/// Decode a base58-encoded 32-byte ed25519 seed. Kept as a dedicated function,
/// distinct from `SettlePolicyConfig`, so the key material is never routed
/// through a `Debug`-derivable struct that a stray `{:?}` log could leak.
pub fn decode_session_key_seed(raw_base58: &str) -> Result<[u8; 32], String> {
    // Operator config, not attacker-controlled in the normal threat model —
    // but the same O(n^2) bs58::decode cost applies to any input, so the
    // same length guard applies here too, on general defense-in-depth
    // principle (see MAX_BASE58_PUBKEY_INPUT_LEN's doc comment).
    if raw_base58.len() > MAX_BASE58_PUBKEY_INPUT_LEN {
        return Err(format!(
            "session key input is {} bytes, longer than any valid 32-byte seed could be",
            raw_base58.len()
        ));
    }
    let bytes = bs58::decode(raw_base58)
        .into_vec()
        .map_err(|e| format!("session key is not valid base58: {e}"))?;
    bytes
        .try_into()
        .map_err(|_| "session key must decode to exactly 32 bytes".to_string())
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
            asset_mint: DEFAULT_MAINNET_USDC_MINT.to_string(),
            amount_atomic: 1_000_000,
            pay_to: VALID_PAYTO.to_string(),
            max_timeout_seconds: Some(30),
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
            asset_mint: "NotTheRealMint".to_string(),
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

    // ---- instruction building ----

    #[test]
    fn build_transfer_instruction_has_correct_tag_and_amount_layout() {
        let plan = build_transfer_instruction(
            VALID_SOURCE_TOKEN_ACCOUNT,
            VALID_PAYTO,
            VALID_OWNER,
            1_000_000,
        )
        .expect("valid pubkeys must build");
        assert_eq!(plan.data[0], SPL_TOKEN_TRANSFER_TAG);
        assert_eq!(&plan.data[1..9], &1_000_000u64.to_le_bytes());
        assert_eq!(plan.data.len(), 9);
    }

    #[test]
    fn build_transfer_instruction_account_metas_are_source_dest_owner_signer_only() {
        let plan =
            build_transfer_instruction(VALID_SOURCE_TOKEN_ACCOUNT, VALID_PAYTO, VALID_OWNER, 1)
                .unwrap();
        assert_eq!(plan.accounts.len(), 3);
        assert!(plan.accounts[0].is_writable && !plan.accounts[0].is_signer);
        assert!(plan.accounts[1].is_writable && !plan.accounts[1].is_signer);
        assert!(plan.accounts[2].is_signer && !plan.accounts[2].is_writable);
    }

    #[test]
    fn build_transfer_instruction_rejects_malformed_destination() {
        let err = build_transfer_instruction(
            VALID_SOURCE_TOKEN_ACCOUNT,
            "not-base58-!!!",
            VALID_OWNER,
            1,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            BuildInstructionError::InvalidPubkey {
                field: "destination_token_account",
                ..
            }
        ));
    }

    #[test]
    fn build_transfer_instruction_rejects_wrong_length_pubkey() {
        let short = bs58::encode([1u8, 2, 3]).into_string();
        let err = build_transfer_instruction(&short, VALID_PAYTO, VALID_OWNER, 1).unwrap_err();
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
}

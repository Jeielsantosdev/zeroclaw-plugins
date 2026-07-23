//! Regression tests against a **real** 402 response, captured live from
//! `https://x402.ottoai.services/crypto-news` on 2026-07-23 (see
//! `tests/fixtures/`, raw header/body, no edits) — identical fixture to
//! `x402-quote-check`'s (duplicated by design, same reason `x402_settle.rs`
//! duplicates the policy core: the CI validator snapshots each plugin
//! directory in isolation). Catches the same two real-world bugs unit tests
//! against hand-written fixtures missed:
//! - the payload lives in the base64 `PAYMENT-REQUIRED` *header*, not the
//!   body — `parse_requirements` alone rejects every real response;
//! - `accepts[]` is multi-chain; the Solana leg must be selected, not
//!   `accepts[0]`.

use std::collections::HashMap;

use x402_settle::x402_settle::{
    parse_requirements, parse_requirements_from_response, validate_requirements,
    SettlePolicyConfig, SolanaCluster, Verdict,
};

const OTTO_HEADER: &str =
    include_str!("fixtures/otto_ai_crypto_news_payment_required_header.b64.txt");
const OTTO_BODY: &str = include_str!("fixtures/otto_ai_crypto_news_body.json");

fn section(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

#[test]
fn body_alone_cannot_be_parsed_this_is_the_bug_the_header_path_fixes() {
    let err = parse_requirements(OTTO_BODY.trim());
    assert!(
        err.is_err(),
        "Otto AI's real 402 body has no accepts[] at all — if this ever \
         parses, something changed upstream"
    );
}

#[test]
fn real_otto_ai_header_parses_and_selects_the_solana_leg_not_the_first_evm_one() {
    let req = parse_requirements_from_response(Some(OTTO_HEADER.trim()), OTTO_BODY.trim())
        .expect("header path should parse the real Otto AI 402");
    assert_eq!(req.source_shape, "x402-spec-v2-accepts");
    assert_eq!(
        req.asset_mint, "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
        "must have picked the Solana accepts[] entry (real USDC mint), not an EVM one"
    );
    assert_eq!(
        req.pay_to, "6XcSfqJHr9vNW2vbiRaMqUYVm7shDgLepca54wUTDPN5",
        "must have picked the Solana accepts[] entry's payTo, not an EVM 0x address"
    );
}

#[test]
fn real_otto_ai_solana_leg_has_a_nonstandard_truncated_genesis_hash() {
    let truncated = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp";
    match SolanaCluster::parse(truncated) {
        SolanaCluster::Other(_) => {}
        other => panic!(
            "expected the truncated genesis hash to fall through to Other \
             (fail closed), got {other:?} instead"
        ),
    }
}

#[test]
fn end_to_end_no_go_against_real_otto_ai_response_nonstandard_genesis_hash() {
    let cfg = SettlePolicyConfig::from_section(&section(&[]));
    let req = parse_requirements_from_response(Some(OTTO_HEADER.trim()), OTTO_BODY.trim())
        .expect("header path should parse the real Otto AI 402");
    match validate_requirements(&req, &cfg) {
        Verdict::NoGo { reasons } => {
            assert!(
                reasons.iter().any(|r| r.contains("network mismatch")),
                "expected a network-mismatch reason for the truncated genesis \
                 hash, got: {reasons:?}"
            );
        }
        Verdict::Go { .. } => panic!(
            "expected NO-GO: Otto AI's Solana leg network field does not match \
             the real mainnet genesis hash"
        ),
    }
}

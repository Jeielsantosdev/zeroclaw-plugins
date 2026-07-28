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
fn real_otto_ai_solana_leg_carries_a_real_facilitator_fee_payer_and_raw_network() {
    // This real, live-captured Otto AI response's Solana leg has an
    // `extra.feePayer` — confirming the facilitator-sponsorship model
    // (`EDITAL.md`: "the facilitator co-signs as fee payer") against a real
    // server, not just the PayAI reference client's source code. `network`
    // must also survive verbatim (the CAIP-2 string, not the normalized
    // "solana-mainnet" label) for `accepted.network` to round-trip
    // correctly in the reply envelope — see `PaymentRequirement::network_raw`'s
    // doc comment for why the normalized label is unsafe to echo back.
    let req = parse_requirements_from_response(Some(OTTO_HEADER.trim()), OTTO_BODY.trim())
        .expect("header path should parse the real Otto AI 402");
    assert_eq!(
        req.fee_payer.as_deref(),
        Some("GVJJ7rdGiXr5xaYbRwRbjfaJL7fmwRygFi1H6aGqDveb")
    );
    assert_eq!(req.network_raw, "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp");
}

#[test]
fn real_otto_ai_solana_leg_genesis_hash_is_caip2_truncated_by_spec_not_malformed() {
    // The CAIP-2 Solana namespace spec (ChainAgnostic/namespaces,
    // solana/caip2.md) mandates `truncate(genesisHash, 32)` as the chain
    // reference — CAIP-2 itself caps chain references at 32 chars, so
    // Otto AI's 32-char form is spec-conformant, not malformed. Treating
    // it as unrecognized was a real bug (fixed 2026-07-26) that made this
    // plugin unable to ever produce a GO against any real-world
    // CAIP-2-compliant x402 server.
    let truncated = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp";
    assert_eq!(
        SolanaCluster::parse(truncated),
        SolanaCluster::Mainnet,
        "the CAIP-2-truncated genesis hash must resolve to Mainnet"
    );
}

#[test]
fn end_to_end_go_against_real_otto_ai_response_after_caip2_fix() {
    // Every field in this real, captured response is well within the
    // default policy (amount 1000 < 5_000_000 cap, timeout 300s == the
    // 300s cap, asset matches the default mainnet USDC mint) once the
    // CAIP-2 network fix correctly resolves the network to Mainnet — so
    // the correct verdict is GO. Before the fix this incorrectly came
    // back NO-GO on "network mismatch" for every real Solana x402 offer,
    // not just malformed ones.
    let cfg = SettlePolicyConfig::from_section(&section(&[]));
    let req = parse_requirements_from_response(Some(OTTO_HEADER.trim()), OTTO_BODY.trim())
        .expect("header path should parse the real Otto AI 402");
    match validate_requirements(&req, &cfg) {
        Verdict::Go { .. } => {}
        Verdict::NoGo { reasons } => panic!(
            "expected GO against this real, well-formed Otto AI offer, got NO-GO: {reasons:?}"
        ),
    }
}

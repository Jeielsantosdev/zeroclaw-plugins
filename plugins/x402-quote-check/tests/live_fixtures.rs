//! Regression tests against a **real** 402 response, captured live from
//! `https://x402.ottoai.services/crypto-news` on 2026-07-23 (see
//! `tests/fixtures/`, raw header/body, no edits). This is what actually
//! caught the bugs unit tests against hand-written fixtures missed:
//! - the payload lives in the base64 `PAYMENT-REQUIRED` *header*, not the
//!   body (the body is just a human-readable hint with no `accepts[]` at
//!   all) — `parse_requirements` alone would reject every real response;
//! - the Solana leg's `network` is CAIP-2 (`solana:<genesis-hash>`), not the
//!   flat `"solana-mainnet"` string.
//!
//! If this file ever needs updating because Otto AI changed its response
//! shape, re-capture with:
//! ```sh
//! curl -sS -D - -o tests/fixtures/otto_ai_crypto_news_body.json \
//!   https://x402.ottoai.services/crypto-news \
//!   | grep -i '^payment-required:' \
//!   | sed 's/^payment-required: //I' | tr -d '\r' \
//!   > tests/fixtures/otto_ai_crypto_news_payment_required_header.b64.txt
//! ```

use std::collections::HashMap;

use x402_quote_check::x402::{
    parse_requirements, parse_requirements_from_response, validate_requirements, QuoteCheckConfig,
    SolanaCluster, Verdict,
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
         parses, something changed upstream and this test (and the header \
         fallback logic) needs revisiting"
    );
}

#[test]
fn real_otto_ai_header_parses_and_selects_the_solana_leg_not_the_first_evm_one() {
    // Otto AI's real accepts[] for this resource is [Base, Base+permit2,
    // Polygon, Polygon+permit2, Solana] — Solana is *last*, not first.
    // parse_v2_accepts_shape must actively pick the Solana entry rather
    // than defaulting to accepts[0] (Base), or this plugin would validate
    // the wrong chain's offer every time against a multi-chain server.
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
fn real_otto_ai_solana_leg_genesis_hash_is_caip2_truncated_by_spec_not_malformed() {
    // Extracted by hand from the same captured header: Otto AI's Solana
    // `accepts[]` entry uses "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp" — 32
    // base58 chars, not the full mainnet genesis hash's 44
    // ("5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d"). This is NOT a
    // server bug: the CAIP-2 Solana namespace spec
    // (ChainAgnostic/namespaces, solana/caip2.md) mandates
    // `truncate(genesisHash, 32)` as the chain reference — CAIP-2 itself
    // caps chain references at 32 chars. SolanaCluster::parse must
    // recognize this truncated form as Mainnet, not fall through to
    // `Other`; treating it as unrecognized was a real bug (fixed
    // 2026-07-26) that made this plugin unable to ever produce a GO
    // against any real-world CAIP-2-compliant x402 server.
    let truncated = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp";
    assert_eq!(
        SolanaCluster::parse(truncated),
        SolanaCluster::Mainnet,
        "the CAIP-2-truncated genesis hash must resolve to Mainnet"
    );
}

#[test]
fn end_to_end_go_against_real_otto_ai_response_after_caip2_fix() {
    // The Solana leg is correctly selected (asset + payTo are the real
    // Solana values, see the test above) and its CAIP-2 network field now
    // correctly resolves to Mainnet. Every other field in this real,
    // captured response is well within the default policy (amount 1000 <
    // 5_000_000 cap, timeout 300s == the 300s cap, asset matches the
    // default mainnet USDC mint) — so the correct verdict is GO. Before
    // the CAIP-2 fix this incorrectly came back NO-GO on "network
    // mismatch" for every real Solana x402 offer, not just malformed ones.
    let cfg = QuoteCheckConfig::from_section(&section(&[]));
    let req = parse_requirements_from_response(Some(OTTO_HEADER.trim()), OTTO_BODY.trim())
        .expect("header path should parse the real Otto AI 402");
    match validate_requirements(&req, &cfg) {
        Verdict::Go { .. } => {}
        Verdict::NoGo { reasons } => panic!(
            "expected GO against this real, well-formed Otto AI offer, got NO-GO: {reasons:?}"
        ),
    }
}

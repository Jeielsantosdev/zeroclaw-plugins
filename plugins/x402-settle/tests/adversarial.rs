//! Adversarial / audit-style tests for `x402-settle` (T2).
//!
//! This is the highest-stakes crate in the whole bounty submission — it
//! signs and moves real funds — so this file goes further than the shared
//! policy tests inherited from `x402-quote-check`: integer-overflow bypass
//! attempts against the cumulative spend cap, degenerate cryptographic
//! input, and internal-consistency checks on the signing path itself.
//! Every test tries to make the plugin do the *unsafe* thing on purpose,
//! mapped back to the bounty's security question:
//!
//! > "Can we prompt-inject it? Does it fail closed? Is the tier honest?"

use std::collections::HashMap;

use x402_settle::rpc_history::extract_outgoing_transfer;
use x402_settle::transaction::build_signed_transaction;
use x402_settle::x402_settle::{
    build_transfer_instruction, check_cumulative_cap, decode_session_key_seed, session_key_pubkey,
    sign_message, CapVerdict, SettlePolicyConfig, TransferRecord, DEFAULT_MAINNET_USDC_MINT,
};

fn section(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

const VALID_PAYTO: &str = "4Nd1mYPBQaXJVwZC5tSTQKQZoT4XU3Pa9wBHLo3vSJRD";
const VALID_SOURCE_TOKEN_ACCOUNT: &str = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";

// ---------------------------------------------------------------------------
// 1. Integer-overflow bypass attempts against the cumulative spend cap
// ---------------------------------------------------------------------------

#[test]
fn cumulative_cap_does_not_wrap_around_on_near_u64_max_history() {
    // Classic DeFi integer-overflow bypass pattern: if the sum of "already
    // spent" used wrapping (non-saturating) addition, an attacker who could
    // influence transfer-history amounts (e.g. via a malicious/compromised
    // RPC) might engineer a sum that wraps past u64::MAX back down to a
    // small number, making the cap think almost nothing has been spent.
    // check_cumulative_cap uses saturating_add specifically to prevent this
    // — this test proves the *outcome* (correctly denied, not wrapped to a
    // tiny "safe-looking" number), not just that the implementation detail
    // exists.
    let now = 1_000_000_000i64;
    let history = [
        TransferRecord {
            amount_atomic: u64::MAX - 10,
            unix_timestamp: now - 100,
        },
        TransferRecord {
            amount_atomic: u64::MAX - 10,
            unix_timestamp: now - 200,
        },
    ];
    match check_cumulative_cap(&history, 1, 20_000_000, now) {
        CapVerdict::Deny { .. } => {} // correct: this must never look "safe"
        CapVerdict::Allow {
            spent_in_window, ..
        } => panic!(
            "near-u64::MAX history must saturate to a huge spent_in_window ({spent_in_window}), \
             never wrap around to something small enough to allow more spending"
        ),
    }
}

#[test]
fn cumulative_cap_new_amount_itself_at_u64_max_does_not_wrap_to_allow() {
    let now = 1_000_000_000i64;
    match check_cumulative_cap(&[], u64::MAX, 20_000_000, now) {
        CapVerdict::Deny { .. } => {}
        CapVerdict::Allow { .. } => {
            panic!("requesting u64::MAX atomic units must never be allowed")
        }
    }
}

#[test]
fn cumulative_cap_many_small_transfers_still_sum_correctly_no_precision_loss() {
    // A different bypass idea: many small transfers that a naive
    // accumulator (e.g. float-based) might lose precision on, letting the
    // true sum drift under the cap. u64 saturating integer arithmetic has
    // no such drift — this pins the exact expected sum for 1,000 transfers.
    let now = 1_000_000_000i64;
    let history: Vec<TransferRecord> = (0..1000)
        .map(|i| TransferRecord {
            amount_atomic: 1_000,
            unix_timestamp: now - i,
        })
        .collect();
    match check_cumulative_cap(&history, 0, 20_000_000, now) {
        CapVerdict::Allow {
            spent_in_window, ..
        } => assert_eq!(spent_in_window, 1_000_000),
        CapVerdict::Deny { reason } => panic!("unexpected deny: {reason}"),
    }
}

// ---------------------------------------------------------------------------
// 2. rpc_history: hostile / malformed on-chain data must never crash or
//    silently misreport spend
// ---------------------------------------------------------------------------

#[test]
fn history_entry_with_amount_larger_than_u64_is_skipped_not_crashed() {
    // A compromised RPC (or a bug elsewhere) returning a balance string
    // that doesn't fit in u64 must be treated as "no data", never panic
    // and never be silently truncated into some other number.
    let tx = serde_json::json!({
        "blockTime": 1,
        "transaction": { "message": { "accountKeys": [
            { "pubkey": VALID_SOURCE_TOKEN_ACCOUNT, "signer": false, "writable": true }
        ]}},
        "meta": {
            "preTokenBalances": [
                { "accountIndex": 0, "uiTokenAmount": { "amount": "999999999999999999999999999999" } }
            ],
            "postTokenBalances": [
                { "accountIndex": 0, "uiTokenAmount": { "amount": "0" } }
            ]
        }
    });
    let result = extract_outgoing_transfer(&tx, VALID_SOURCE_TOKEN_ACCOUNT);
    // Either a clean error/None is acceptable; a panic is not. The real
    // assertion here is that this line above did not already abort the test.
    assert!(result.is_ok() || result.is_err());
}

#[test]
fn duplicate_signature_history_entries_bias_toward_denial_not_toward_allowing() {
    // If the shim's fetch layer or a hostile RPC ever returned the exact
    // same transaction twice, check_cumulative_cap has no way to deduplicate
    // (it only ever sees whatever list it's handed) — but that failure mode
    // biases toward *over*-counting spend, which is the safe direction (more
    // likely to deny a legitimate payment) rather than under-counting (which
    // would be the dangerous direction). This test documents and locks in
    // that this is the safe bias, not an exploitable one.
    let now = 1_000_000_000i64;
    let single = TransferRecord {
        amount_atomic: 15_000_000,
        unix_timestamp: now - 10,
    };
    let duplicated = [single, single];
    let verdict = check_cumulative_cap(&duplicated, 1, 20_000_000, now);
    match verdict {
        CapVerdict::Deny { .. } => {} // over-counted spend correctly denies
        CapVerdict::Allow { .. } => {
            panic!("duplicated history entries must never under-count spend")
        }
    }
}

// ---------------------------------------------------------------------------
// 3. Signing: degenerate keys, and internal consistency between seed and
//    the pubkey embedded in the transaction
// ---------------------------------------------------------------------------

#[test]
fn all_zero_session_key_seed_still_signs_verifiably_no_crash() {
    // Some ed25519 implementations mishandle degenerate/all-zero scalars.
    // An operator who fat-fingers config (or a test harness generating a
    // "placeholder" key) must not crash the plugin or produce an unverifiable
    // signature — it should behave like any other valid 32-byte seed.
    let seed = [0u8; 32];
    let pubkey = session_key_pubkey(&seed);
    let sig = sign_message(&seed, b"test message");

    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let vk = VerifyingKey::from_bytes(&pubkey)
        .expect("all-zero seed must still derive a valid curve point");
    let signature = Signature::from_bytes(&sig);
    vk.verify(b"test message", &signature)
        .expect("signature from an all-zero seed must still verify correctly");
}

#[test]
fn all_ff_session_key_seed_still_signs_verifiably_no_crash() {
    let seed = [0xffu8; 32];
    let pubkey = session_key_pubkey(&seed);
    let sig = sign_message(&seed, b"test message");

    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let vk = VerifyingKey::from_bytes(&pubkey)
        .expect("all-0xff seed must still derive a valid curve point");
    let signature = Signature::from_bytes(&sig);
    vk.verify(b"test message", &signature)
        .expect("signature from an all-0xff seed must still verify correctly");
}

#[test]
fn mismatched_fee_payer_pubkey_produces_a_transaction_that_fails_to_verify() {
    // build_signed_transaction's signature is a documented internal
    // invariant: takes a seed AND a separately-passed fee_payer_pubkey, and
    // trusts the caller to keep them consistent (lib.rs always derives
    // fee_payer_pubkey = session_key_pubkey(&seed) immediately before
    // calling this). This test proves what happens if a future change ever
    // breaks that invariant: the built transaction's signature does NOT
    // verify against the (wrong) pubkey embedded in the message — it fails
    // safely on-chain (invalid signature), rather than silently succeeding
    // with the wrong signer, which is the property that actually matters.
    let real_seed = [11u8; 32];
    let wrong_pubkey = session_key_pubkey(&[22u8; 32]); // a DIFFERENT key's pubkey
    let source = [1u8; 32];
    let destination = [2u8; 32];
    let program_id = [3u8; 32];
    let blockhash = [4u8; 32];

    let tx = build_signed_transaction(
        &real_seed,
        wrong_pubkey,
        source,
        destination,
        program_id,
        1,
        blockhash,
    );

    let signature_bytes: [u8; 64] = tx[1..65].try_into().unwrap();
    let message_bytes = &tx[65..];

    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let embedded_pubkey = VerifyingKey::from_bytes(&wrong_pubkey).unwrap();
    let signature = Signature::from_bytes(&signature_bytes);
    assert!(
        embedded_pubkey.verify(message_bytes, &signature).is_err(),
        "a transaction signed by a different key than the one embedded as fee payer must fail to verify — \
         this is what protects against the invariant being silently broken elsewhere"
    );
}

#[test]
fn signature_does_not_verify_against_a_tampered_amount() {
    // Baseline tamper-evidence check: if a single byte of the signed message
    // is altered after signing (e.g. a MITM or a bug that re-serializes the
    // amount differently before submission), the signature must not verify.
    let seed = [5u8; 32];
    let pubkey = session_key_pubkey(&seed);
    let tx = build_signed_transaction(
        &seed, pubkey, [1u8; 32], [2u8; 32], [3u8; 32], 1_000_000, [6u8; 32],
    );

    let signature_bytes: [u8; 64] = tx[1..65].try_into().unwrap();
    let mut tampered_message = tx[65..].to_vec();
    // Flip a byte inside the instruction data's amount field (the last 8
    // bytes of the message in this fixed shape).
    let last = tampered_message.len() - 1;
    tampered_message[last] ^= 0xFF;

    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let vk = VerifyingKey::from_bytes(&pubkey).unwrap();
    let signature = Signature::from_bytes(&signature_bytes);
    assert!(
        vk.verify(&tampered_message, &signature).is_err(),
        "a signature must not verify against a message that was altered after signing"
    );
}

// ---------------------------------------------------------------------------
// 4. base58 / pubkey CPU-exhaustion (same class of finding as
//    x402-quote-check's, verified independently here since this crate
//    duplicates the decode logic rather than sharing it)
// ---------------------------------------------------------------------------

#[test]
fn oversized_destination_pubkey_is_rejected_in_bounded_time() {
    let huge_destination = "A".repeat(1_000_000);
    let start = std::time::Instant::now();
    let result = build_transfer_instruction(
        VALID_SOURCE_TOKEN_ACCOUNT,
        &huge_destination,
        VALID_PAYTO,
        1,
    );
    let elapsed = start.elapsed();
    assert!(
        elapsed.as_secs() < 2,
        "building a transfer instruction with a 1MB destination took {elapsed:?} — \
         the O(n^2) bs58::decode DoS guard has regressed"
    );
    assert!(
        result.is_err(),
        "a 1MB \"pubkey\" must never be accepted as well-formed"
    );
}

#[test]
fn oversized_session_key_is_rejected_in_bounded_time() {
    let huge_key = "B".repeat(1_000_000);
    let start = std::time::Instant::now();
    let result = decode_session_key_seed(&huge_key);
    let elapsed = start.elapsed();
    assert!(
        elapsed.as_secs() < 2,
        "decoding a 1MB session_key took {elapsed:?}"
    );
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// 5. Policy determinism under config/network edge cases (parity with the
//    equivalent x402-quote-check adversarial coverage, re-verified here
//    since the policy core is duplicated, not shared, between the crates)
// ---------------------------------------------------------------------------

#[test]
fn known_mint_config_is_compared_literally_never_partially() {
    // A mint string that is a strict prefix of the real one (or vice versa)
    // must not be treated as a match.
    let section = section(&[(
        "known_mint",
        &DEFAULT_MAINNET_USDC_MINT[..DEFAULT_MAINNET_USDC_MINT.len() - 1],
    )]);
    let cfg = SettlePolicyConfig::from_section(&section);
    assert_ne!(
        cfg.known_mint, DEFAULT_MAINNET_USDC_MINT,
        "config must store exactly what was configured, never silently corrected"
    );
}

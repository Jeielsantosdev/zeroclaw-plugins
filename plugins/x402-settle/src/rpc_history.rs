//! Parses Solana RPC `getTransaction` responses (jsonParsed encoding) into
//! [`TransferRecord`]s for the cumulative spend cap in
//! [`crate::x402_settle::check_cumulative_cap`].
//!
//! This module only ever reasons about JSON already fetched by the wasm
//! shim — it makes no network calls itself, which is what keeps it
//! host-testable with representative fixtures.
//!
//! **Fixture provenance:** most fixtures below are modeled on the
//! [documented Solana RPC HTTP API](https://solana.com/docs/rpc/http/gettransaction)
//! response shape. One (`extracts_from_a_real_devnet_transaction`) is a
//! trimmed but otherwise verbatim capture of a real `getTransaction` response
//! for signature
//! `47jV74je72xtvHB7MwAXLkrqSDZBWPZouGDGyBq1xydRirMLD2oDnLZEgoDN2cvecnCxzD1gTqT9hjj69gpWuetq`
//! (an SPL Token `transferChecked` for the devnet USDC-style mint
//! `4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU`, fetched from
//! `https://api.devnet.solana.com` — this environment does have live RPC
//! access), confirming the modeled shapes above match reality.

use crate::x402_settle::{TransferRecord, CUMULATIVE_WINDOW_SECONDS};

/// From a `getSignaturesForAddress` response (newest-first), select the
/// signatures that fall within the trailing 24h window ending at
/// `now_unix`, without needing to fetch each one's full transaction first —
/// `getSignaturesForAddress` already reports each entry's `blockTime`.
///
/// Pulled out of the wasm shim into this host-testable pure function on
/// purpose: the filtering logic here is exactly the kind of thing this
/// project's pure-core/thin-shim split exists to protect from going
/// untested, and it very nearly didn't get a single test of its own when
/// it was written straight into `lib.rs`.
///
/// Returns `Err` if more than `max_count` signatures fall inside the
/// window — under-counting real spend by silently checking only some of
/// them would defeat the entire purpose of the cumulative cap this feeds,
/// so an inability to fully verify spend must itself deny the payment, not
/// degrade to "probably fine."
///
/// Scans the whole list instead of stopping at the first stale-looking
/// entry — a malicious RPC could plant an out-of-order entry to trigger an
/// early stop and hide real in-window signatures after it.
pub fn select_signatures_within_window(
    signatures: &[serde_json::Value],
    now_unix: i64,
    max_count: usize,
) -> Result<Vec<&str>, String> {
    let window_start = now_unix.saturating_sub(CUMULATIVE_WINDOW_SECONDS);
    let mut selected = Vec::new();
    for entry in signatures {
        let Some(signature) = entry.get("signature").and_then(|s| s.as_str()) else {
            continue;
        };
        match entry.get("blockTime").and_then(|b| b.as_i64()) {
            Some(block_time) if block_time <= window_start => continue,
            // A missing blockTime is not proof the entry is old — inspect
            // it rather than assume it's out of window.
            _ => selected.push(signature),
        }
    }
    if selected.len() > max_count {
        return Err(format!(
            "at least {} signatures fall within the trailing 24h window, exceeding the {max_count} \
             this plugin will inspect per call",
            selected.len()
        ));
    }
    Ok(selected)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HistoryParseError {
    /// The response doesn't look like a transaction at all (missing
    /// `transaction`/`meta`) — fail closed rather than guess.
    NotATransaction,
    /// The account we care about isn't referenced by this transaction. Not
    /// an error as far as the caller is concerned — just "no record" — but
    /// modeled explicitly so callers can't confuse it with a real zero-delta
    /// transfer.
    AccountNotReferenced,
}

/// Given one `getTransaction` (jsonParsed) response and the token account we
/// are tracking spend for, extract an outgoing-transfer record if this
/// transaction decreased that account's token balance. Transactions that
/// increased the balance (incoming) or didn't touch it at all are `Ok(None)`,
/// not an error — a hostile or irrelevant transaction is simply not counted,
/// it doesn't break the whole history fetch.
pub fn extract_outgoing_transfer(
    tx: &serde_json::Value,
    tracked_token_account: &str,
    now_unix: i64,
) -> Result<Option<TransferRecord>, HistoryParseError> {
    let account_keys = tx
        .get("transaction")
        .and_then(|t| t.get("message"))
        .and_then(|m| m.get("accountKeys"))
        .and_then(|k| k.as_array())
        .ok_or(HistoryParseError::NotATransaction)?;

    let account_index = account_keys.iter().position(|entry| {
        entry
            .get("pubkey")
            .and_then(|p| p.as_str())
            .is_some_and(|p| p == tracked_token_account)
    });
    let Some(account_index) = account_index else {
        return Err(HistoryParseError::AccountNotReferenced);
    };

    let meta = tx.get("meta").ok_or(HistoryParseError::NotATransaction)?;
    let pre = find_balance_for_index(meta, "preTokenBalances", account_index);
    let post = find_balance_for_index(meta, "postTokenBalances", account_index);

    // Absent pre/post for this index means the token account had no token
    // balance entry recorded (e.g. the transaction didn't touch it as a
    // token account) — treat as "no transfer", never guess an amount.
    let (Some(pre), Some(post)) = (pre, post) else {
        return Ok(None);
    };

    if pre <= post {
        // Balance did not decrease: incoming transfer or unchanged. Out of
        // scope for an *outgoing* spend record.
        return Ok(None);
    }

    let amount_atomic = pre - post;
    // A missing blockTime defaults to "now", not 0 — 0 would push the
    // record outside the 24h window and drop it from the cumulative sum,
    // under-counting real spend instead of counting it conservatively.
    let unix_timestamp = tx
        .get("blockTime")
        .and_then(|b| b.as_i64())
        .unwrap_or(now_unix);

    Ok(Some(TransferRecord {
        amount_atomic,
        unix_timestamp,
    }))
}

/// Read `meta[field][*]` looking for an entry whose `accountIndex` matches,
/// returning its `uiTokenAmount.amount` (the exact atomic-unit string) as a
/// `u64`. Malformed or missing data yields `None`, never a panic or a guess.
fn find_balance_for_index(
    meta: &serde_json::Value,
    field: &str,
    account_index: usize,
) -> Option<u64> {
    let entries = meta.get(field)?.as_array()?;
    let entry = entries
        .iter()
        .find(|e| e.get("accountIndex").and_then(|i| i.as_u64()) == Some(account_index as u64))?;
    let amount_str = entry.get("uiTokenAmount")?.get("amount")?.as_str()?;
    amount_str.parse::<u64>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn tx_with_balances(
        tracked_account: &str,
        pre_amount: &str,
        post_amount: &str,
        block_time: i64,
    ) -> serde_json::Value {
        json!({
            "blockTime": block_time,
            "transaction": {
                "message": {
                    "accountKeys": [
                        { "pubkey": "SomeOtherAccount11111111111111111111111", "signer": true, "writable": true },
                        { "pubkey": tracked_account, "signer": false, "writable": true },
                    ]
                }
            },
            "meta": {
                "preTokenBalances": [
                    { "accountIndex": 1, "uiTokenAmount": { "amount": pre_amount } }
                ],
                "postTokenBalances": [
                    { "accountIndex": 1, "uiTokenAmount": { "amount": post_amount } }
                ]
            }
        })
    }

    const TRACKED: &str = "TrackedTokenAccount1111111111111111111111";

    #[test]
    fn extracts_outgoing_transfer_amount_and_timestamp() {
        let tx = tx_with_balances(TRACKED, "10000000", "9000000", 1_700_000_000);
        let record = extract_outgoing_transfer(&tx, TRACKED, 1_700_000_000)
            .expect("should parse")
            .expect("should be Some — balance decreased");
        assert_eq!(record.amount_atomic, 1_000_000);
        assert_eq!(record.unix_timestamp, 1_700_000_000);
    }

    #[test]
    fn incoming_transfer_is_not_counted_as_outgoing() {
        let tx = tx_with_balances(TRACKED, "9000000", "10000000", 1_700_000_000);
        let record = extract_outgoing_transfer(&tx, TRACKED, 1_700_000_000).expect("should parse");
        assert!(record.is_none(), "balance increase must not count as spend");
    }

    #[test]
    fn unchanged_balance_is_not_counted() {
        let tx = tx_with_balances(TRACKED, "5000000", "5000000", 1_700_000_000);
        let record = extract_outgoing_transfer(&tx, TRACKED, 1_700_000_000).expect("should parse");
        assert!(record.is_none());
    }

    #[test]
    fn account_not_referenced_is_reported_distinctly() {
        let tx = tx_with_balances("SomeUnrelatedAccount111111111111111111111", "1", "0", 1);
        let err = extract_outgoing_transfer(&tx, TRACKED, 1).unwrap_err();
        assert_eq!(err, HistoryParseError::AccountNotReferenced);
    }

    #[test]
    fn malformed_response_fails_closed_not_a_transaction() {
        let garbage = json!({ "not": "a transaction" });
        let err = extract_outgoing_transfer(&garbage, TRACKED, 1).unwrap_err();
        assert_eq!(err, HistoryParseError::NotATransaction);
    }

    #[test]
    fn missing_block_time_falls_back_to_now_not_zero() {
        let tx = json!({
            "transaction": {
                "message": {
                    "accountKeys": [
                        { "pubkey": TRACKED, "signer": false, "writable": true },
                    ]
                }
            },
            "meta": {
                "preTokenBalances": [
                    { "accountIndex": 0, "uiTokenAmount": { "amount": "10" } }
                ],
                "postTokenBalances": [
                    { "accountIndex": 0, "uiTokenAmount": { "amount": "9" } }
                ]
            }
        });
        let record = extract_outgoing_transfer(&tx, TRACKED, 1_700_000_000)
            .expect("should parse")
            .expect("balance decreased");
        assert_eq!(
            record.unix_timestamp, 1_700_000_000,
            "a missing blockTime must count as 'now', not epoch 0 — 0 would push the \
             record out of the 24h window and silently drop it from the cumulative sum"
        );
    }

    #[test]
    fn missing_token_balance_entries_yield_none_not_a_guess() {
        let tx = json!({
            "blockTime": 1,
            "transaction": {
                "message": {
                    "accountKeys": [
                        { "pubkey": TRACKED, "signer": false, "writable": true },
                    ]
                }
            },
            "meta": {
                "preTokenBalances": [],
                "postTokenBalances": []
            }
        });
        let record = extract_outgoing_transfer(&tx, TRACKED, 1).expect("should parse");
        assert!(record.is_none());
    }

    #[test]
    fn extracts_from_a_real_devnet_transaction() {
        // Trimmed but verbatim `getTransaction` (jsonParsed) response fetched
        // live from https://api.devnet.solana.com for signature
        // 47jV74je72xtvHB7MwAXLkrqSDZBWPZouGDGyBq1xydRirMLD2oDnLZEgoDN2cvecnCxzD1gTqT9hjj69gpWuetq
        // — an SPL "Withdraw from stream" program moving 1 atomic unit
        // (0.000001) of the devnet USDC-style mint out of account index 3.
        // Only fields this parser reads are kept; everything else (compute
        // units, log messages, other balance entries, etc.) is omitted, but
        // nothing present below was altered from the real response.
        let real_tx = json!({
            "blockTime": 1784757866,
            "transaction": {
                "message": {
                    "accountKeys": [
                        { "pubkey": "wdrwhnCv4pzW8beKsbPa4S2UDZrXenjg16KJdKSpb5u", "signer": true, "source": "transaction", "writable": true },
                        { "pubkey": "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU", "signer": false, "source": "transaction", "writable": true },
                        { "pubkey": "5SEpbdjFK5FxwTvfsGMXVQTD2v4M2c5tyRTxhdsPkgDw", "signer": false, "source": "transaction", "writable": true },
                        { "pubkey": "5YGHhGV7L7gfL4aDBXrs3V6nLb7Kpkk9YFX8vg5rqGbN", "signer": false, "source": "transaction", "writable": true },
                        { "pubkey": "7XCApjU1MR7eVgyturEaVnuDQYB9KU1KMSSytDPK1iRy", "signer": false, "source": "transaction", "writable": true }
                    ]
                }
            },
            "meta": {
                "preTokenBalances": [
                    {
                        "accountIndex": 3,
                        "mint": "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
                        "owner": "5YGHhGV7L7gfL4aDBXrs3V6nLb7Kpkk9YFX8vg5rqGbN",
                        "programId": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
                        "uiTokenAmount": { "amount": "30492", "decimals": 6, "uiAmount": 0.030492, "uiAmountString": "0.030492" }
                    }
                ],
                "postTokenBalances": [
                    {
                        "accountIndex": 3,
                        "mint": "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
                        "owner": "5YGHhGV7L7gfL4aDBXrs3V6nLb7Kpkk9YFX8vg5rqGbN",
                        "programId": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
                        "uiTokenAmount": { "amount": "30491", "decimals": 6, "uiAmount": 0.030491, "uiAmountString": "0.030491" }
                    }
                ]
            }
        });

        let record = extract_outgoing_transfer(
            &real_tx,
            "5YGHhGV7L7gfL4aDBXrs3V6nLb7Kpkk9YFX8vg5rqGbN",
            1784757866,
        )
        .expect("must parse a real devnet response")
        .expect("balance genuinely decreased in this real transaction");
        assert_eq!(record.amount_atomic, 1);
        assert_eq!(record.unix_timestamp, 1784757866);
    }

    fn sig(signature: &str, block_time: i64) -> serde_json::Value {
        json!({ "signature": signature, "blockTime": block_time, "slot": 1, "err": null, "confirmationStatus": "finalized" })
    }

    #[test]
    fn select_signatures_within_window_uses_real_devnet_signature_list_shape() {
        // Verbatim getSignaturesForAddress entries fetched live from
        // https://api.devnet.solana.com for the same mint used above.
        let real_signatures = vec![
            json!({"blockTime":1784757889,"confirmationStatus":"finalized","err":null,"memo":"[36] 2107ed4b-6ebb-4373-923d-1753581ac1f1","signature":"26M9eMgEraNgHRFn4U4duxSvZGhA3AB96eENWwPmfnksBNMizUTYLi7mf86cMciHjL5JousptTuVxJ59f8SgpX8M","slot":478181027,"transactionIndex":23}),
            json!({"blockTime":1784757887,"confirmationStatus":"finalized","err":null,"memo":null,"signature":"4FLmgEnm7mjMabWotsXvFaQndvR1BDtdMBoREzrKQKK9UMpn3Vu9f4PcCg865NQrqXn8bUBCJss9Ks5o9MYhju2M","slot":478181022,"transactionIndex":2}),
            json!({"blockTime":1784757885,"confirmationStatus":"finalized","err":null,"memo":"[36] 41e28be0-0c8f-49b3-b820-eb33451cb122","signature":"3bdARJhijmfVYLtsFHydb6QL7oG1PYqtE8jhAPeGpZAvkTwMNrPU1bSofnqy6KU1BkNgsa5DN5GrjKFuuCpQUJXA","slot":478181015,"transactionIndex":22}),
            json!({"blockTime":1784757870,"confirmationStatus":"finalized","err":null,"memo":null,"signature":"4MWZUkMvsZ6Uqd32GTBtrP8moWZ79dttNNLSYm8Ftj5UWEcfYNkiiueyay4xQNxtyPiuSQAEfax7WUVPZQdH1kbC","slot":478180976,"transactionIndex":2}),
            json!({"blockTime":1784757866,"confirmationStatus":"finalized","err":null,"memo":"[10] Auto-Claim","signature":"47jV74je72xtvHB7MwAXLkrqSDZBWPZouGDGyBq1xydRirMLD2oDnLZEgoDN2cvecnCxzD1gTqT9hjj69gpWuetq","slot":478180965,"transactionIndex":4}),
        ];
        // "Now" set just after the newest entry — all 5 fall well within a
        // 24h window that starts long before any of them.
        let now = 1784757890;
        let selected = select_signatures_within_window(&real_signatures, now, 100).unwrap();
        assert_eq!(selected.len(), 5);
        assert_eq!(
            selected[0],
            "26M9eMgEraNgHRFn4U4duxSvZGhA3AB96eENWwPmfnksBNMizUTYLi7mf86cMciHjL5JousptTuVxJ59f8SgpX8M"
        );
    }

    #[test]
    fn select_signatures_within_window_skips_stale_entries_wherever_they_sit() {
        let now = 100_000i64;
        let window_start = now - CUMULATIVE_WINDOW_SECONDS;
        let signatures = vec![
            sig("newest", now - 10),
            sig("also_recent", now - 20),
            sig("exactly_at_boundary", window_start), // stale
            sig("out_of_order_but_in_window", now - 1),
        ];
        let selected = select_signatures_within_window(&signatures, now, 100).unwrap();
        assert_eq!(
            selected,
            vec!["newest", "also_recent", "out_of_order_but_in_window"]
        );
    }

    #[test]
    fn select_signatures_within_window_treats_missing_block_time_as_in_window() {
        let signatures = vec![json!({ "signature": "no_block_time_field" })];
        let selected = select_signatures_within_window(&signatures, 1_000_000, 100).unwrap();
        assert_eq!(
            selected,
            vec!["no_block_time_field"],
            "a missing blockTime must not be silently treated as 'safely old'"
        );
    }

    #[test]
    fn select_signatures_within_window_denies_when_over_the_inspection_cap() {
        let now = 1_000_000i64;
        let signatures: Vec<serde_json::Value> =
            (0..5).map(|i| sig(&format!("sig{i}"), now - i)).collect();
        let err = select_signatures_within_window(&signatures, now, 3).unwrap_err();
        assert!(
            err.contains('5'),
            "error should mention the actual in-window count: {err}"
        );
    }

    #[test]
    fn select_signatures_within_window_allows_exactly_at_the_cap() {
        let now = 1_000_000i64;
        let signatures: Vec<serde_json::Value> =
            (0..3).map(|i| sig(&format!("sig{i}"), now - i)).collect();
        assert!(select_signatures_within_window(&signatures, now, 3).is_ok());
    }
}

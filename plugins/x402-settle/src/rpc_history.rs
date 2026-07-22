//! Parses Solana RPC `getTransaction` responses (jsonParsed encoding) into
//! [`TransferRecord`]s for the cumulative spend cap in
//! [`crate::x402_settle::check_cumulative_cap`].
//!
//! This module only ever reasons about JSON already fetched by the wasm
//! shim — it makes no network calls itself, which is what keeps it
//! host-testable with representative fixtures.
//!
//! **Fixture provenance note:** the JSON shapes below are modeled on the
//! [documented Solana RPC HTTP API](https://solana.com/docs/rpc/http/gettransaction)
//! response shape, not captured from a live transaction (this environment has
//! no live RPC access). Before merge, re-verify field names and nesting
//! against at least one real `getTransaction` response for a token transfer,
//! the same way `plugins/x402-quote-check` verified its Kamino-adjacent
//! assumptions against live data where possible.

use crate::x402_settle::TransferRecord;

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
    let unix_timestamp = tx.get("blockTime").and_then(|b| b.as_i64()).unwrap_or(0);

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
        let record = extract_outgoing_transfer(&tx, TRACKED)
            .expect("should parse")
            .expect("should be Some — balance decreased");
        assert_eq!(record.amount_atomic, 1_000_000);
        assert_eq!(record.unix_timestamp, 1_700_000_000);
    }

    #[test]
    fn incoming_transfer_is_not_counted_as_outgoing() {
        let tx = tx_with_balances(TRACKED, "9000000", "10000000", 1_700_000_000);
        let record = extract_outgoing_transfer(&tx, TRACKED).expect("should parse");
        assert!(record.is_none(), "balance increase must not count as spend");
    }

    #[test]
    fn unchanged_balance_is_not_counted() {
        let tx = tx_with_balances(TRACKED, "5000000", "5000000", 1_700_000_000);
        let record = extract_outgoing_transfer(&tx, TRACKED).expect("should parse");
        assert!(record.is_none());
    }

    #[test]
    fn account_not_referenced_is_reported_distinctly() {
        let tx = tx_with_balances("SomeUnrelatedAccount111111111111111111111", "1", "0", 1);
        let err = extract_outgoing_transfer(&tx, TRACKED).unwrap_err();
        assert_eq!(err, HistoryParseError::AccountNotReferenced);
    }

    #[test]
    fn malformed_response_fails_closed_not_a_transaction() {
        let garbage = json!({ "not": "a transaction" });
        let err = extract_outgoing_transfer(&garbage, TRACKED).unwrap_err();
        assert_eq!(err, HistoryParseError::NotATransaction);
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
        let record = extract_outgoing_transfer(&tx, TRACKED).expect("should parse");
        assert!(record.is_none());
    }
}

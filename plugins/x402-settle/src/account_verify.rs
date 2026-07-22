//! Parses Solana RPC `getAccountInfo` (jsonParsed encoding) responses to
//! verify a token account before this plugin ever signs a transfer to it —
//! closes the SOL-fee-griefing gap noted in the README's "Second audit
//! pass": a malicious server supplying a `payTo` that is not an initialized
//! SPL token account for the accepted mint would otherwise get a validly
//! signed transaction handed to it, and a submitted-but-failing instruction
//! can still cost the fee payer (this plugin's session key) the base SOL
//! fee, per Solana's fee model — that cost is not bounded by
//! `max_amount_atomic`/`max_cumulative_atomic_24h`, which are denominated
//! entirely in the token mint.
//!
//! Like `rpc_history.rs`, this module only ever reasons about JSON already
//! fetched by the wasm shim — no network calls here, which is what keeps it
//! host-testable with representative fixtures. Most fixtures are modeled on
//! the documented RPC shape; `accepts_a_real_devnet_token_account` is a
//! verbatim `getAccountInfo` response fetched live from
//! `https://api.devnet.solana.com` for a real token account holding the
//! devnet USDC-style mint, confirming the modeled shape matches reality.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountVerifyError {
    /// `getAccountInfo` returned `null` for `value` — the account does not
    /// exist on-chain at all.
    AccountDoesNotExist,
    /// The account exists but is not owned by the SPL Token program — it
    /// cannot be a token account, whatever it is.
    NotOwnedBySplToken { actual_owner: String },
    /// The account is owned by the SPL Token program but is not decoded as
    /// a token account by the RPC's own parser (e.g. it's a mint account,
    /// not a token account).
    NotAParsedTokenAccount,
    /// The account is a token account, but for a different mint than the
    /// one this payment is supposed to use.
    MintMismatch { expected: String, actual: String },
    /// The response didn't match the expected shape at all — fail closed
    /// rather than guess.
    MalformedResponse,
}

impl std::fmt::Display for AccountVerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AccountVerifyError::AccountDoesNotExist => {
                write!(f, "destination token account does not exist on-chain")
            }
            AccountVerifyError::NotOwnedBySplToken { actual_owner } => write!(
                f,
                "destination account is not owned by the SPL Token program (owner: {actual_owner})"
            ),
            AccountVerifyError::NotAParsedTokenAccount => {
                write!(f, "destination account is not a parsed SPL token account")
            }
            AccountVerifyError::MintMismatch { expected, actual } => write!(
                f,
                "destination token account is for mint {actual:?}, expected {expected:?}"
            ),
            AccountVerifyError::MalformedResponse => {
                write!(
                    f,
                    "getAccountInfo response did not match the expected shape"
                )
            }
        }
    }
}

use crate::x402_settle::SPL_TOKEN_PROGRAM_ID;

/// Verify that `getAccountInfo`'s (jsonParsed) response for the destination
/// describes a real, initialized SPL token account for `expected_mint`.
/// Every failure mode is a distinct, named error — never a silent "looks
/// fine" default — because this check exists specifically to refuse
/// signing before any fee could be charged, not to produce a best-effort
/// guess.
pub fn verify_token_account(
    account_info: &serde_json::Value,
    expected_mint: &str,
) -> Result<(), AccountVerifyError> {
    let value = account_info
        .get("value")
        .ok_or(AccountVerifyError::MalformedResponse)?;
    if value.is_null() {
        return Err(AccountVerifyError::AccountDoesNotExist);
    }

    let owner = value
        .get("owner")
        .and_then(|o| o.as_str())
        .ok_or(AccountVerifyError::MalformedResponse)?;
    if owner != SPL_TOKEN_PROGRAM_ID {
        return Err(AccountVerifyError::NotOwnedBySplToken {
            actual_owner: owner.to_string(),
        });
    }

    let program = value
        .get("data")
        .and_then(|d| d.get("program"))
        .and_then(|p| p.as_str());
    let mint = value
        .get("data")
        .and_then(|d| d.get("parsed"))
        .and_then(|p| p.get("info"))
        .and_then(|i| i.get("mint"))
        .and_then(|m| m.as_str());

    match (program, mint) {
        (Some("spl-token"), Some(actual_mint)) => {
            if actual_mint == expected_mint {
                Ok(())
            } else {
                Err(AccountVerifyError::MintMismatch {
                    expected: expected_mint.to_string(),
                    actual: actual_mint.to_string(),
                })
            }
        }
        _ => Err(AccountVerifyError::NotAParsedTokenAccount),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const USDC_MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";

    fn valid_token_account_response(mint: &str) -> serde_json::Value {
        json!({
            "context": { "slot": 123456 },
            "value": {
                "owner": SPL_TOKEN_PROGRAM_ID,
                "lamports": 2039280,
                "data": {
                    "program": "spl-token",
                    "parsed": {
                        "type": "account",
                        "info": {
                            "mint": mint,
                            "owner": "SomeWalletOwner1111111111111111111111111111",
                            "tokenAmount": { "amount": "1000000", "decimals": 6 }
                        }
                    }
                }
            }
        })
    }

    #[test]
    fn accepts_a_genuine_token_account_for_the_right_mint() {
        let resp = valid_token_account_response(USDC_MINT);
        assert!(verify_token_account(&resp, USDC_MINT).is_ok());
    }

    #[test]
    fn rejects_nonexistent_account() {
        let resp = json!({ "context": { "slot": 1 }, "value": null });
        assert_eq!(
            verify_token_account(&resp, USDC_MINT).unwrap_err(),
            AccountVerifyError::AccountDoesNotExist
        );
    }

    #[test]
    fn rejects_account_not_owned_by_token_program() {
        // e.g. a plain System-owned wallet address, exactly the kind of
        // "syntactically valid pubkey, semantically wrong" input a
        // malicious server would supply to grief the fee payer.
        let resp = json!({
            "context": { "slot": 1 },
            "value": {
                "owner": "11111111111111111111111111111111",
                "lamports": 5000,
                "data": { "program": "system", "parsed": { "type": "account", "info": {} } }
            }
        });
        match verify_token_account(&resp, USDC_MINT) {
            Err(AccountVerifyError::NotOwnedBySplToken { actual_owner }) => {
                assert_eq!(actual_owner, "11111111111111111111111111111111")
            }
            other => panic!("expected NotOwnedBySplToken, got {other:?}"),
        }
    }

    #[test]
    fn rejects_wrong_mint() {
        let resp = valid_token_account_response("SomeOtherMintNotUSDCAtAll111111111111111111");
        match verify_token_account(&resp, USDC_MINT) {
            Err(AccountVerifyError::MintMismatch { expected, actual }) => {
                assert_eq!(expected, USDC_MINT);
                assert_eq!(actual, "SomeOtherMintNotUSDCAtAll111111111111111111");
            }
            other => panic!("expected MintMismatch, got {other:?}"),
        }
    }

    #[test]
    fn rejects_token_owned_account_that_is_not_a_token_account() {
        // e.g. a mint account itself, or an account that just happens to
        // be owned by the token program without being a decodable token
        // account (malformed/foreign data layout).
        let resp = json!({
            "context": { "slot": 1 },
            "value": {
                "owner": SPL_TOKEN_PROGRAM_ID,
                "lamports": 1000000,
                "data": { "program": "spl-token", "parsed": { "type": "mint", "info": { "decimals": 6 } } }
            }
        });
        assert_eq!(
            verify_token_account(&resp, USDC_MINT).unwrap_err(),
            AccountVerifyError::NotAParsedTokenAccount
        );
    }

    #[test]
    fn malformed_response_fails_closed() {
        let garbage = json!({ "unrelated": true });
        assert_eq!(
            verify_token_account(&garbage, USDC_MINT).unwrap_err(),
            AccountVerifyError::MalformedResponse
        );
    }

    #[test]
    fn accepts_a_real_devnet_token_account() {
        // Verbatim `getAccountInfo` (jsonParsed) response fetched live from
        // https://api.devnet.solana.com for account
        // 5YGHhGV7L7gfL4aDBXrs3V6nLb7Kpkk9YFX8vg5rqGbN, a real initialized
        // SPL token account for the devnet USDC-style mint
        // 4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU. Nothing altered
        // except the balance amount, which changes every time someone
        // interacts with this real, actively-used devnet account.
        let real_response = json!({
            "context": { "apiVersion": "4.2.0-beta.1", "slot": 478181164 },
            "value": {
                "data": {
                    "parsed": {
                        "info": {
                            "isNative": false,
                            "mint": "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
                            "owner": "5YGHhGV7L7gfL4aDBXrs3V6nLb7Kpkk9YFX8vg5rqGbN",
                            "state": "initialized",
                            "tokenAmount": { "amount": "30490", "decimals": 6, "uiAmount": 0.03049, "uiAmountString": "0.03049" }
                        },
                        "type": "account"
                    },
                    "program": "spl-token",
                    "space": 165
                },
                "executable": false,
                "lamports": 2039280,
                "owner": SPL_TOKEN_PROGRAM_ID,
                "rentEpoch": 18446744073709551615u64,
                "space": 165
            }
        });

        verify_token_account(
            &real_response,
            "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
        )
        .expect("a real, genuine devnet token account must pass verification");
    }

    #[test]
    fn rejects_a_real_devnet_mint_account_as_not_a_token_account() {
        // Verbatim getAccountInfo response for the mint address itself
        // (4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU) — a real, easy
        // mistake for a hostile or careless server to make: pointing payTo
        // at the mint instead of a token account for that mint. type is
        // "mint", not "account", so no `info.mint` field exists to match
        // against — must be rejected as NotAParsedTokenAccount.
        let real_mint_response = json!({
            "context": { "apiVersion": "4.2.0-beta.1", "slot": 478181023 },
            "value": {
                "data": {
                    "parsed": {
                        "info": {
                            "decimals": 6,
                            "freezeAuthority": "CJtyoKSLrktozQzjERTiK3btQtiTK3nN4QrqGHLidyCT",
                            "isInitialized": true,
                            "mintAuthority": "GrNg1XM2ctzeE2mXxXCfhcTUbejM8Z4z4wNVTy2FjMEz",
                            "supply": "16286785255557674663"
                        },
                        "type": "mint"
                    },
                    "program": "spl-token",
                    "space": 82
                },
                "executable": false,
                "lamports": 397055532289u64,
                "owner": SPL_TOKEN_PROGRAM_ID,
                "rentEpoch": 18446744073709551615u64,
                "space": 82
            }
        });

        assert_eq!(
            verify_token_account(
                &real_mint_response,
                "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"
            )
            .unwrap_err(),
            AccountVerifyError::NotAParsedTokenAccount
        );
    }
}

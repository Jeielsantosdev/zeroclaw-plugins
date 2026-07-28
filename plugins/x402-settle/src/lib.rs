//! A ZeroClaw WIT tool plugin: `x402_settle`.
//!
//! Pays for an x402-gated resource under a scoped session key: fetches the
//! resource, validates the server's payment requirements against operator
//! policy, enforces a cumulative 24h spend cap recomputed from real on-chain
//! transfer history, builds and signs an SPL Token Transfer, and retries the
//! resource request with the `PAYMENT-SIGNATURE` proof. See [`x402_settle`] for the
//! tested policy/signing core, [`transaction`] for manual Solana transaction
//! serialization, [`rpc_history`] for turning RPC responses into spend
//! records, and [`account_verify`] for the pre-signing destination check.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod account_verify;
pub mod associated_token;
pub mod rpc_history;
pub mod transaction;
pub mod x402_settle;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;
    use std::time::Duration;

    use zeroize::Zeroize;

    use crate::account_verify::{extract_mint_decimals, verify_token_account};
    use crate::associated_token::derive_associated_token_address;
    use crate::rpc_history::{extract_outgoing_transfer, select_signatures_within_window};
    use crate::transaction::{build_transfer_checked_transaction, to_base64};
    use crate::x402_settle::{
        build_approval_token, check_cumulative_cap, decode_session_key_seed,
        parse_requirements_from_response, session_key_pubkey, validate_requirements,
        verify_approval_token, CapVerdict, PaymentRequirement, SettlePolicyConfig, TransferRecord,
        Verdict, APPROVAL_WINDOW_SLOTS, DEFAULT_MAX_TIMEOUT_SECONDS, SPL_TOKEN_PROGRAM_ID,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct X402Settle;

    const PLUGIN_NAME: &str = "x402-settle";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "x402_settle";
    const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
    /// Cap on the initial and final HTTP fetch of the x402 resource itself.
    const MAX_BODY_BYTES: usize = 32 * 1024;
    /// Cap on any single RPC response body. Larger than `MAX_BODY_BYTES`
    /// deliberately: `getSignaturesForAddress` at `SIGNATURES_FETCH_LIMIT`
    /// runs ~233 bytes/entry in practice (measured against real devnet
    /// data), so 200 entries is ~47 KiB — the original shared 32 KiB cap
    /// would have rejected that response outright, silently defeating the
    /// point of raising the signature limit below.
    const MAX_RPC_BODY_BYTES: usize = 96 * 1024;
    /// How many signatures `getSignaturesForAddress` fetches per call.
    /// Solana's hard ceiling for this method is 1000; 200 is chosen instead
    /// because responses at that size stay comfortably under
    /// `MAX_RPC_BODY_BYTES` (~47 KiB observed vs. a 96 KiB cap) while still
    /// covering a genuinely active session key's realistic daily volume.
    /// This bounds the size of *one* RPC call, not how many of those
    /// signatures actually get inspected — see `MAX_HISTORY_TRANSACTIONS_TO_FETCH`
    /// and `fetch_recent_transfer_history`'s doc comment for the real fix to
    /// the under-counting risk this constant alone doesn't solve.
    const SIGNATURES_FETCH_LIMIT: usize = 200;
    /// Hard cap on how many `getTransaction` calls one `execute()` will make
    /// to reconstruct 24h of spend history. If more than this many
    /// signatures fall inside the 24h window, this plugin refuses to pay
    /// rather than silently inspect only a subset of them — under-counting
    /// real spend here is exactly the fail-open risk `check_cumulative_cap`
    /// exists to prevent, so an inability to fully verify spend must itself
    /// deny, not degrade to "probably fine."
    const MAX_HISTORY_TRANSACTIONS_TO_FETCH: usize = 100;

    #[derive(serde::Deserialize)]
    struct ExecuteArgs {
        resource_url: String,
        /// Two-phase approval gate: `"propose"` (default when omitted) never
        /// signs or submits anything — it validates policy, checks the
        /// cumulative cap, verifies the destination, and returns an
        /// `approval_token`. `"confirm"` requires that exact token (still
        /// fresh) and is the only path that ever signs and submits. See the
        /// README's "Approval gate" section.
        #[serde(default)]
        action: Option<String>,
        /// Required when `action = "confirm"`: the token a prior `"propose"`
        /// call returned for this exact payment.
        #[serde(default)]
        approval_token: Option<String>,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

    impl PluginInfo for X402Settle {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for X402Settle {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Pay for an x402-gated resource, via a two-phase approval gate. Call with no \
             `action` (or action=\"propose\") first: fetches the resource, validates the \
             server's HTTP 402 payment requirements against operator policy (network, mint, \
             amount, recipient, timeout), enforces a cumulative 24h spend cap recomputed from \
             real on-chain transfer history, verifies the destination — and returns an \
             `approval_token`, WITHOUT signing or submitting anything. Only a second call with \
             action=\"confirm\" and that exact (still-fresh) approval_token builds and signs an \
             SPL token transfer with a scoped session key — never the operator's main wallet — \
             and retries with proof of payment."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "resource_url": {
                        "type": "string",
                        "description": "HTTPS URL of the x402-gated resource to pay for."
                    },
                    "action": {
                        "type": "string",
                        "enum": ["propose", "confirm"],
                        "description": "\"propose\" (default): validate everything and return an approval_token, never signs or submits. \"confirm\": actually pay — requires the approval_token a prior propose call returned."
                    },
                    "approval_token": {
                        "type": "string",
                        "description": "Required when action=\"confirm\": the exact approval_token a prior propose call for this same payment returned."
                    }
                },
                "required": ["resource_url"],
                "additionalProperties": false
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let mut parsed: ExecuteArgs = match serde_json::from_str(&args) {
                Ok(a) => a,
                Err(e) => {
                    emit(
                        PluginAction::Fail,
                        PluginOutcome::Failure,
                        "invalid arguments",
                    );
                    return Ok(deny(format!("invalid arguments: {e}")));
                }
            };

            if !parsed.resource_url.starts_with("https://") {
                emit(
                    PluginAction::Fail,
                    PluginOutcome::Failure,
                    "non-https resource_url",
                );
                return Ok(deny("resource_url must be an https:// URL".to_string()));
            }

            // Approval gate: "propose" (the default) validates everything
            // below and returns an approval_token without ever touching the
            // session key or signing anything. Only "confirm", with that
            // exact token, reaches the signing path further down. Checked
            // here, before any network I/O, so a malformed action/token
            // fails fast instead of spending RPC calls first.
            let action = parsed.action.as_deref().unwrap_or("propose");
            if action != "propose" && action != "confirm" {
                emit(PluginAction::Fail, PluginOutcome::Failure, "invalid action");
                return Ok(deny(format!(
                    "action must be \"propose\" or \"confirm\", got {action:?}"
                )));
            }
            if action == "confirm" && parsed.approval_token.as_deref().unwrap_or("").is_empty() {
                emit(
                    PluginAction::Fail,
                    PluginOutcome::Failure,
                    "confirm without approval_token",
                );
                return Ok(deny(
                    "approval_token is required when action=\"confirm\" — call with \
                     action=\"propose\" first to get one"
                        .to_string(),
                ));
            }

            let cfg = SettlePolicyConfig::from_section(&parsed.config);

            let Some(rpc_url) = cfg.rpc_url.clone() else {
                emit(
                    PluginAction::Fail,
                    PluginOutcome::Failure,
                    "no rpc_url configured",
                );
                return Ok(deny(
                    "rpc_url must be configured — there is no safe default RPC endpoint"
                        .to_string(),
                ));
            };
            let Some(source_token_account) = cfg.session_token_account.clone() else {
                emit(
                    PluginAction::Fail,
                    PluginOutcome::Failure,
                    "no session_token_account configured",
                );
                return Ok(deny(
                    "session_token_account must be configured (see README limitations)".to_string(),
                ));
            };
            // Only check that a session_key is *configured* here — it is not
            // decoded (and never touches the signing path) unless and until
            // action="confirm" passes its approval-token check below. A
            // "propose" call never has any reason to touch the secret
            // material at all.
            if !parsed.config.contains_key("session_key") {
                emit(
                    PluginAction::Fail,
                    PluginOutcome::Failure,
                    "no session_key configured",
                );
                return Ok(deny("session_key must be configured".to_string()));
            }

            // Step 1: fetch the resource, expect a 402 challenge.
            let first_resp = match http_get(&parsed.resource_url, None) {
                Ok(r) => r,
                Err(e) => {
                    emit(
                        PluginAction::Fail,
                        PluginOutcome::Failure,
                        "initial request failed",
                    );
                    return Ok(deny(e));
                }
            };
            if first_resp.status != 402 {
                emit(
                    PluginAction::Complete,
                    PluginOutcome::Success,
                    "no payment required",
                );
                return Ok(ToolResult {
                    success: true,
                    output: format!(
                        "no payment required right now (HTTP {}) — nothing paid",
                        first_resp.status
                    ),
                    error: None,
                });
            }
            // Real x402 servers put the payload in the base64
            // `PAYMENT-REQUIRED` header, not the body (confirmed against
            // live Otto AI and Syra deployments, 2026-07-23) — the body is
            // only a fallback here, so a non-UTF-8 body must not block a
            // valid header from being read. Lossy conversion is fine: an
            // invalid-UTF-8 body would fail JSON parsing anyway, and the
            // header path is tried first regardless.
            let body_text = String::from_utf8_lossy(&first_resp.body).into_owned();
            let req = match parse_requirements_from_response(
                first_resp.payment_required_header.as_deref(),
                &body_text,
            ) {
                Ok(r) => r,
                Err(e) => {
                    emit(
                        PluginAction::Fail,
                        PluginOutcome::Failure,
                        "unrecognized 402 shape",
                    );
                    return Ok(deny(format!("could not parse payment requirements: {e}")));
                }
            };

            // Step 2: policy validation — every field the server could lie about.
            if let Verdict::NoGo { reasons } = validate_requirements(&req, &cfg) {
                emit(
                    PluginAction::Fail,
                    PluginOutcome::Failure,
                    "requirements rejected by policy",
                );
                return Ok(deny(format!(
                    "payment requirements rejected by policy: {}",
                    reasons.join("; ")
                )));
            }

            // Step 3: cumulative cap, recomputed from real on-chain history —
            // never an in-memory counter (see check_cumulative_cap docs).
            // Read the current slot once and reuse it both for "now" and as
            // the minContextSlot floor for the history fetch immediately
            // below, so a lagging RPC node fails closed instead of silently
            // serving a stale (under-counted) history.
            let current_slot = match rpc_get_slot(&rpc_url) {
                Ok(s) => s,
                Err(e) => {
                    emit(
                        PluginAction::Fail,
                        PluginOutcome::Failure,
                        "slot fetch failed",
                    );
                    return Ok(deny(format!(
                        "could not read current slot, refusing to pay: {e}"
                    )));
                }
            };
            let now_unix = match rpc_get_block_time(&rpc_url, current_slot) {
                Ok(t) => t,
                Err(e) => {
                    emit(
                        PluginAction::Fail,
                        PluginOutcome::Failure,
                        "clock fetch failed",
                    );
                    return Ok(deny(format!(
                        "could not determine current time, refusing to pay: {e}"
                    )));
                }
            };
            let history = match fetch_recent_transfer_history(
                &rpc_url,
                &source_token_account,
                current_slot,
                now_unix,
            ) {
                Ok(h) => h,
                Err(e) => {
                    emit(
                        PluginAction::Fail,
                        PluginOutcome::Failure,
                        "history fetch failed",
                    );
                    return Ok(deny(format!(
                        "could not verify cumulative spend history, refusing to pay: {e}"
                    )));
                }
            };
            match check_cumulative_cap(
                &history,
                req.amount_atomic,
                cfg.max_cumulative_atomic_24h,
                now_unix,
            ) {
                CapVerdict::Deny { reason } => {
                    emit(
                        PluginAction::Fail,
                        PluginOutcome::Failure,
                        "cumulative cap exceeded",
                    );
                    return Ok(deny(reason));
                }
                CapVerdict::Allow { .. } => {}
            }

            // Blockhash freshness only matters for a call that will actually
            // submit — never fetched on the `propose` path, since it would
            // just go stale waiting for a human to approve.
            let source_bytes = match decode_pubkey(&source_token_account) {
                Ok(b) => b,
                Err(e) => {
                    emit(
                        PluginAction::Fail,
                        PluginOutcome::Failure,
                        "malformed session_token_account",
                    );
                    return Ok(deny(e));
                }
            };
            let payto_bytes = match decode_pubkey(&req.pay_to) {
                Ok(b) => b,
                Err(e) => {
                    emit(
                        PluginAction::Fail,
                        PluginOutcome::Failure,
                        "malformed payTo",
                    );
                    return Ok(deny(e));
                }
            };

            // SPL_TOKEN_PROGRAM_ID is a fixed, compile-time-known constant, so
            // this can never fail in practice — but fail closed via the
            // normal deny() path rather than a panic, on principle: no
            // production code path in this component ever panics, even one
            // that looks provably unreachable today.
            let token_program_bytes = match decode_pubkey(SPL_TOKEN_PROGRAM_ID) {
                Ok(b) => b,
                Err(e) => {
                    emit(
                        PluginAction::Fail,
                        PluginOutcome::Failure,
                        "internal: SPL_TOKEN_PROGRAM_ID constant failed to decode",
                    );
                    return Ok(deny(e));
                }
            };
            let mint_bytes = match decode_pubkey(&req.asset_mint) {
                Ok(b) => b,
                Err(e) => {
                    emit(
                        PluginAction::Fail,
                        PluginOutcome::Failure,
                        "malformed asset_mint",
                    );
                    return Ok(deny(e));
                }
            };

            // Step 3.5: resolve and verify the real destination token
            // account before ever signing. Closes a SOL-fee-griefing gap
            // found during the second audit pass: a server-supplied payTo
            // that passes the base58/length shape check but isn't actually
            // an initialized SPL token account would still let us sign a
            // transaction whose instruction is doomed to fail on-chain —
            // and Solana can still charge the fee payer (this session key)
            // the base SOL fee for a submitted-but-failing transaction, a
            // cost the token-denominated spend caps don't track at all.
            //
            // Real x402 servers (confirmed 2026-07-27 against two
            // independent live deployments — Otto AI mainnet, PayAI Echo
            // Merchant devnet) publish `payTo` as the recipient's *wallet*
            // address, not a token account — the payer is expected to
            // derive the Associated Token Account (ATA) for (wallet, mint)
            // itself. payTo-as-token-account is tried first (cheapest, no
            // derivation, no second RPC round trip); a server that instead
            // already publishes a token account directly keeps working
            // exactly as before. Only if that fails is payTo treated as a
            // wallet and its ATA derived and checked — so both real-world
            // conventions work without knowing in advance which one a
            // given server uses.
            let account_info = match rpc_call(
                &rpc_url,
                "getAccountInfo",
                serde_json::json!([req.pay_to, {"encoding": "jsonParsed"}]),
            ) {
                Ok(v) => v,
                Err(e) => {
                    emit(
                        PluginAction::Fail,
                        PluginOutcome::Failure,
                        "destination account lookup failed",
                    );
                    return Ok(deny(format!(
                        "could not verify destination token account, refusing to sign: {e}"
                    )));
                }
            };

            let destination_bytes = if verify_token_account(&account_info, &req.asset_mint).is_ok()
            {
                payto_bytes
            } else {
                let derived_ata = match derive_associated_token_address(
                    &payto_bytes,
                    &token_program_bytes,
                    &mint_bytes,
                ) {
                    Ok(a) => a,
                    Err(e) => {
                        emit(
                            PluginAction::Fail,
                            PluginOutcome::Failure,
                            "internal: ATA derivation failed",
                        );
                        return Ok(deny(e.to_string()));
                    }
                };
                let derived_ata_b58 = bs58::encode(derived_ata).into_string();
                let derived_account_info = match rpc_call(
                    &rpc_url,
                    "getAccountInfo",
                    serde_json::json!([derived_ata_b58, {"encoding": "jsonParsed"}]),
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        emit(
                            PluginAction::Fail,
                            PluginOutcome::Failure,
                            "derived ATA lookup failed",
                        );
                        return Ok(deny(format!(
                            "could not verify derived associated token account, refusing to sign: {e}"
                        )));
                    }
                };
                if let Err(e) = verify_token_account(&derived_account_info, &req.asset_mint) {
                    emit(
                        PluginAction::Fail,
                        PluginOutcome::Failure,
                        "payTo is neither a valid token account nor a wallet with an initialized ATA",
                    );
                    return Ok(deny(format!(
                        "refusing to sign: payTo {:?} is not itself a valid token account for the \
                         accepted mint, and its derived associated token account {derived_ata_b58} \
                         also failed verification: {e}",
                        req.pay_to
                    )));
                }
                derived_ata
            };

            // Step 3.6: resolve the two extra values the real x402 v2
            // "exact" Solana scheme needs that its own response never
            // carries: the mint's `decimals` (required for `TransferChecked`,
            // which validates it on-chain — confirmed absent from every
            // real 402 response captured this session) and, if the server
            // sponsors the transaction fee, the address that will pay it
            // (`extra.feePayer` — confirmed present on live Otto AI and
            // PayAI responses; `EDITAL.md`: "the facilitator co-signs as
            // fee payer, so the agent needs no SOL for gas"). Both are
            // resolved here, before the approval gate, so a malformed mint
            // or feePayer surfaces on "propose" rather than deep inside
            // "confirm".
            let mint_account_info = match rpc_call(
                &rpc_url,
                "getAccountInfo",
                serde_json::json!([req.asset_mint, {"encoding": "jsonParsed"}]),
            ) {
                Ok(v) => v,
                Err(e) => {
                    emit(
                        PluginAction::Fail,
                        PluginOutcome::Failure,
                        "mint account lookup failed",
                    );
                    return Ok(deny(format!(
                        "could not read the asset mint's decimals, refusing to sign: {e}"
                    )));
                }
            };
            let mint_decimals = match extract_mint_decimals(&mint_account_info) {
                Ok(d) => d,
                Err(e) => {
                    emit(
                        PluginAction::Fail,
                        PluginOutcome::Failure,
                        "asset_mint is not a parsed SPL mint account",
                    );
                    return Ok(deny(format!(
                        "refusing to sign: could not read decimals for asset_mint {:?}: {e}",
                        req.asset_mint
                    )));
                }
            };
            let server_fee_payer_bytes = match req.fee_payer.as_deref() {
                Some(fp) => match decode_pubkey(fp) {
                    Ok(b) => Some(b),
                    Err(e) => {
                        emit(
                            PluginAction::Fail,
                            PluginOutcome::Failure,
                            "malformed extra.feePayer",
                        );
                        return Ok(deny(format!(
                            "refusing to sign: server's extra.feePayer is malformed: {e}"
                        )));
                    }
                },
                None => None,
            };

            // Approval gate, part 2: everything above (policy, cumulative
            // cap, destination verification) has now run against live data.
            // "propose" stops here — no signing, no submission, nothing
            // irreversible — and hands back a token that binds this exact
            // payment to a short expiry window.
            if action == "propose" {
                let expires_at_slot = current_slot + APPROVAL_WINDOW_SLOTS;
                let token = build_approval_token(&req, &source_token_account, expires_at_slot);
                emit(
                    PluginAction::Complete,
                    PluginOutcome::Success,
                    "proposed, awaiting confirmation",
                );
                return Ok(ToolResult {
                    success: true,
                    output: format!(
                        "PROPOSED, NOT YET PAID: {} atomic units of {} to {} on {}. Nothing has \
                         been signed or submitted. To actually pay, call this tool again with \
                         action=\"confirm\" and approval_token=\"{token}\" before slot \
                         {expires_at_slot} (roughly the next 1-2 minutes) — after that this token \
                         expires and a fresh \"propose\" call is required.",
                        req.amount_atomic,
                        req.asset_mint,
                        req.pay_to,
                        req.network_label(),
                    ),
                    error: None,
                });
            }

            // action == "confirm" from here on: the approval_token must
            // match the payment above and still be within its expiry
            // window, checked against the same freshly-read current_slot
            // used for the cumulative cap above — never a cached slot.
            let approval_token = parsed.approval_token.as_deref().unwrap_or("");
            if let Err(e) =
                verify_approval_token(approval_token, &req, &source_token_account, current_slot)
            {
                emit(
                    PluginAction::Fail,
                    PluginOutcome::Failure,
                    "approval token rejected",
                );
                return Ok(deny(e.to_string()));
            }

            // Only now, with a valid, fresh, matching approval_token in
            // hand, does this call ever touch the session key.
            // .remove() takes ownership out of the map instead of cloning —
            // cloning would leave an unzeroized copy sitting in
            // parsed.config until execute() returns.
            let Some(mut session_key_raw) = parsed.config.remove("session_key") else {
                emit(
                    PluginAction::Fail,
                    PluginOutcome::Failure,
                    "no session_key configured",
                );
                return Ok(deny("session_key must be configured".to_string()));
            };
            let decoded_seed = decode_session_key_seed(&session_key_raw);
            // The config String has served its purpose the moment decoding is
            // attempted, whether it succeeded or not — scrub it here rather
            // than let it drop normally at the end of scope. Found during a
            // zeroize audit: this was previously left for ordinary Drop.
            session_key_raw.zeroize();
            let seed = match decoded_seed {
                Ok(s) => zeroize::Zeroizing::new(s),
                Err(e) => {
                    emit(
                        PluginAction::Fail,
                        PluginOutcome::Failure,
                        "malformed session_key",
                    );
                    return Ok(deny(format!("malformed session_key: {e}")));
                }
            };
            // `seed` is `Zeroizing<[u8; 32]>` from here on: it derefs to
            // `[u8; 32]` everywhere it's used below, and is scrubbed on drop
            // no matter which of `execute`'s remaining early-return paths
            // fires after this point — not just the success path.
            let authority_pubkey = session_key_pubkey(&seed);
            // Self-funded fallback when the server sponsors no fee payer:
            // see transaction.rs's module docs for why this is the same
            // code path as the sponsored case, not a separate branch.
            let fee_payer_pubkey = server_fee_payer_bytes.unwrap_or(authority_pubkey);

            // Only fetched now, on the confirm path that will actually
            // submit — a blockhash fetched during `propose` would just sit
            // stale while a human reads and approves the request.
            let recent_blockhash = match rpc_get_latest_blockhash(&rpc_url) {
                Ok(b) => b,
                Err(e) => {
                    emit(
                        PluginAction::Fail,
                        PluginOutcome::Failure,
                        "blockhash fetch failed",
                    );
                    return Ok(deny(e));
                }
            };

            let tx_bytes = match build_transfer_checked_transaction(
                &seed,
                authority_pubkey,
                fee_payer_pubkey,
                source_bytes,
                destination_bytes,
                mint_bytes,
                token_program_bytes,
                req.amount_atomic,
                mint_decimals,
                recent_blockhash,
            ) {
                Ok(b) => b,
                Err(e) => {
                    emit(
                        PluginAction::Fail,
                        PluginOutcome::Failure,
                        "internal: transaction build failed",
                    );
                    return Ok(deny(e));
                }
            };
            let payment_header = build_payment_signature_header(&tx_bytes, &req);

            // Step 5: retry the resource with proof of payment.
            let final_resp = match http_get(&parsed.resource_url, Some(&payment_header)) {
                Ok(r) => r,
                Err(e) => {
                    emit(
                        PluginAction::Fail,
                        PluginOutcome::Failure,
                        "payment retry request failed",
                    );
                    return Ok(deny(e));
                }
            };

            if (200..300).contains(&final_resp.status) {
                emit(
                    PluginAction::Complete,
                    PluginOutcome::Success,
                    "payment settled",
                );
                Ok(ToolResult {
                    success: true,
                    output: format!(
                        "paid {} atomic units of {} to {} — resource returned HTTP {}",
                        req.amount_atomic, req.asset_mint, req.pay_to, final_resp.status
                    ),
                    error: None,
                })
            } else {
                emit(
                    PluginAction::Fail,
                    PluginOutcome::Failure,
                    "server rejected payment proof",
                );
                Ok(deny(format!(
                    "transaction was signed and submitted but the server rejected it: HTTP {}",
                    final_resp.status
                )))
            }
        }
    }

    // -- HTTP / RPC plumbing -------------------------------------------------

    struct HttpResponse {
        status: u16,
        body: Vec<u8>,
        /// The base64-encoded `PAYMENT-REQUIRED` response header, if present
        /// — real x402 servers (confirmed against live Otto AI and Syra
        /// deployments, 2026-07-23) carry payment requirements here, not in
        /// the body. See `x402_settle::parse_requirements_from_response`.
        payment_required_header: Option<String>,
    }

    /// `payment_header`, when present, is sent as `PAYMENT-SIGNATURE` — the
    /// x402 v2 header name (confirmed against `@payai/x402`'s client:
    /// `encodePaymentSignatureHeader` sends `PAYMENT-SIGNATURE` for
    /// `x402Version: 2` and only falls back to the legacy `X-Payment` name
    /// for `x402Version: 1`, which this plugin does not build). Kept as a
    /// single named optional parameter rather than a generic header list:
    /// waki's `.header()` requires the header *name* to satisfy
    /// `IntoHeaderName`, which for `&str` is only implemented for
    /// `&'static str` — a borrowed slice of `(&str, &str)` tuples loses that
    /// staticness and fails to compile. Every header this component ever
    /// sends is a compile-time-known literal name, so this is not a real
    /// limitation, just the shape waki's API wants.
    fn http_get(url: &str, payment_header: Option<&str>) -> Result<HttpResponse, String> {
        let mut req = waki::Client::new()
            .get(url)
            .connect_timeout(CONNECT_TIMEOUT);
        if let Some(value) = payment_header {
            req = req.header("PAYMENT-SIGNATURE", value);
        }
        let resp = req
            .send()
            .map_err(|e| format!("request to {url} failed: {e}"))?;
        let status = resp.status_code();
        // `header()` borrows, so it must run before `body()` consumes `resp`.
        let payment_required_header = resp
            .header("payment-required")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let body = resp
            .body()
            .map_err(|e| format!("failed to read response body from {url}: {e}"))?;
        if body.len() > MAX_BODY_BYTES {
            return Err(format!(
                "response body from {url} exceeds {MAX_BODY_BYTES} bytes — refusing to parse"
            ));
        }
        Ok(HttpResponse {
            status,
            body,
            payment_required_header,
        })
    }

    fn rpc_call(
        rpc_url: &str,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });
        let resp = waki::Client::new()
            .post(rpc_url)
            .connect_timeout(CONNECT_TIMEOUT)
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .map_err(|e| format!("RPC {method} request failed: {e}"))?;
        let status = resp.status_code();
        let raw = resp
            .body()
            .map_err(|e| format!("RPC {method}: failed to read response body: {e}"))?;
        if raw.len() > MAX_RPC_BODY_BYTES {
            return Err(format!(
                "RPC {method}: response exceeds {MAX_RPC_BODY_BYTES} bytes"
            ));
        }
        if !(200..300).contains(&status) {
            return Err(format!("RPC {method} returned HTTP {status}"));
        }
        let parsed: serde_json::Value =
            serde_json::from_slice(&raw).map_err(|e| format!("RPC {method}: invalid JSON: {e}"))?;
        if let Some(err) = parsed.get("error") {
            return Err(format!("RPC {method} returned an error: {err}"));
        }
        parsed
            .get("result")
            .cloned()
            .ok_or_else(|| format!("RPC {method}: response has no \"result\" field"))
    }

    fn rpc_get_latest_blockhash(rpc_url: &str) -> Result<[u8; 32], String> {
        let result = rpc_call(
            rpc_url,
            "getLatestBlockhash",
            serde_json::json!([{"commitment": "confirmed"}]),
        )?;
        let blockhash_str = result
            .get("value")
            .and_then(|v| v.get("blockhash"))
            .and_then(|b| b.as_str())
            .ok_or("getLatestBlockhash: missing value.blockhash in response")?;
        decode_pubkey(blockhash_str)
    }

    /// The cluster's current slot, read once per `execute()` call and reused
    /// both as the source of "now" (via `getBlockTime`) and as the
    /// `minContextSlot` floor for every subsequent read in the same call —
    /// see `fetch_recent_transfer_history`'s doc comment for why.
    fn rpc_get_slot(rpc_url: &str) -> Result<u64, String> {
        rpc_call(
            rpc_url,
            "getSlot",
            serde_json::json!([{"commitment": "confirmed"}]),
        )?
        .as_u64()
        .ok_or_else(|| "getSlot: response was not an integer".to_string())
    }

    /// Uses the cluster's own clock (`getBlockTime` on `slot`) rather than
    /// any local wall-clock source — the wasm sandbox exposes no clock
    /// import in this WIT world, and trusting an unauthenticated local clock
    /// for a 24h spend-window boundary would be a fail-open risk in itself.
    fn rpc_get_block_time(rpc_url: &str, slot: u64) -> Result<i64, String> {
        rpc_call(rpc_url, "getBlockTime", serde_json::json!([slot]))?
            .as_i64()
            .ok_or_else(|| "getBlockTime: response was not an integer".to_string())
    }

    /// `min_context_slot` requires the RPC node to have caught up to at
    /// least that slot before answering, or return an error — Solana's own
    /// mechanism for refusing a stale read rather than silently serving one.
    /// Fixes a real gap found during the second audit pass: without this,
    /// an RPC node lagging behind (not necessarily malicious — could just be
    /// a slow public endpoint) would silently return a short-but-genuine-
    /// looking signature list, making `check_cumulative_cap` under-count
    /// real recent spend with no error ever surfacing. Pinning both this
    /// call and `getTransaction` below to the same slot `rpc_get_slot`
    /// already read for "now" (see `execute`) closes that gap: a lagging
    /// node fails closed here instead of silently serving stale data.
    ///
    /// **Filters by `blockTime` before ever calling `getTransaction`.**
    /// `getSignaturesForAddress` returns newest-first and already includes
    /// each signature's `blockTime` — no need to fetch the full transaction
    /// just to find out it's outside the 24h window. This closes a real
    /// under-counting risk found while load-testing the original design
    /// against real response sizes: fetching only the `limit` *most recent*
    /// signatures (previously 50, with no time filtering) would silently
    /// miss older-but-still-in-window transfers on any session key active
    /// enough to have more than `limit` transactions in a day — exactly the
    /// kind of account this plugin exists to serve. If more than
    /// `MAX_HISTORY_TRANSACTIONS_TO_FETCH` signatures fall inside the
    /// window, this returns an error (denying the payment) rather than
    /// silently inspecting only some of them.
    fn fetch_recent_transfer_history(
        rpc_url: &str,
        tracked_token_account: &str,
        min_context_slot: u64,
        now_unix: i64,
    ) -> Result<Vec<TransferRecord>, String> {
        // "confirmed" explicitly, not the RPC's implicit default (typically
        // "finalized", ~13-19s behind) — narrows, but does not close, the
        // window in which a burst of fast/concurrent x402_settle calls can
        // each read the cap before an earlier call's transfer lands. See
        // the README's threat model, item #8, for what this does and does
        // not guarantee.
        let signatures_result = rpc_call(
            rpc_url,
            "getSignaturesForAddress",
            serde_json::json!([
                tracked_token_account,
                {"limit": SIGNATURES_FETCH_LIMIT, "minContextSlot": min_context_slot, "commitment": "confirmed"}
            ]),
        )?;
        let signatures = signatures_result
            .as_array()
            .ok_or("getSignaturesForAddress: response was not an array")?;

        let in_window_signatures = select_signatures_within_window(
            signatures,
            now_unix,
            MAX_HISTORY_TRANSACTIONS_TO_FETCH,
        )?;

        let mut history = Vec::new();
        for signature in in_window_signatures {
            let tx = rpc_call(
                rpc_url,
                "getTransaction",
                serde_json::json!([signature, {
                    "encoding": "jsonParsed",
                    "maxSupportedTransactionVersion": 0,
                    "minContextSlot": min_context_slot,
                    "commitment": "confirmed"
                }]),
            )?;
            match extract_outgoing_transfer(&tx, tracked_token_account, now_unix) {
                Ok(Some(record)) => history.push(record),
                Ok(None) => {}
                // The account genuinely isn't referenced by this signature's
                // transaction — skip it rather than fail the whole fetch.
                Err(_) => {}
            }
        }
        Ok(history)
    }

    fn decode_pubkey(candidate: &str) -> Result<[u8; 32], String> {
        // bs58::decode is O(n^2) in input length (see MAX_BASE58_PUBKEY_INPUT_LEN
        // in x402_settle.rs); `candidate` here can ultimately trace back to
        // an untrusted server's `payTo` field. Reject oversized input before
        // ever decoding, and never format the full candidate into an error
        // either — both the CPU cost and the error-message size scale with
        // attacker-controlled input length otherwise.
        if candidate.len() > crate::x402_settle::MAX_BASE58_PUBKEY_INPUT_LEN {
            return Err(format!(
                "input is {} bytes, longer than any valid 32-byte pubkey could be",
                candidate.len()
            ));
        }
        let bytes = bs58::decode(candidate)
            .into_vec()
            .map_err(|e| format!("{candidate:?} is not valid base58: {e}"))?;
        bytes
            .try_into()
            .map_err(|_| format!("{candidate:?} must decode to exactly 32 bytes"))
    }

    /// Builds the x402 v2 `PAYMENT-SIGNATURE` payload: base64-encoded JSON
    /// matching `PaymentPayloadV2Schema` in the reference client
    /// (`@payai/x402`'s TypeScript source, vendored under
    /// `x402-echo-merchant/node_modules/@payai/x402`) —
    /// `{x402Version: 2, accepted, payload, extensions}`.
    ///
    /// `accepted.network` echoes the server's original string byte-for-byte
    /// (`req.network_raw`, never the normalized `network_label()` form) —
    /// confirmed against `@payai/x402-svm`'s facilitator `verify()`, which
    /// selects which of the server's own stored requirements to check
    /// against by comparing `payload.accepted.network` for strict string
    /// equality; a mismatch here fails lookup before any real check runs.
    /// Every other field the facilitator actually verifies for correctness
    /// (mint, destination, amount) it re-derives from decoding the signed
    /// transaction's own instructions against its own stored requirements —
    /// not from what this function sends — so `accepted`'s remaining fields
    /// only need to satisfy the schema, not be independently authoritative.
    fn build_payment_signature_header(tx_bytes: &[u8], req: &PaymentRequirement) -> String {
        let mut accepted = serde_json::json!({
            "scheme": "exact",
            "network": req.network_raw,
            "amount": req.amount_atomic.to_string(),
            "asset": req.asset_mint,
            "payTo": req.pay_to,
            "maxTimeoutSeconds": req.max_timeout_seconds.unwrap_or(DEFAULT_MAX_TIMEOUT_SECONDS),
        });
        if let Some(fee_payer) = &req.fee_payer {
            accepted["extra"] = serde_json::json!({ "feePayer": fee_payer });
        }
        let payload = serde_json::json!({
            "x402Version": 2,
            "accepted": accepted,
            "payload": { "transaction": to_base64(tx_bytes) },
            "extensions": {}
        });
        to_base64(payload.to_string().as_bytes())
    }

    /// A validation/parsing/network failure is a normal, expected tool
    /// outcome, not a broken component — always `success: false` with a
    /// reason, never `Err`.
    fn deny(reason: String) -> ToolResult {
        ToolResult {
            success: false,
            output: String::new(),
            error: Some(reason),
        }
    }

    fn emit(action: PluginAction, outcome: PluginOutcome, message: &str) {
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "x402_settle::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: None,
                message: message.to_string(),
            },
        );
    }

    export!(X402Settle);
}

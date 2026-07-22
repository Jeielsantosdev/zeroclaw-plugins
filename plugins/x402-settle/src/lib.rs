//! A ZeroClaw WIT tool plugin: `x402_settle`.
//!
//! Pays for an x402-gated resource under a scoped session key: fetches the
//! resource, validates the server's payment requirements against operator
//! policy, enforces a cumulative 24h spend cap recomputed from real on-chain
//! transfer history, builds and signs an SPL Token Transfer, and retries the
//! resource request with the `X-Payment` proof. See [`x402_settle`] for the
//! tested policy/signing core, [`transaction`] for manual Solana transaction
//! serialization, and [`rpc_history`] for turning RPC responses into spend
//! records.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

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

    use crate::rpc_history::extract_outgoing_transfer;
    use crate::transaction::{build_signed_transaction, to_base64};
    use crate::x402_settle::{
        check_cumulative_cap, decode_session_key_seed, parse_requirements, session_key_pubkey,
        validate_requirements, CapVerdict, SettlePolicyConfig, TransferRecord, Verdict,
        SPL_TOKEN_PROGRAM_ID,
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
    /// Cap on any single HTTP/RPC response body this component will read.
    const MAX_BODY_BYTES: usize = 32 * 1024;
    /// How many recent signatures to inspect for the cumulative cap. Bounded
    /// so a very active session account can never turn one `execute()` call
    /// into an unbounded number of RPC round trips.
    const MAX_HISTORY_SIGNATURES: usize = 50;

    #[derive(serde::Deserialize)]
    struct ExecuteArgs {
        resource_url: String,
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
            "Pay for an x402-gated resource. Fetches the resource, validates the server's HTTP \
             402 payment requirements against operator policy (network, mint, amount, recipient, \
             timeout), enforces a cumulative 24h spend cap recomputed from real on-chain transfer \
             history, then builds and signs an SPL token transfer with a scoped session key — \
             never the operator's main wallet — and retries with proof of payment."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "resource_url": {
                        "type": "string",
                        "description": "HTTPS URL of the x402-gated resource to pay for."
                    }
                },
                "required": ["resource_url"],
                "additionalProperties": false
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let parsed: ExecuteArgs = match serde_json::from_str(&args) {
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
            let Some(session_key_raw) = parsed.config.get("session_key").cloned() else {
                emit(
                    PluginAction::Fail,
                    PluginOutcome::Failure,
                    "no session_key configured",
                );
                return Ok(deny("session_key must be configured".to_string()));
            };
            let seed = match decode_session_key_seed(&session_key_raw) {
                Ok(s) => s,
                Err(e) => {
                    emit(
                        PluginAction::Fail,
                        PluginOutcome::Failure,
                        "malformed session_key",
                    );
                    return Ok(deny(format!("malformed session_key: {e}")));
                }
            };
            let fee_payer_pubkey = session_key_pubkey(&seed);

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
            let body_text = match String::from_utf8(first_resp.body) {
                Ok(s) => s,
                Err(_) => {
                    emit(
                        PluginAction::Fail,
                        PluginOutcome::Failure,
                        "402 body not utf8",
                    );
                    return Ok(deny("402 response body is not valid UTF-8".to_string()));
                }
            };
            let req = match parse_requirements(&body_text) {
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
            let history = match fetch_recent_transfer_history(&rpc_url, &source_token_account) {
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
            let now_unix = match rpc_get_unix_time(&rpc_url) {
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

            // Step 4: build and sign the transfer.
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
            let destination_bytes = match decode_pubkey(&req.pay_to) {
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

            let tx_bytes = build_signed_transaction(
                &seed,
                fee_payer_pubkey,
                source_bytes,
                destination_bytes,
                token_program_bytes,
                req.amount_atomic,
                recent_blockhash,
            );
            let payment_header = build_x_payment_header(&tx_bytes, req.network_label());

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
    }

    /// `payment_header`, when present, is sent as `X-Payment`. Kept as a
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
            req = req.header("X-Payment", value);
        }
        let resp = req
            .send()
            .map_err(|e| format!("request to {url} failed: {e}"))?;
        let status = resp.status_code();
        let body = resp
            .body()
            .map_err(|e| format!("failed to read response body from {url}: {e}"))?;
        if body.len() > MAX_BODY_BYTES {
            return Err(format!(
                "response body from {url} exceeds {MAX_BODY_BYTES} bytes — refusing to parse"
            ));
        }
        Ok(HttpResponse { status, body })
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
        if raw.len() > MAX_BODY_BYTES {
            return Err(format!(
                "RPC {method}: response exceeds {MAX_BODY_BYTES} bytes"
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

    /// Uses the cluster's own clock (via `getBlockTime` on the current slot,
    /// obtained through `getSlot`) rather than any local wall-clock source —
    /// the wasm sandbox exposes no clock import in this WIT world, and trusting
    /// an unauthenticated local clock for a 24h spend-window boundary would be
    /// a fail-open risk in itself.
    fn rpc_get_unix_time(rpc_url: &str) -> Result<i64, String> {
        let slot = rpc_call(
            rpc_url,
            "getSlot",
            serde_json::json!([{"commitment": "confirmed"}]),
        )?
        .as_i64()
        .ok_or("getSlot: response was not an integer")?;
        let block_time = rpc_call(rpc_url, "getBlockTime", serde_json::json!([slot]))?
            .as_i64()
            .ok_or("getBlockTime: response was not an integer")?;
        Ok(block_time)
    }

    fn fetch_recent_transfer_history(
        rpc_url: &str,
        tracked_token_account: &str,
    ) -> Result<Vec<TransferRecord>, String> {
        let signatures_result = rpc_call(
            rpc_url,
            "getSignaturesForAddress",
            serde_json::json!([tracked_token_account, {"limit": MAX_HISTORY_SIGNATURES}]),
        )?;
        let signatures = signatures_result
            .as_array()
            .ok_or("getSignaturesForAddress: response was not an array")?;

        let mut history = Vec::new();
        for entry in signatures {
            let Some(signature) = entry.get("signature").and_then(|s| s.as_str()) else {
                continue;
            };
            let tx = rpc_call(
                rpc_url,
                "getTransaction",
                serde_json::json!([signature, {"encoding": "jsonParsed", "maxSupportedTransactionVersion": 0}]),
            )?;
            match extract_outgoing_transfer(&tx, tracked_token_account) {
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

    fn build_x_payment_header(tx_bytes: &[u8], network: &str) -> String {
        let payload = serde_json::json!({
            "x402Version": 1,
            "scheme": "exact",
            "network": network,
            "payload": { "serializedTransaction": to_base64(tx_bytes) }
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

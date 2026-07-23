//! A ZeroClaw WIT tool plugin: `x402_quote_check`.
//!
//! Fetches an x402-gated resource, parses the HTTP 402 payment requirements
//! (preferring the base64-encoded `PAYMENT-REQUIRED` response header real
//! servers use, falling back to the response body's own shape tolerance —
//! see `x402::parse_requirements_from_response`), and returns a GO/NO-GO
//! verdict against operator-configured policy (network, mint, per-call
//! amount cap, `payTo` shape, timeout ceiling). **This plugin never pays
//! anything** — it holds no
//! session key, builds no transaction, and cannot itself be the target of a
//! "drain the funds" attack. It is the T0 half of a two-part delivery: see
//! the README's "Roadmap" section for the planned `x402-settle` (T2) sibling.
//!
//! The pure policy core lives in [`x402`] with no wasm dependency, so it
//! compiles and tests on the host with a plain `cargo test`; the wasm
//! component reuses the exact same logic through this shim.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod x402;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;
    use std::time::Duration;

    use crate::x402::{
        format_brief, parse_requirements_from_response, validate_requirements, QuoteCheckConfig,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct X402QuoteCheck;

    const PLUGIN_NAME: &str = "x402-quote-check";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "x402_quote_check";
    const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
    /// Cap on how much of a 402 response body we'll ever read. A hostile or
    /// misbehaving server dumping megabytes of JSON should never blow the
    /// agent's context budget or this component's memory.
    const MAX_BODY_BYTES: usize = 16 * 1024;

    #[derive(serde::Deserialize)]
    struct ExecuteArgs {
        resource_url: String,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

    impl PluginInfo for X402QuoteCheck {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for X402QuoteCheck {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Probe an x402-gated resource and report whether paying for it would be safe, \
             without ever paying. Fetches the resource, parses the HTTP 402 payment \
             requirements the server returns, and validates network, token mint, amount, \
             recipient, and timeout window against operator policy. Read-only: never builds \
             or signs a transaction."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "resource_url": {
                        "type": "string",
                        "description": "HTTPS URL of the x402-gated resource to probe."
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
                        None,
                    );
                    return Ok(deny(format!("invalid arguments: {e}")));
                }
            };

            if !parsed.resource_url.starts_with("https://") {
                emit(
                    PluginAction::Fail,
                    PluginOutcome::Failure,
                    "non-https resource_url",
                    None,
                );
                return Ok(deny("resource_url must be an https:// URL".to_string()));
            }

            let cfg = QuoteCheckConfig::from_section(&parsed.config);

            let resp = match waki::Client::new()
                .get(&parsed.resource_url)
                .connect_timeout(CONNECT_TIMEOUT)
                .send()
            {
                Ok(r) => r,
                Err(e) => {
                    emit(
                        PluginAction::Fail,
                        PluginOutcome::Failure,
                        "http request failed",
                        None,
                    );
                    return Ok(deny(format!("request to resource failed: {e}")));
                }
            };

            let status = resp.status_code();
            if status != 402 {
                emit(
                    PluginAction::Complete,
                    PluginOutcome::Success,
                    "resource did not request payment",
                    None,
                );
                return Ok(ToolResult {
                    success: true,
                    output: format!(
                        "no payment required right now (HTTP {status}) — nothing to validate"
                    ),
                    error: None,
                });
            }

            // Real x402 servers (confirmed against live Otto AI and Syra
            // deployments, 2026-07-23) carry the payment requirements in a
            // base64-encoded `PAYMENT-REQUIRED` response header, not the
            // body — the body is typically just a human-readable hint.
            // `header()` borrows, so it must run before `body()` consumes
            // `resp`.
            let payment_required_header = resp
                .header("payment-required")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());

            let body = match resp.body() {
                Ok(b) if b.len() > MAX_BODY_BYTES => {
                    emit(
                        PluginAction::Fail,
                        PluginOutcome::Failure,
                        "402 body too large",
                        None,
                    );
                    return Ok(deny(format!(
                        "402 response body exceeds {MAX_BODY_BYTES} bytes — refusing to parse"
                    )));
                }
                Ok(b) => b,
                Err(e) => {
                    emit(
                        PluginAction::Fail,
                        PluginOutcome::Failure,
                        "failed to read 402 body",
                        None,
                    );
                    return Ok(deny(format!("failed to read 402 response body: {e}")));
                }
            };
            let body_text = match String::from_utf8(body) {
                Ok(s) => s,
                Err(_) => {
                    emit(
                        PluginAction::Fail,
                        PluginOutcome::Failure,
                        "402 body not utf8",
                        None,
                    );
                    return Ok(deny("402 response body is not valid UTF-8".to_string()));
                }
            };

            let req = match parse_requirements_from_response(
                payment_required_header.as_deref(),
                &body_text,
            ) {
                Ok(r) => r,
                Err(e) => {
                    emit(
                        PluginAction::Fail,
                        PluginOutcome::Failure,
                        "unrecognized 402 shape",
                        None,
                    );
                    return Ok(deny(format!("could not parse payment requirements: {e}")));
                }
            };

            let verdict = validate_requirements(&req, &cfg);
            let is_go = matches!(verdict, crate::x402::Verdict::Go { .. });
            emit(
                PluginAction::Complete,
                PluginOutcome::Success,
                if is_go {
                    "verdict: go"
                } else {
                    "verdict: no-go"
                },
                None,
            );

            Ok(ToolResult {
                success: true,
                output: format_brief(&verdict),
                error: None,
            })
        }
    }

    /// A validation/parsing failure is a normal, expected tool outcome, not a
    /// broken component — always `success: false` with a reason, never `Err`.
    fn deny(reason: String) -> ToolResult {
        ToolResult {
            success: false,
            output: String::new(),
            error: Some(reason),
        }
    }

    fn emit(action: PluginAction, outcome: PluginOutcome, message: &str, attrs: Option<String>) {
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "x402_quote_check::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs,
                message: message.to_string(),
            },
        );
    }

    export!(X402QuoteCheck);
}

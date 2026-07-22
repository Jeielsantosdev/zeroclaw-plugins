//! Automated checks tying this plugin directly to the bounty's hard
//! requirements and judging criteria, instead of relying only on the manual
//! checklist in `../../../VERIFICATION.md`. Each test names the exact
//! requirement/criterion it protects so a failure is self-explanatory.
//!
//! Judging criteria (official listing, see `../../../../docs/02-criterios-avaliacao.md`):
//! utilidade real (30%), segurança/custódia (25%), qualidade de código (20%),
//! prontidão para merge (15%), demo/documentação (10%).
//!
//! This crate is T2 — the bounty's own text warns the safety bar here is
//! "brutal", so a few checks below exist only in this file, not in
//! x402-quote-check's equivalent (T0 has no session key to misconfigure).

use std::fs;
use std::path::Path;

use x402_settle::x402_settle::SettlePolicyConfig;

fn manifest_dir() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn read(rel_path: &str) -> String {
    let path = manifest_dir().join(rel_path);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("could not read {path:?}: {e}"))
}

/// Every `.rs` file directly under `src/`.
fn source_files() -> Vec<std::path::PathBuf> {
    let dir = manifest_dir().join("src");
    fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("could not read {dir:?}: {e}"))
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|p| p.extension().is_some_and(|ext| ext == "rs"))
        .collect()
}

/// The portion of a source file before its `#[cfg(test)]` module, if any —
/// production code only, matching the manual review procedure in
/// `VERIFICATION.md` section 2.2.
fn production_code_only(source: &str) -> &str {
    match source.find("#[cfg(test)]") {
        Some(idx) => &source[..idx],
        None => source,
    }
}

// ---------------------------------------------------------------------------
// Hard requirement: manifest.toml correct — feeds prontidão para merge (15%)
// ---------------------------------------------------------------------------

#[test]
fn manifest_declares_exactly_the_tool_capability() {
    let manifest = read("manifest.toml");
    assert!(manifest.contains(r#"capabilities = ["tool"]"#));
}

#[test]
fn manifest_name_matches_the_plugin_directory_name() {
    let manifest = read("manifest.toml");
    let dir_name = manifest_dir().file_name().and_then(|n| n.to_str()).unwrap();
    let expected = format!(r#"name = "{dir_name}""#);
    assert!(
        manifest.contains(&expected),
        "manifest.toml's name must match the plugin directory name ({dir_name})"
    );
}

#[test]
fn manifest_declares_the_t2_tier_honestly() {
    let manifest = read("manifest.toml");
    assert!(
        manifest.to_ascii_uppercase().contains("T2"),
        "manifest.toml's description should state the custody tier (T2) — \
         judging question: \"is the tier honest?\""
    );
}

// ---------------------------------------------------------------------------
// Hard requirement: only permissions actually used are declared
// ---------------------------------------------------------------------------

#[test]
fn declared_permissions_are_the_only_ones_and_are_all_actually_used() {
    let manifest = read("manifest.toml");
    let lib_rs = read("src/lib.rs");

    let permissions_line = manifest
        .lines()
        .find(|l| l.trim_start().starts_with("permissions"))
        .expect("manifest.toml must have a permissions line");
    let bracketed = permissions_line
        .split_once('[')
        .and_then(|(_, rest)| rest.split_once(']'))
        .map(|(inside, _)| inside)
        .expect("permissions line must be a bracketed list");
    for token in bracketed.split(',') {
        let token = token.trim().trim_matches('"');
        if token.is_empty() {
            continue;
        }
        assert!(
            token == "http_client" || token == "config_read",
            "unexpected permission {token:?} declared"
        );
    }

    assert!(
        manifest.contains("http_client"),
        "x402-settle must declare http_client"
    );
    assert!(
        lib_rs.contains("waki::"),
        "http_client declared but waki:: never used"
    );
    assert!(
        manifest.contains("config_read"),
        "x402-settle must declare config_read"
    );
    assert!(
        lib_rs.contains("__config"),
        "config_read declared but __config never read"
    );
}

// ---------------------------------------------------------------------------
// Hard requirement: pure-core/thin-shim layout, MIT-compatible license,
// cdylib+rlib
// ---------------------------------------------------------------------------

#[test]
fn cargo_toml_declares_a_permissive_license() {
    let cargo_toml = read("Cargo.toml");
    let license_line = cargo_toml
        .lines()
        .find(|l| l.trim_start().starts_with("license"))
        .expect("Cargo.toml must declare a license");
    assert!(license_line.contains("MIT"), "{license_line:?}");
}

#[test]
fn crate_type_is_cdylib_and_rlib() {
    let cargo_toml = read("Cargo.toml");
    assert!(cargo_toml.contains(r#"crate-type = ["cdylib", "rlib"]"#));
}

#[test]
fn wasm_only_dependencies_are_target_gated() {
    let cargo_toml = read("Cargo.toml");
    assert!(cargo_toml.contains(r#"[target.'cfg(target_family = "wasm")'.dependencies]"#));
}

// ---------------------------------------------------------------------------
// Hard requirement: structured logging only, no stdout
// ---------------------------------------------------------------------------

#[test]
fn no_stdout_logging_anywhere_in_source() {
    for path in source_files() {
        let content = fs::read_to_string(&path).unwrap();
        assert!(
            !content.contains("println!")
                && !content.contains("eprintln!")
                && !content.contains("dbg!"),
            "{path:?} must never log via stdout/stderr — only log_record is permitted"
        );
    }
}

// ---------------------------------------------------------------------------
// Hard requirement: fail-closed, no panics in production code
// ---------------------------------------------------------------------------

#[test]
fn no_panicking_calls_in_production_code() {
    let panic_markers = [".unwrap()", ".expect(", "panic!", "unimplemented!", "todo!"];
    for path in source_files() {
        let content = fs::read_to_string(&path).unwrap();
        let production = production_code_only(&content);
        for marker in panic_markers {
            assert!(
                !production.contains(marker),
                "{path:?} contains {marker:?} in production code — a malformed/hostile input, \
                 or an RPC error, must produce ToolResult{{success:false}} or Err, never panic"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Hard requirement: no hardcoded secrets — instant-disqualification territory
// ---------------------------------------------------------------------------

#[test]
fn no_hardcoded_secret_looking_assignments() {
    for path in source_files() {
        let content = fs::read_to_string(&path).unwrap().to_ascii_lowercase();
        for needle in ["private_key =", "secret_key =", "priv_key =", "api_key =\""] {
            assert!(
                !content.contains(needle),
                "{path:?} appears to hardcode {needle:?}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// T2-specific: "Requires scoped session key with spend limits... Fails
// closed on any missing guard" (CLAUDE.md custody tier definition) — the
// single most consequential requirement for this specific plugin
// ---------------------------------------------------------------------------

#[test]
fn no_safe_default_exists_for_the_session_key_itself() {
    // Unlike expected_network/known_mint/the caps (which all have real,
    // conservative defaults), the session key must have NO default at all
    // — its absence is a hard error at the shim level (see lib.rs), not a
    // silently-assumed value. This test pins that by construction: nothing
    // in SettlePolicyConfig carries key material, so there is no field here
    // that could accidentally grow a default.
    let empty = std::collections::HashMap::new();
    let cfg = SettlePolicyConfig::from_section(&empty);
    // If this ever needs updating because a `session_key` field was added
    // to SettlePolicyConfig, that is itself the regression this test exists
    // to catch — session key material must stay outside any Debug-derivable
    // config struct (see src/x402_settle.rs's own doc comment on this).
    let debug_repr = format!("{cfg:?}");
    assert!(
        !debug_repr.to_ascii_lowercase().contains("key"),
        "SettlePolicyConfig's Debug output must never mention key material: {debug_repr}"
    );
}

#[test]
fn spend_limits_have_real_conservative_defaults_even_without_config() {
    // T2's own definition requires "spend limits" to exist, full stop —
    // this confirms the unprivileged (no config_read) case still has real,
    // non-zero, non-unbounded caps, not an accidental "0 means unlimited"
    // or similar footgun.
    let empty = std::collections::HashMap::new();
    let cfg = SettlePolicyConfig::from_section(&empty);
    assert!(
        cfg.max_amount_atomic > 0,
        "per-call cap must never default to 0/unlimited"
    );
    assert!(
        cfg.max_cumulative_atomic_24h > 0,
        "cumulative cap must never default to 0/unlimited"
    );
    assert!(
        cfg.max_cumulative_atomic_24h >= cfg.max_amount_atomic,
        "cumulative cap smaller than the per-call cap would make the per-call cap pointless"
    );
}

#[test]
fn rpc_url_and_session_token_account_have_no_unsafe_defaults() {
    // Also no safe generic default — see SettlePolicyConfig's own doc
    // comment. Confirmed here rather than only in x402_settle.rs's unit
    // tests, since this file's whole point is checking bounty-facing
    // guarantees independent of the core's own test suite.
    let empty = std::collections::HashMap::new();
    let cfg = SettlePolicyConfig::from_section(&empty);
    assert_eq!(cfg.rpc_url, None);
    assert_eq!(cfg.session_token_account, None);
}

// ---------------------------------------------------------------------------
// Hard requirement: README covers what it does, config, tier, threat model,
// example
// ---------------------------------------------------------------------------

#[test]
fn readme_covers_the_required_sections() {
    let readme = read("README.md");
    let required_substrings = [
        ("custody tier", "Custody tier"),
        ("threat model", "Threat model"),
        ("config keys", "Config keys"),
        ("worked example", "example"),
        ("wasm32-wasip2 build notes", "wasm32-wasip2"),
    ];
    for (label, needle) in required_substrings {
        assert!(
            readme
                .to_ascii_lowercase()
                .contains(&needle.to_ascii_lowercase()),
            "README.md is missing its {label} section (expected to find {needle:?})"
        );
    }
}

#[test]
fn readme_declares_the_same_tier_the_manifest_description_implies() {
    let readme = read("README.md");
    let manifest = read("manifest.toml");
    assert!(readme.to_ascii_uppercase().contains("T2"));
    assert!(manifest.to_ascii_uppercase().contains("T2"));
}

#[test]
fn readme_defends_why_this_cannot_be_t1() {
    // T2 is the "brutal safety bar" tier — the bounty explicitly wants to
    // see the T1-vs-T2 reasoning defended, not just the tier declared.
    let readme = read("README.md").to_ascii_lowercase();
    assert!(
        readme.contains("t1")
            && (readme.contains("proof of payment") || readme.contains("cannot be genuinely t1")),
        "README must defend why this idea cannot be T1, not just assert T2"
    );
}

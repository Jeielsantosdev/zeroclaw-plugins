//! Automated checks tying this plugin directly to the bounty's hard
//! requirements and judging criteria, instead of relying only on the manual
//! checklist in `../../../VERIFICATION.md`. Each test names the exact
//! requirement/criterion it protects so a failure is self-explanatory.
//!
//! Judging criteria (official listing, see `../../../../docs/02-criterios-avaliacao.md`):
//! utilidade real (30%), segurança/custódia (25%), qualidade de código (20%),
//! prontidão para merge (15%), demo/documentação (10%).

use std::fs;
use std::path::Path;

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
// Hard requirement: "1 componente = 1 ferramenta"; manifest.toml correct
// (docs/01-requisitos.md) — feeds prontidão para merge (15%)
// ---------------------------------------------------------------------------

#[test]
fn manifest_declares_exactly_the_tool_capability() {
    let manifest = read("manifest.toml");
    assert!(
        manifest.contains(r#"capabilities = ["tool"]"#),
        "manifest.toml must declare capabilities = [\"tool\"] exactly — one component, one tool"
    );
}

#[test]
fn manifest_name_matches_the_plugin_directory_name() {
    let manifest = read("manifest.toml");
    let dir_name = manifest_dir().file_name().and_then(|n| n.to_str()).unwrap();
    let expected = format!(r#"name = "{dir_name}""#);
    assert!(
        manifest.contains(&expected),
        "manifest.toml's name must match the plugin directory name ({dir_name}) — \
         the official CI validator (tools/ci/validate_components.sh) hard-fails on this"
    );
}

#[test]
fn manifest_declares_a_custody_tier_relevant_description() {
    let manifest = read("manifest.toml");
    assert!(
        manifest.to_ascii_uppercase().contains("T0"),
        "manifest.toml's description should state the custody tier (T0) — \
         judging question: \"is the tier honest?\""
    );
}

// ---------------------------------------------------------------------------
// Hard requirement: only permissions actually used are declared
// (docs/07-checklist.md) — feeds prontidão para merge (15%)
// ---------------------------------------------------------------------------

#[test]
fn declared_permissions_are_the_only_ones_and_are_all_actually_used() {
    let manifest = read("manifest.toml");
    let lib_rs = read("src/lib.rs");

    let declares_http_client = manifest.contains("http_client");
    let declares_config_read = manifest.contains("config_read");

    // No permission beyond these two exists in the WIT contract for
    // tool-plugin; assert nothing unexpected slipped in.
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
            "unexpected permission {token:?} declared — only http_client and config_read exist \
             in the tool-plugin WIT contract"
        );
    }

    if declares_http_client {
        assert!(
            lib_rs.contains("waki::"),
            "manifest declares http_client but src/lib.rs never uses waki:: — \
             declaring an unused permission is a demerit per docs/02-criterios-avaliacao.md"
        );
    }
    if declares_config_read {
        assert!(
            lib_rs.contains("__config"),
            "manifest declares config_read but src/lib.rs never reads __config"
        );
    }
}

// ---------------------------------------------------------------------------
// Hard requirement: pure-core/thin-shim layout, MIT-compatible license,
// cdylib+rlib — feeds qualidade de código (20%) and prontidão (15%)
// ---------------------------------------------------------------------------

#[test]
fn cargo_toml_declares_a_permissive_license() {
    let cargo_toml = read("Cargo.toml");
    let license_line = cargo_toml
        .lines()
        .find(|l| l.trim_start().starts_with("license"))
        .expect("Cargo.toml must declare a license");
    assert!(
        license_line.contains("MIT"),
        "license must be MIT (or MIT-compatible) per the bounty's hard requirements: {license_line:?}"
    );
}

#[test]
fn crate_type_is_cdylib_and_rlib() {
    let cargo_toml = read("Cargo.toml");
    assert!(
        cargo_toml.contains(r#"crate-type = ["cdylib", "rlib"]"#),
        "must be cdylib (wasm component) + rlib (host-testable pure core), matching plugins/redact-text"
    );
}

#[test]
fn wasm_only_dependencies_are_target_gated() {
    let cargo_toml = read("Cargo.toml");
    assert!(
        cargo_toml.contains(r#"[target.'cfg(target_family = "wasm")'.dependencies]"#),
        "waki (wasm-only HTTP) must be under a wasm target gate, not a plain dependency, \
         so `cargo test` never needs the wasm toolchain"
    );
}

// ---------------------------------------------------------------------------
// Hard requirement: structured logging only, no stdout — feeds segurança
// (25%, \"does it fail closed?\" territory) and qualidade de código (20%)
// ---------------------------------------------------------------------------

#[test]
fn no_stdout_logging_anywhere_in_source() {
    for path in source_files() {
        let content = fs::read_to_string(&path).unwrap();
        assert!(
            !content.contains("println!")
                && !content.contains("eprintln!")
                && !content.contains("dbg!"),
            "{path:?} must never log via stdout/stderr — only log_record is permitted \
             (docs/07-checklist.md: \"nenhum println!/stdout no caminho do componente\")"
        );
    }
}

// ---------------------------------------------------------------------------
// Hard requirement: fail-closed, no panics in production code — feeds
// segurança (25%, \"does it fail closed?\")
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
                "{path:?} contains {marker:?} in production code (outside #[cfg(test)]) — \
                 a malformed/hostile input must produce ToolResult{{success:false}}, never a panic"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Hard requirement: no hardcoded secrets — instant-disqualification territory
// (docs/01-requisitos.md, \"We will not accept\") — feeds segurança (25%)
// ---------------------------------------------------------------------------

#[test]
fn no_hardcoded_secret_looking_assignments() {
    for path in source_files() {
        let content = fs::read_to_string(&path).unwrap().to_ascii_lowercase();
        for needle in ["private_key =", "secret_key =", "priv_key =", "api_key =\""] {
            assert!(
                !content.contains(needle),
                "{path:?} appears to hardcode a secret-shaped value ({needle:?}) — \
                 secrets must only ever come from config_read/__config"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Hard requirement: README covers what it does, config, tier, threat model,
// example (docs/01-requisitos.md) — feeds demo/documentação (10%) as a
// perception multiplier over the other 90%
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
    // Both must agree on T0 — a mismatch here is exactly the "is the tier
    // honest?" failure mode the judging criteria calls out by name.
    assert!(readme.to_ascii_uppercase().contains("T0"));
    assert!(manifest.to_ascii_uppercase().contains("T0"));
}

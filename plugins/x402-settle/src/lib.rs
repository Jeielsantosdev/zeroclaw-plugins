//! A ZeroClaw WIT tool plugin: `x402_settle` (work in progress).
//!
//! Pays for an x402-gated resource under a scoped session key, enforcing a
//! cumulative 24h spend cap recomputed from real on-chain transfer history on
//! every call. See [`x402_settle`] for the tested policy/signing core.
//!
//! **Status:** the pure core (requirement validation, cumulative cap, SPL
//! Transfer instruction building, ed25519 signing) is implemented and tested.
//! The wasm shim (`#[cfg(target_family = "wasm")]`, fetching the 402
//! challenge and the session account's transfer history, assembling and
//! submitting the final signed transaction) is not yet implemented — that is
//! the next unit of work. This crate intentionally does not yet export a
//! `tool-plugin` component.

pub mod x402_settle;

//! A ZeroClaw WIT tool plugin: `x402_settle` (work in progress).
//!
//! Pays for an x402-gated resource under a scoped session key, enforcing a
//! cumulative 24h spend cap recomputed from real on-chain transfer history on
//! every call. See [`x402_settle`] for the tested policy/signing core and
//! [`transaction`] for the manual Solana transaction wire-format assembly.
//!
//! **Status:** the pure core (requirement validation, cumulative cap, SPL
//! Transfer instruction building, ed25519 signing, and now full legacy
//! transaction serialization) is implemented and tested. The wasm shim
//! (`#[cfg(target_family = "wasm")]`, fetching the 402 challenge and the
//! session account's transfer history, then submitting the final signed
//! transaction) is not yet implemented — that is the next unit of work. This
//! crate intentionally does not yet export a `tool-plugin` component.

pub mod transaction;
pub mod x402_settle;

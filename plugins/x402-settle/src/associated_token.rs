//! Associated Token Account (ATA) address derivation — a pure Solana PDA
//! (Program Derived Address) computation, no RPC involved.
//!
//! Needed because real x402 servers publish `payTo` as a wallet address
//! (the token account's *owner*), not the token account itself — confirmed
//! against two independent live servers on 2026-07-27 (Otto AI mainnet,
//! PayAI Echo Merchant devnet), both routing payments to a
//! System-Program-owned wallet, not an SPL token account. `lib.rs` derives
//! the ATA from that wallet plus the accepted mint before verifying and
//! transferring into it — see `account_verify` for the verification step.
//!
//! Like `account_verify` and `rpc_history`, this module only ever computes
//! from inputs already in hand — no network calls here, which is what
//! keeps it host-testable.

use crate::x402_settle::{decode_pubkey, BuildInstructionError};
use curve25519_dalek::edwards::CompressedEdwardsY;
use sha2::{Digest, Sha256};

/// The SPL Associated Token Account program. Verified live (2026-07-27)
/// against both mainnet and devnet RPC: `getAccountInfo` reports this
/// address as `executable: true`, owned by
/// `BPFLoader2111111111111111111111111111111111` on both clusters.
pub const ASSOCIATED_TOKEN_PROGRAM_ID: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";

const PDA_MARKER: &[u8] = b"ProgramDerivedAddress";

/// True if `candidate` decodes to a valid point on the ed25519 curve. A PDA
/// is valid only when it does *not* — that absence of a corresponding
/// point is what guarantees no private key exists for it. Matches Solana's
/// `Pubkey::find_program_address` exactly; cross-checked in this module's
/// tests against two real, already-created Associated Token Accounts on
/// this workspace's own devnet wallets.
fn is_on_curve(candidate: &[u8; 32]) -> bool {
    CompressedEdwardsY(*candidate).decompress().is_some()
}

/// Solana's generic PDA derivation: the first (from bump 255 downward)
/// SHA-256 of `seeds || bump || program_id || "ProgramDerivedAddress"` that
/// is off-curve.
fn find_program_address(seeds: &[&[u8]], program_id: &[u8; 32]) -> ([u8; 32], u8) {
    for bump in (0..=255u8).rev() {
        let mut hasher = Sha256::new();
        for seed in seeds {
            hasher.update(seed);
        }
        hasher.update([bump]);
        hasher.update(program_id);
        hasher.update(PDA_MARKER);
        let hash: [u8; 32] = hasher.finalize().into();
        if !is_on_curve(&hash) {
            return (hash, bump);
        }
    }
    // Cryptographically implausible (a valid curve point at all 256 bump
    // values in a row) — no input reaches this in practice, but every
    // production path in this plugin fails closed rather than panics, so
    // the caller gets a zeroed, obviously-invalid address instead of an
    // abort; downstream getAccountInfo/verify_token_account on it will
    // simply fail like any other nonexistent account.
    ([0u8; 32], 0)
}

/// Derives the Associated Token Account address for `owner`'s holdings of
/// `mint`, under the (legacy) SPL Token program — this plugin only ever
/// builds legacy SPL Token transfers, never Token-2022, so `token_program`
/// should always be `SPL_TOKEN_PROGRAM_ID`.
pub fn derive_associated_token_address(
    owner: &[u8; 32],
    token_program: &[u8; 32],
    mint: &[u8; 32],
) -> Result<[u8; 32], BuildInstructionError> {
    let ata_program = decode_pubkey("associated_token_program", ASSOCIATED_TOKEN_PROGRAM_ID)?;
    let (address, _bump) = find_program_address(&[owner, token_program, mint], &ata_program);
    Ok(address)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x402_settle::SPL_TOKEN_PROGRAM_ID;

    fn pk(base58: &str) -> [u8; 32] {
        decode_pubkey("test", base58).expect("valid test pubkey")
    }

    /// Cross-checked against `spl-token address --owner <owner> --token
    /// <mint>` (the canonical CLI derivation) and the real, already-created
    /// ATA on devnet — bump 255, i.e. the very first candidate is off-curve.
    #[test]
    fn derives_the_real_merchant_ata_bump_255() {
        let owner = pk("fKzQPahKiYtPfJdUjgsEdgUr5MW9AKtSNrsWNCuDCnJ");
        let token_program = pk(SPL_TOKEN_PROGRAM_ID);
        let mint = pk("8aS82AXRNyYGYQ3iHPBa9LhsfWkjLcPeGz35enQW4tcx");

        let derived = derive_associated_token_address(&owner, &token_program, &mint)
            .expect("derivation must succeed for well-formed inputs");
        let expected = pk("AYKv8Y4y1eav2NqctYh9BYRu5FuaSGG6ko3VgZjPYdUX");
        assert_eq!(derived, expected);
    }

    /// Same cross-check, but for an owner whose derivation needs a
    /// non-trivial bump search (254, not 255) — confirms the downward
    /// bump-search loop itself is correct, not just the trivial first-try
    /// case above.
    #[test]
    fn derives_the_real_session_ata_bump_254() {
        let owner = pk("12rrpYxuYcz6jf1tNy2abNsbyPHN69dKj13tThkPe3Lo");
        let token_program = pk(SPL_TOKEN_PROGRAM_ID);
        let mint = pk("8aS82AXRNyYGYQ3iHPBa9LhsfWkjLcPeGz35enQW4tcx");

        let derived = derive_associated_token_address(&owner, &token_program, &mint)
            .expect("derivation must succeed for well-formed inputs");
        let expected = pk("FiAKw62cykUgG5YwsPK9wXhYTvsKXNyUg9rhKPsruQuo");
        assert_eq!(derived, expected);
    }

    #[test]
    fn different_mints_derive_different_atas_for_the_same_owner() {
        let owner = pk("fKzQPahKiYtPfJdUjgsEdgUr5MW9AKtSNrsWNCuDCnJ");
        let token_program = pk(SPL_TOKEN_PROGRAM_ID);
        let mint_a = pk("8aS82AXRNyYGYQ3iHPBa9LhsfWkjLcPeGz35enQW4tcx");
        let mint_b = pk("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");

        let ata_a = derive_associated_token_address(&owner, &token_program, &mint_a).unwrap();
        let ata_b = derive_associated_token_address(&owner, &token_program, &mint_b).unwrap();
        assert_ne!(ata_a, ata_b);
    }

    #[test]
    fn is_on_curve_rejects_a_known_off_curve_pda() {
        // The hash that produced the real merchant ATA above, verified
        // off-curve by definition (it's a valid PDA).
        let ata = pk("AYKv8Y4y1eav2NqctYh9BYRu5FuaSGG6ko3VgZjPYdUX");
        assert!(!is_on_curve(&ata));
    }

    #[test]
    fn is_on_curve_accepts_a_known_on_curve_point() {
        // Any real ed25519 public key (e.g. our own devnet session key) is
        // by construction a valid curve point.
        let real_pubkey = pk("12rrpYxuYcz6jf1tNy2abNsbyPHN69dKj13tThkPe3Lo");
        assert!(is_on_curve(&real_pubkey));
    }
}

//! Solana transaction assembly using the modular `solana-*` crates (message
//! compilation, `TransferChecked`, `ComputeBudget`) instead of hand-rolled
//! byte encoding.
//!
//! An earlier version of this module hand-encoded a single plain `Transfer`
//! instruction directly as bytes, reasoning that `solana-sdk` doesn't target
//! `wasm32-wasip2`. That premise was incomplete: `EDITAL.md` (this bounty's
//! source of truth) confirms the *modular* crates —
//! `solana-pubkey`/`solana-instruction`/`solana-message`/`solana-transaction`/
//! `solana-hash`, plus `spl-token` — compile clean to `wasm32-wasip2` and are
//! explicitly preferred over hand-rolled encoding. Verified against this
//! exact plugin's target (2026-07-27) before adopting them here.
//!
//! The instruction shape itself also had to change to match what real x402
//! v2 Solana servers actually require (confirmed against the x402.org
//! public facilitator and `docs.payai.network/x402/clients/typescript/
//! manual-flow.md`, "Solana exact scheme"), in this exact order:
//! 1. `SetComputeUnitLimit` (<=40,000 compute units)
//! 2. `SetComputeUnitPrice` (<=5 microlamports/CU)
//! 3. `TransferChecked` (validates mint + decimals, unlike plain `Transfer`)
//!
//! ## Two fee-payer models, one code path
//!
//! `EDITAL.md`: *"the facilitator co-signs as fee payer, so the agent needs
//! no SOL for gas"* — the standard x402 v2 pattern, confirmed live: every
//! real server tested this session (Otto AI, PayAI, x402.org) advertises an
//! `extra.feePayer`. `fee_payer_pubkey` carries that address when present.
//!
//! When the server provides no `feePayer`, the caller passes the session
//! key's own pubkey as `fee_payer_pubkey` — identical to `authority_pubkey`.
//! `Message::new_with_blockhash`'s key deduplication then naturally collapses
//! this to a single required signer, so the self-funded model (the original
//! behavior) falls out of the *same* code path rather than a separate one:
//! fewer branches to get wrong in a T2 component.
//!
//! In the sponsored case, the transaction is deliberately left **partially
//! signed**: the fee payer's signature slot (always account index 0 — an
//! ordering `Message::new_with_blockhash` guarantees, verified in this
//! module's tests) stays the default/zeroed placeholder. This plugin signs
//! only its own slot, as the transfer authority — never the fee payer's.
//! Only the facilitator can complete and broadcast it.

use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_hash::Hash;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_transaction::Transaction;

use crate::x402_settle::sign_message;

/// Compute unit ceiling the spec allows for this instruction shape.
pub const COMPUTE_UNIT_LIMIT: u32 = 40_000;
/// Priority-fee ceiling the spec allows, in microlamports per compute unit.
pub const COMPUTE_UNIT_PRICE_MICROLAMPORTS: u64 = 5;

/// Builds the full instruction set, compiles the message, signs only this
/// plugin's own signer slot (transfer authority — never the fee payer's, if
/// they differ), and returns the serialized transaction wire bytes.
///
/// `fee_payer_pubkey` may equal `authority_pubkey` (self-funded fallback) or
/// name a different address (server-sponsored — see module docs); either
/// way this is the only transaction-building path in the plugin.
#[allow(clippy::too_many_arguments)]
pub fn build_transfer_checked_transaction(
    authority_seed: &[u8; 32],
    authority_pubkey: [u8; 32],
    fee_payer_pubkey: [u8; 32],
    source_token_account: [u8; 32],
    destination_token_account: [u8; 32],
    mint: [u8; 32],
    token_program_id: [u8; 32],
    amount_atomic: u64,
    decimals: u8,
    recent_blockhash: [u8; 32],
) -> Result<Vec<u8>, String> {
    let token_program = Pubkey::new_from_array(token_program_id);
    let source = Pubkey::new_from_array(source_token_account);
    let mint_key = Pubkey::new_from_array(mint);
    let destination = Pubkey::new_from_array(destination_token_account);
    let authority = Pubkey::new_from_array(authority_pubkey);
    let fee_payer = Pubkey::new_from_array(fee_payer_pubkey);

    let ix_limit = ComputeBudgetInstruction::set_compute_unit_limit(COMPUTE_UNIT_LIMIT);
    let ix_price =
        ComputeBudgetInstruction::set_compute_unit_price(COMPUTE_UNIT_PRICE_MICROLAMPORTS);
    let ix_transfer = spl_token::instruction::transfer_checked(
        &token_program,
        &source,
        &mint_key,
        &destination,
        &authority,
        &[],
        amount_atomic,
        decimals,
    )
    .map_err(|e| format!("failed to build transfer_checked instruction: {e}"))?;

    let instructions = [ix_limit, ix_price, ix_transfer];
    let blockhash = Hash::new_from_array(recent_blockhash);
    let message = Message::new_with_blockhash(&instructions, Some(&fee_payer), &blockhash);

    // Never assume a fixed index for our own signer slot: when fee_payer
    // and authority are the same key (self-funded fallback), the *only*
    // slot is index 0; when they differ, ours is whichever index the
    // message compiler placed it at (index 1 in every case observed so
    // far, but this must never be hardcoded — see the sponsored-model test
    // below for what would happen if it silently weren't).
    let num_signers = message.header.num_required_signatures as usize;
    let our_index = message.account_keys[..num_signers]
        .iter()
        .position(|k| k.as_ref() == authority_pubkey.as_slice())
        .ok_or_else(|| {
            "internal: our authority key is not among the required signers".to_string()
        })?;

    let mut tx = Transaction::new_unsigned(message);
    let message_bytes = bincode::serialize(&tx.message)
        .map_err(|e| format!("internal: message serialize failed: {e}"))?;
    let sig_bytes = sign_message(authority_seed, &message_bytes);
    tx.signatures[our_index] = Signature::from(sig_bytes);

    bincode::serialize(&tx).map_err(|e| format!("internal: transaction serialize failed: {e}"))
}

/// Base64-encode the final transaction bytes for the x402 `PAYMENT-SIGNATURE`
/// payload's `transaction` field.
pub fn to_base64(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x402_settle::{session_key_pubkey, SPL_TOKEN_PROGRAM_ID};
    use solana_signature::Signature as SolSignature;

    fn pk(base58: &str) -> [u8; 32] {
        crate::x402_settle::decode_pubkey("test", base58).expect("valid test pubkey")
    }

    struct FixedAccounts {
        seed: [u8; 32],
        authority: [u8; 32],
        source: [u8; 32],
        destination: [u8; 32],
        mint: [u8; 32],
        program_id: [u8; 32],
    }

    fn fixed_accounts() -> FixedAccounts {
        let seed = [11u8; 32];
        FixedAccounts {
            seed,
            authority: session_key_pubkey(&seed),
            source: [1u8; 32],
            destination: [2u8; 32],
            mint: [5u8; 32],
            program_id: pk(SPL_TOKEN_PROGRAM_ID),
        }
    }

    fn decode_tx(bytes: &[u8]) -> Transaction {
        bincode::deserialize(bytes).expect("must decode as a Transaction")
    }

    #[test]
    fn self_funded_fallback_collapses_to_a_single_fully_signed_transaction() {
        let a = fixed_accounts();
        let blockhash = [4u8; 32];
        let tx_bytes = build_transfer_checked_transaction(
            &a.seed,
            a.authority,
            a.authority, // no server-provided fee payer: same key
            a.source,
            a.destination,
            a.mint,
            a.program_id,
            1_000_000,
            6,
            blockhash,
        )
        .expect("build must succeed");

        let tx = decode_tx(&tx_bytes);
        assert_eq!(
            tx.message.header.num_required_signatures, 1,
            "same fee payer and authority must dedup to one signer"
        );
        assert_ne!(
            tx.signatures[0],
            SolSignature::default(),
            "the single slot must be signed"
        );
    }

    #[test]
    fn sponsored_fee_payer_is_account_zero_and_stays_unsigned_by_us() {
        let a = fixed_accounts();
        let fee_payer = [99u8; 32]; // a different key: the "facilitator"
        let blockhash = [4u8; 32];
        let tx_bytes = build_transfer_checked_transaction(
            &a.seed,
            a.authority,
            fee_payer,
            a.source,
            a.destination,
            a.mint,
            a.program_id,
            1_000_000,
            6,
            blockhash,
        )
        .expect("build must succeed");

        let tx = decode_tx(&tx_bytes);
        assert_eq!(tx.message.header.num_required_signatures, 2);
        assert_eq!(
            tx.message.account_keys[0].as_ref(),
            fee_payer.as_slice(),
            "fee payer must be account index 0"
        );
        assert_eq!(
            tx.signatures[0],
            SolSignature::default(),
            "fee payer's slot must stay unsigned — only the facilitator may fill it in"
        );
        let our_index = tx.message.account_keys[..2]
            .iter()
            .position(|k| k.as_ref() == a.authority.as_slice())
            .expect("our authority must be among the required signers");
        assert_ne!(our_index, 0, "we must never occupy the fee payer's slot");
        assert_ne!(
            tx.signatures[our_index],
            SolSignature::default(),
            "our own slot must be signed"
        );
    }

    #[test]
    fn instructions_are_compute_budget_then_transfer_checked_in_order() {
        let a = fixed_accounts();
        let tx_bytes = build_transfer_checked_transaction(
            &a.seed,
            a.authority,
            a.authority,
            a.source,
            a.destination,
            a.mint,
            a.program_id,
            42,
            6,
            [4u8; 32],
        )
        .expect("build must succeed");

        let tx = decode_tx(&tx_bytes);
        assert_eq!(
            tx.message.instructions.len(),
            3,
            "compute limit + price + transfer"
        );
        let compute_budget_program = "ComputeBudget111111111111111111111111111111";
        let program_at = |ix_index: usize| {
            let program_index = tx.message.instructions[ix_index].program_id_index as usize;
            tx.message.account_keys[program_index].to_string()
        };
        assert_eq!(program_at(0), compute_budget_program);
        assert_eq!(program_at(1), compute_budget_program);
        assert_eq!(program_at(2), SPL_TOKEN_PROGRAM_ID);
    }

    #[test]
    fn signature_does_not_verify_against_a_tampered_message() {
        let a = fixed_accounts();
        let tx_bytes = build_transfer_checked_transaction(
            &a.seed,
            a.authority,
            a.authority,
            a.source,
            a.destination,
            a.mint,
            a.program_id,
            1_000_000,
            6,
            [4u8; 32],
        )
        .expect("build must succeed");
        let mut tampered = decode_tx(&tx_bytes);
        // Flip the amount encoded in the TransferChecked instruction data.
        let last_ix = tampered.message.instructions.last_mut().unwrap();
        let last_byte = last_ix.data.len() - 1;
        last_ix.data[last_byte] ^= 0xFF;

        use ed25519_dalek::{Verifier, VerifyingKey};
        let verifying_key = VerifyingKey::from_bytes(&a.authority).unwrap();
        let tampered_message_bytes = bincode::serialize(&tampered.message).unwrap();
        let sig = ed25519_dalek::Signature::from_bytes(
            tampered.signatures[0].as_ref().try_into().unwrap(),
        );
        assert!(
            verifying_key.verify(&tampered_message_bytes, &sig).is_err(),
            "signature must not verify once the message bytes are tampered with"
        );
    }

    #[test]
    fn to_base64_roundtrips() {
        let bytes = [0u8, 1, 2, 253, 254, 255];
        let encoded = to_base64(&bytes);
        use base64::Engine;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&encoded)
            .expect("must decode");
        assert_eq!(decoded, bytes);
    }
}

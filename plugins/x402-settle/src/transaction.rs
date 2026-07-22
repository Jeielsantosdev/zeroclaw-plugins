//! Manual Solana legacy transaction wire-format serialization — no
//! `solana-sdk`/`solana-client`, which do not target `wasm32-wasip2`.
//!
//! This is deliberately **not** a general-purpose transaction compiler. It
//! builds exactly one fixed shape: a single SPL Token `Transfer` instruction,
//! paid for and authorized by the same session key. Fewer degrees of freedom
//! here means fewer ways to get account ordering wrong — a genuinely
//! security-relevant simplification for a T2 component, not a shortcut.
//!
//! Fixed account order for this shape (Solana requires all signer accounts
//! before non-signer accounts, writable before read-only within each group):
//!
//! 1. `fee_payer` / transfer authority — signer, writable (index 0; the fee
//!    payer must be both signer and writable, since transaction fees debit
//!    its lamport balance)
//! 2. `source_token_account` — writable, non-signer
//! 3. `destination_token_account` — writable, non-signer
//! 4. SPL Token program ID — read-only, non-signer
//!
//! Message header is therefore always `(num_required_signatures: 1,
//! num_readonly_signed_accounts: 0, num_readonly_unsigned_accounts: 1)`.

use crate::x402_settle::{sign_message, SPL_TOKEN_TRANSFER_TAG};

/// Solana's "compact-u16" / shortvec length prefix: 7 bits per byte, MSB set
/// on every byte except the last. Every array length in this fixed shape
/// (1 signature, 4 account keys, 1 instruction, 3 instruction-account
/// indices, 9 bytes of instruction data) fits in a single byte, but the
/// encoder is written generally and tested at the multi-byte boundaries so
/// it is not just "happens to work for small numbers".
pub fn encode_shortvec_len(mut len: usize) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut byte = (len & 0x7f) as u8;
        len >>= 7;
        if len != 0 {
            byte |= 0x80;
            out.push(byte);
        } else {
            out.push(byte);
            break;
        }
    }
    out
}

/// Serialize the legacy `Message` (everything the signature covers) for the
/// fixed transfer shape described above. Returns the message bytes alone —
/// callers sign these bytes, then prepend the compact-array of signatures to
/// get the final transaction.
pub fn compile_transfer_message(
    fee_payer: [u8; 32],
    source_token_account: [u8; 32],
    destination_token_account: [u8; 32],
    token_program_id: [u8; 32],
    amount_atomic: u64,
    recent_blockhash: [u8; 32],
) -> Vec<u8> {
    let mut msg = Vec::new();

    // Message header.
    msg.push(1u8); // num_required_signatures
    msg.push(0u8); // num_readonly_signed_accounts
    msg.push(1u8); // num_readonly_unsigned_accounts

    // Account keys, compact array. Fixed order — see module docs.
    let account_keys = [
        fee_payer,
        source_token_account,
        destination_token_account,
        token_program_id,
    ];
    msg.extend_from_slice(&encode_shortvec_len(account_keys.len()));
    for key in &account_keys {
        msg.extend_from_slice(key);
    }

    // Recent blockhash.
    msg.extend_from_slice(&recent_blockhash);

    // Instructions, compact array — exactly one: the SPL Token Transfer.
    msg.extend_from_slice(&encode_shortvec_len(1));
    // program_id_index: index 3 in account_keys (the token program).
    msg.push(3u8);
    // account indices referenced by this instruction, in the order the SPL
    // Token program expects for Transfer: [source, destination, owner].
    let instruction_accounts: [u8; 3] = [1, 2, 0];
    msg.extend_from_slice(&encode_shortvec_len(instruction_accounts.len()));
    msg.extend_from_slice(&instruction_accounts);
    // instruction data: tag (3 = Transfer) + amount as u64 little-endian.
    let mut data = Vec::with_capacity(9);
    data.push(SPL_TOKEN_TRANSFER_TAG);
    data.extend_from_slice(&amount_atomic.to_le_bytes());
    msg.extend_from_slice(&encode_shortvec_len(data.len()));
    msg.extend_from_slice(&data);

    msg
}

/// Compile the message, sign it with the session key, and assemble the final
/// transaction wire bytes: compact-array-of-signatures followed by the
/// message. `fee_payer_seed` is the session key's 32-byte ed25519 seed —
/// the fee payer, transfer authority, and signer are always this same key
/// in this fixed shape; there is no code path for a different signer.
pub fn build_signed_transaction(
    fee_payer_seed: &[u8; 32],
    fee_payer_pubkey: [u8; 32],
    source_token_account: [u8; 32],
    destination_token_account: [u8; 32],
    token_program_id: [u8; 32],
    amount_atomic: u64,
    recent_blockhash: [u8; 32],
) -> Vec<u8> {
    let message = compile_transfer_message(
        fee_payer_pubkey,
        source_token_account,
        destination_token_account,
        token_program_id,
        amount_atomic,
        recent_blockhash,
    );
    let signature = sign_message(fee_payer_seed, &message);

    let mut tx = Vec::with_capacity(1 + 64 + message.len());
    tx.extend_from_slice(&encode_shortvec_len(1)); // one signature
    tx.extend_from_slice(&signature);
    tx.extend_from_slice(&message);
    tx
}

/// Base64-encode the final transaction bytes for the x402 `X-Payment`
/// payload's `serializedTransaction` field.
pub fn to_base64(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x402_settle::session_key_pubkey;

    #[test]
    fn shortvec_encodes_single_byte_values() {
        assert_eq!(encode_shortvec_len(0), vec![0x00]);
        assert_eq!(encode_shortvec_len(1), vec![0x01]);
        assert_eq!(encode_shortvec_len(127), vec![0x7f]);
    }

    #[test]
    fn shortvec_encodes_two_byte_boundary() {
        // 128 = 0b1000_0000 -> low 7 bits = 0, continuation set, then 1.
        assert_eq!(encode_shortvec_len(128), vec![0x80, 0x01]);
        assert_eq!(encode_shortvec_len(16383), vec![0xff, 0x7f]);
    }

    #[test]
    fn shortvec_encodes_three_byte_boundary() {
        assert_eq!(encode_shortvec_len(16384), vec![0x80, 0x80, 0x01]);
    }

    struct FixedAccounts {
        seed: [u8; 32],
        fee_payer: [u8; 32],
        source: [u8; 32],
        destination: [u8; 32],
        program_id: [u8; 32],
    }

    fn fixed_accounts() -> FixedAccounts {
        let seed = [11u8; 32];
        FixedAccounts {
            seed,
            fee_payer: session_key_pubkey(&seed),
            source: [1u8; 32],
            destination: [2u8; 32],
            program_id: [3u8; 32],
        }
    }

    #[test]
    fn compiled_message_has_correct_header_and_account_order() {
        let a = fixed_accounts();
        let blockhash = [4u8; 32];
        let msg = compile_transfer_message(
            a.fee_payer,
            a.source,
            a.destination,
            a.program_id,
            1_000_000,
            blockhash,
        );

        assert_eq!(
            &msg[0..3],
            &[1, 0, 1],
            "header: 1 required sig, 0 readonly-signed, 1 readonly-unsigned"
        );
        assert_eq!(msg[3], 4, "compact array len for 4 account keys");
        assert_eq!(&msg[4..36], &a.fee_payer, "account 0 must be the fee payer");
        assert_eq!(
            &msg[36..68],
            &a.source,
            "account 1 must be the source token account"
        );
        assert_eq!(
            &msg[68..100],
            &a.destination,
            "account 2 must be the destination token account"
        );
        assert_eq!(
            &msg[100..132],
            &a.program_id,
            "account 3 must be the token program"
        );
        assert_eq!(
            &msg[132..164],
            &blockhash,
            "recent blockhash follows the account keys"
        );
    }

    #[test]
    fn compiled_message_instruction_references_correct_indices_and_data() {
        let a = fixed_accounts();
        let blockhash = [4u8; 32];
        let msg = compile_transfer_message(
            a.fee_payer,
            a.source,
            a.destination,
            a.program_id,
            42,
            blockhash,
        );

        // offset 164: compact array len of instructions (1)
        let mut i = 164;
        assert_eq!(msg[i], 1, "exactly one instruction");
        i += 1;
        assert_eq!(msg[i], 3, "program_id_index must point at account index 3");
        i += 1;
        assert_eq!(msg[i], 3, "instruction references exactly 3 accounts");
        i += 1;
        assert_eq!(
            &msg[i..i + 3],
            &[1, 2, 0],
            "account indices: source, destination, owner"
        );
        i += 3;
        assert_eq!(msg[i], 9, "instruction data is 9 bytes");
        i += 1;
        assert_eq!(msg[i], SPL_TOKEN_TRANSFER_TAG);
        assert_eq!(&msg[i + 1..i + 9], &42u64.to_le_bytes());
        assert_eq!(
            msg.len(),
            i + 9,
            "no trailing bytes beyond the instruction data"
        );
    }

    #[test]
    fn signed_transaction_signature_verifies_against_the_message_bytes() {
        use ed25519_dalek::{Verifier, VerifyingKey};

        let a = fixed_accounts();
        let blockhash = [7u8; 32];
        let tx = build_signed_transaction(
            &a.seed,
            a.fee_payer,
            a.source,
            a.destination,
            a.program_id,
            500_000,
            blockhash,
        );

        // tx = [sig_count_prefix(1 byte for count=1)] [64-byte signature] [message...]
        assert_eq!(tx[0], 1, "compact array len prefix for one signature");
        let signature_bytes: [u8; 64] = tx[1..65].try_into().unwrap();
        let message_bytes = &tx[65..];

        let expected_message = compile_transfer_message(
            a.fee_payer,
            a.source,
            a.destination,
            a.program_id,
            500_000,
            blockhash,
        );
        assert_eq!(message_bytes, expected_message.as_slice());

        let verifying_key = VerifyingKey::from_bytes(&a.fee_payer)
            .expect("fee payer must be a valid ed25519 point");
        let signature = ed25519_dalek::Signature::from_bytes(&signature_bytes);
        verifying_key
            .verify(message_bytes, &signature)
            .expect("signature must verify against the exact message bytes it signed");
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

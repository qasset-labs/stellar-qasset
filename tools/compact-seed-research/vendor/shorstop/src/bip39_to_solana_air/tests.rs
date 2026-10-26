//! Unit tests for the BIP-39 → Solana composition AIR.

#![cfg(test)]

use p3_field::PrimeField32;

use crate::bip39_to_solana_air::generation::generate_bip39_to_solana_witness;
use crate::Val;

#[test]
fn witness_pv_concatenates_address_pq_blockhash() {
    let mut address = [0u8; 32];
    let mut pq = [0u8; 32];
    let mut blockhash = [0u8; 32];
    for i in 0..32 {
        address[i] = (i as u8).wrapping_mul(17).wrapping_add(3);
        pq[i] = (i as u8).wrapping_mul(31).wrapping_add(7);
        blockhash[i] = (i as u8).wrapping_mul(53).wrapping_add(11);
    }
    let witness = generate_bip39_to_solana_witness::<Val>(&address, &pq, &blockhash);
    assert_eq!(witness.bip39_to_solana_pv.len(), 96);

    // PV layout: [solana_address (32) || pq_destination (32) || blockhash (32)].
    for byte_index in 0..32 {
        assert_eq!(
            witness.bip39_to_solana_pv[byte_index].as_canonical_u32(),
            address[byte_index] as u32,
        );
        assert_eq!(
            witness.bip39_to_solana_pv[32 + byte_index].as_canonical_u32(),
            pq[byte_index] as u32,
        );
        assert_eq!(
            witness.bip39_to_solana_pv[64 + byte_index].as_canonical_u32(),
            blockhash[byte_index] as u32,
        );
    }
}

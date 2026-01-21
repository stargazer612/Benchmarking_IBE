use crate::{FieldElement, GTElement};
use ark_bls12_381::{Bls12_381, G1Projective as G1, G2Projective as G2};
use ark_ec::{PrimeGroup, pairing::Pairing};
use bit_vec::BitVec;

pub fn f_i(i: usize, l: usize, message: &[u8]) -> u8 {
    if i < 2 {
        return 0;
    }

    let bit_index = (i - 2) / 2;
    let bit_value = (i - 2) % 2;

    if bit_index >= l || bit_index >= message.len() * 8 {
        return 0;
    }

    let msg = BitVec::from_bytes(message);
    // Original code accesses bits of each byte from LSB to MSB
    // BitVec access bits of each byte from MSB to LSB
    // This idx maps between both to keep original behavior
    let idx = (bit_index / 8) * 8 + (7 - bit_index % 8);
    let message_bit = msg[idx] as usize;

    if message_bit == bit_value { 1 } else { 0 }
}

pub fn f_prime_i(i: usize) -> u8 {
    if i == 0 { 1 } else { 0 }
}

pub fn scalar_mul_g1(s: FieldElement) -> G1 {
    G1::generator() * s
}

pub fn scalar_mul_g2(s: FieldElement) -> G2 {
    G2::generator() * s
}

pub fn pairing(g1: &G1, g2: &G2) -> GTElement {
    Bls12_381::pairing(g1, g2).0
}

pub fn multi_pairing(pairs: &[(G1, G2)]) -> GTElement {
    let g1s = pairs.iter().map(|(g1, _)| g1);
    let g2s = pairs.iter().map(|(_, g2)| g2);
    Bls12_381::multi_pairing(g1s, g2s).0
}

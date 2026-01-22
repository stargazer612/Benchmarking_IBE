use crate::{FieldElement, GTElement};
use ark_bls12_381::{Bls12_381, G1Projective as G1, G2Projective as G2};
use ark_ec::{PrimeGroup, pairing::Pairing};

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

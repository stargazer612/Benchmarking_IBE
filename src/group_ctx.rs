use ark_bls12_381::{Bls12_381, G1Projective as G1, G2Projective as G2};
use ark_ec::PrimeGroup;
use ark_ec::pairing::Pairing;

use crate::{FieldElement, GTElement};

pub struct GroupCtx {
    pub g1: G1,
    pub g2: G2,
    pub gt: GTElement,
}

impl GroupCtx {
    pub fn bls12_381() -> Self {
        let g1 = G1::generator();
        let g2 = G2::generator();
        let gt = Bls12_381::pairing(g1, g2).0;
        Self { g1, g2, gt }
    }

    pub fn scalar_mul_p1(&self, s: FieldElement) -> G1 {
        self.g1 * s
    }

    pub fn scalar_mul_p2(&self, s: FieldElement) -> G2 {
        self.g2 * s
    }

    pub fn scalar_expo_gt(&self, _: FieldElement) -> GTElement {
        panic!("Unreachable");
    }

    pub fn pairing(&self, g1: &G1, g2: &G2) -> GTElement {
        Bls12_381::pairing(g1, g2).0
    }

    pub fn multi_pairing(&self, pairs: &[(G1, G2)]) -> GTElement {
        let g1s = pairs.iter().map(|(g1, _)| g1);
        let g2s = pairs.iter().map(|(_, g2)| g2);
        Bls12_381::multi_pairing(g1s, g2s).0
    }
}

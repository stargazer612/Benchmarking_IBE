use ark_bls12_381::{Bls12_381, G1Affine, G1Projective as G1, G2Affine, G2Projective as G2};
use ark_ec::{PairingEngine, ProjectiveCurve};
use ark_ff::{Field, PrimeField};

use crate::{FieldElement, GTElement};

pub struct GroupCtx {
    pub p1: G1,
    pub p2: G2,
    pub pt: GTElement,
}

impl GroupCtx {
    pub fn bls12_381() -> Self {
        let p1 = G1::prime_subgroup_generator();
        let p2 = G2::prime_subgroup_generator();
        //pt = e(p1,p2)
        let g1_affine: G1Affine = p1.into_affine();
        let g2_affine: G2Affine = p2.into_affine();
        let pt = Bls12_381::pairing(g1_affine, g2_affine);
        Self { p1, p2, pt }
    }

    pub fn scalar_mul_p1(&self, s: FieldElement) -> G1 {
        self.p1.mul(s.into_repr())
    }

    pub fn scalar_mul_p2(&self, s: FieldElement) -> G2 {
        self.p2.mul(s.into_repr())
    }

    pub fn scalar_expo_gt(&self, s: FieldElement) -> GTElement {
        // e(p1,p2)^s = pt^s
        self.pt.pow(s.into_repr())
    }

    pub fn pairing(&self, g1_elem: &G1, g2_elem: &G2) -> GTElement {
        let g1_affine: G1Affine = g1_elem.into_affine();
        let g2_affine: G2Affine = g2_elem.into_affine();
        Bls12_381::pairing(g1_affine, g2_affine)
    }

    pub fn multi_pairing(&self, pairs: &[(G1, G2)]) -> GTElement {
        let prepared_pairs: Vec<_> = pairs
            .iter()
            .map(|(g1, g2)| {
                (
                    <Bls12_381 as PairingEngine>::G1Prepared::from(g1.into_affine()),
                    <Bls12_381 as PairingEngine>::G2Prepared::from(g2.into_affine()),
                )
            })
            .collect();
        Bls12_381::product_of_pairings(prepared_pairs.iter())
    }
}

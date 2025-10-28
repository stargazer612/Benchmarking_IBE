use ark_bls12_381::{Bls12_381, Fq12 as Gt, Fr, G1Projective as G1, G2Projective as G2};
use ark_ec::PrimeGroup;
use ark_ec::pairing::Pairing;
use ark_ff::{One, PrimeField, UniformRand, Zero};
use ark_std::rand::Rng;

pub struct MSK {
    pub alpha: Fr,
    pub b: Fr,
    pub b_0: Fr,
    pub b_1: Fr,
}

pub struct MPK {
    pub a: Gt,
    pub b_g1: G1,
    pub b_g2: G2,
    pub b_0_g1: G1,
    pub b_0_g2: G2,
    pub b_1_g1: G1,
    pub b_1_g2: G2,
}

pub struct LW {}

impl LW {
    pub fn setup(&self, mut rng: impl Rng) -> (MSK, MPK) {
        let alpha = Fr::rand(&mut rng);
        let b = Fr::rand(&mut rng);
        let b_0 = Fr::rand(&mut rng);
        let b_1 = Fr::rand(&mut rng);
        let msk = MSK { alpha, b, b_0, b_1 };

        let g1 = G1::generator();
        let g2 = G2::generator();
        let a = Bls12_381::pairing(g1 * alpha, g2).0;

        let b_g1 = g1 * b;
        let b_g2 = g2 * b;
        let b_0_g1 = g1 * b_0;
        let b_0_g2 = g2 * b_0;
        let b_1_g1 = g1 * b_1;
        let b_1_g2 = g2 * b_1;

        let mpk = MPK {
            a,
            b_g1,
            b_g2,
            b_0_g1,
            b_0_g2,
            b_1_g1,
            b_1_g2,
        };

        (msk, mpk)
    }
}

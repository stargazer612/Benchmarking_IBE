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

pub struct USK {
    pub identity: Vec<String>,
    pub k: Vec<G2>,
    pub k_1: Vec<G2>,
    pub k_2: Vec<G2>,
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

    pub fn keygen(&self, mut rng: impl Rng, msk: &MSK, identity: Vec<String>) -> USK {
        let n_k = identity.len();
        assert!(n_k > 0);

        let g2 = G2::generator();

        let mut k = Vec::with_capacity(n_k);
        let mut k_1 = Vec::with_capacity(n_k);
        let mut k_2 = Vec::with_capacity(n_k);

        let mut rs = Vec::with_capacity(n_k);
        for _ in 0..n_k {
            let r_i = Fr::rand(&mut rng);
            rs.push(r_i);
            k.push(g2 * r_i);
        }

        let mut lambdas = Vec::with_capacity(n_k);
        let mut sum = Fr::zero();
        lambdas.push(Fr::zero());
        for _ in 1..n_k {
            let lambda_i = Fr::rand(&mut rng);
            sum += lambda_i;
        }
        lambdas[0] = msk.alpha - sum;

        for i in 0..n_k {
            let e_1 = lambdas[i] + rs[i] * msk.b;
            k_1.push(g2 * e_1);

            // TODO: properly hash id_i to G2
            let xid = Fr::rand(&mut rng);
            let e_2 = rs[i] * (msk.b_0 + xid * msk.b_1);
            k_2.push(g2 * e_2);
        }

        USK {
            identity: identity.clone(),
            k,
            k_1,
            k_2,
        }
    }
}

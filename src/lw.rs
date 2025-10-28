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

pub struct CT {
    pub k: Gt,
    pub c: G1,
    pub c_i: Vec<G1>,
    pub c_i_alt: Vec<G1>,
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

    pub fn encrypt(&self, mut rng: impl Rng, mpk: &MPK, identity: Vec<String>) -> CT {
        let n_c = identity.len();
        assert!(n_c > 0);

        let g1 = G1::generator();
        let s = Fr::rand(&mut rng);
        let c = g1 * s;

        let mut c_i = Vec::with_capacity(n_c);
        let mut c_i_alt = Vec::with_capacity(n_c);

        let mut ss = Vec::with_capacity(n_c);
        for _ in 0..n_c {
            let s_i = Fr::rand(&mut rng);
            ss.push(s_i);
            c_i_alt.push(g1 * s);
        }

        for i in 0..n_c {
            // TODO: properly hash id_i to G1
            let xid = Fr::rand(&mut rng);
            let e = ss[i] * xid;

            let c_1 = mpk.b_g1 * s;
            let c_2 = mpk.b_0_g1 * ss[i];
            let c_3 = mpk.b_1_g1 * e;

            c_i.push(c_1 + c_2 + c_3);
        }

        CT {
            // TODO: probably this should be the masked payload instead
            k: mpk.a,
            c,
            c_i,
            c_i_alt,
        }
    }
}

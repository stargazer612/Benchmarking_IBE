use ark_bls12_381::{Bls12_381, Fq12 as Gt, Fr, G1Projective as G1, G2Projective as G2};
use ark_ec::PrimeGroup;
use ark_ec::pairing::Pairing;
use ark_ff::{Field, PrimeField, UniformRand};
use ark_std::rand::Rng;

use super::IBEScheme;

use crate::hash_to_fr;

pub struct MSK {
    alpha: Fr,
    b_0: Fr,
    b_1: Fr,
}

pub struct MPK {
    a: Gt,
    b_0: G1,
    b_1: G1,
}

pub struct USK {
    pub identity: String,
    r: G2,
    k: G2,
}

pub struct CT {
    pub identity: String,
    msg: Gt,
    s: G1,
    c: G1,
}

pub struct BB {}

impl BB {
    pub fn new() -> BB {
        Self {}
    }
}

impl IBEScheme for BB {
    type MPK = MPK;
    type MSK = MSK;
    type USK = USK;
    type CT = CT;

    fn name(&self) -> String {
        String::from("bb")
    }

    fn setup(&self, mut rng: impl Rng) -> (MSK, MPK) {
        let alpha = Fr::rand(&mut rng);
        let b_0 = Fr::rand(&mut rng);
        let b_1 = Fr::rand(&mut rng);
        let msk = MSK { alpha, b_0, b_1 };

        let g1 = G1::generator();
        let g2 = G2::generator();

        let mpk = MPK {
            a: Bls12_381::pairing(g1 * alpha, g2).0,
            b_0: g1 * b_0,
            b_1: g1 * b_1,
        };

        (msk, mpk)
    }

    fn keygen(&self, mut rng: impl Rng, msk: &MSK, identity: String) -> USK {
        let g2 = G2::generator();
        let r = Fr::rand(&mut rng);
        let xid = hash_to_fr(&identity);

        USK {
            identity: identity,
            r: g2 * r,
            k: g2 * (msk.alpha + r * (msk.b_0 + xid * msk.b_1)),
        }
    }

    fn encrypt(&self, mut rng: impl Rng, msg: &Gt, mpk: &MPK, identity: String) -> CT {
        let g1 = G1::generator();

        let s = Fr::rand(&mut rng);
        let xid = hash_to_fr(&identity);

	// Unexpectedly, a VariableBaseMSM here is slightly slower than the naive computation
        let c = mpk.b_0 * s + mpk.b_1 * (s * xid);

        CT {
            identity: identity,
            msg: mpk.a.pow(s.into_bigint()) * msg,
            s: g1 * s,
            c,
        }
    }

    fn decrypt(&self, usk: &USK, ct: &CT) -> Option<Gt> {
        if &usk.identity != &ct.identity {
            return None;
        }

        let result = Bls12_381::multi_pairing([ct.s, -ct.c], [usk.k, usk.r]).0;
        Some(ct.msg / result)
    }
}

use ark_bls12_381::{Bls12_381, Fq12 as Gt, Fr, G1Projective as G1, G2Projective as G2};
use ark_ec::PrimeGroup;
use ark_ec::pairing::Pairing;
use ark_ff::{Field, PrimeField, UniformRand};
use ark_std::rand::Rng;

use crate::hash_to_fr;

pub struct MSK {
    pub alpha: Fr,
    pub b_0: Fr,
    pub b_1: Fr,
}

pub struct MPK {
    pub a: Gt,
    pub b_0_g1: G1,
    pub b_0_g2: G2,
    pub b_1_g1: G1,
    pub b_1_g2: G2,
}

pub struct USK {
    pub identity: String,
    pub r: G2,
    pub k: G2,
}

pub struct CT {
    pub identity: String,
    pub msg: Gt,
    pub s: G1,
    pub c: G1,
}

pub struct BB {}

impl BB {
    pub fn new() -> BB {
        Self {}
    }

    pub fn setup(&self, mut rng: impl Rng) -> (MSK, MPK) {
        let alpha = Fr::rand(&mut rng);
        let b_0 = Fr::rand(&mut rng);
        let b_1 = Fr::rand(&mut rng);
        let msk = MSK { alpha, b_0, b_1 };

        let g1 = G1::generator();
        let g2 = G2::generator();

        let mpk = MPK {
            a: Bls12_381::pairing(g1 * alpha, g2).0,
            b_0_g1: g1 * b_0,
            b_0_g2: g2 * b_0,
            b_1_g1: g1 * b_1,
            b_1_g2: g2 * b_1,
        };

        (msk, mpk)
    }

    pub fn keygen(&self, mut rng: impl Rng, msk: &MSK, identity: String) -> USK {
        let g2 = G2::generator();
        let r = Fr::rand(&mut rng);
        let xid = hash_to_fr(&identity);

        USK {
            identity: identity.clone(),
            r: g2 * r,
            k: g2 * (msk.alpha + r * (msk.b_0 + xid * msk.b_1)),
        }
    }

    pub fn encrypt(&self, mut rng: impl Rng, msg: &Gt, mpk: &MPK, identity: String) -> CT {
        let g1 = G1::generator();

        let s = Fr::rand(&mut rng);
        let xid = hash_to_fr(&identity);

        CT {
            identity: identity.clone(),
            msg: mpk.a.pow(s.into_bigint()) * msg,
            s: g1 * s,
            c: mpk.b_0_g1 * s + mpk.b_1_g1 * (s * xid),
        }
    }

    pub fn decrypt(&self, usk: &USK, ct: &CT) -> Option<Gt> {
        if &usk.identity != &ct.identity {
            return None;
        }

        let result = Bls12_381::pairing(ct.s, usk.k).0 * Bls12_381::pairing(-ct.c, usk.r).0;
        Some(ct.msg / result)
    }
}

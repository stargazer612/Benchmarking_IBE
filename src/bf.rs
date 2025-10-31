use ark_bls12_381::{Bls12_381, Fq12 as Gt, Fr, G1Projective as G1, G2Projective as G2};
use ark_ec::PrimeGroup;
use ark_ec::pairing::Pairing;
use ark_ff::{Field, PrimeField, UniformRand};
use ark_std::rand::Rng;

use crate::hash_to_fr;

pub struct MSK {
    pub alpha: Fr,
}

pub struct MPK {
    pub a: Gt,
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

pub struct BF {}

impl BF {
    pub fn new() -> BF {
        Self {}
    }

    pub fn setup(&self, mut rng: impl Rng) -> (MSK, MPK) {
        let alpha = Fr::rand(&mut rng);
        let msk = MSK { alpha };

        let g1 = G1::generator();
        let g2 = G2::generator();

        let mpk = MPK {
            a: Bls12_381::pairing(g1 * alpha, g2).0,
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
            k: g2 * (msk.alpha + r * xid),
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
            c: g1 * (s * xid),
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

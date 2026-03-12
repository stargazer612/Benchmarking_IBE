use ark_bls12_381::{Bls12_381, Fq12 as Gt, Fr, G1Projective as G1, G2Projective as G2};
use ark_ec::PrimeGroup;
use ark_ec::pairing::Pairing;
use ark_ff::{PrimeField, UniformRand};
use ark_std::rand::Rng;

use crate::{gt_gen::gt_gen, hash_to_g1, pes::IBEScheme, scalar_mul::k_ary_gt};

pub struct MSK {
    pub alpha: Fr,
}

pub struct MPK {
    pub a: Gt,
}

pub struct USK {
    pub identity: String,
    pub r: G2,
    pub k: G1,
}

pub struct CT {
    pub identity: String,
    pub msg: Gt,
    pub s: G2,
    pub c: G1,
}

pub struct BF {}

impl BF {
    pub fn new() -> BF {
        Self {}
    }
}

impl IBEScheme for BF {
    type MPK = MPK;
    type MSK = MSK;
    type USK = USK;
    type CT = CT;

    fn name(&self) -> String {
        String::from("bf")
    }

    fn setup(&self, mut rng: impl Rng) -> (MSK, MPK) {
        let alpha = Fr::rand(&mut rng);
        let msk = MSK { alpha };

        let mpk = MPK {
            a: k_ary_gt(gt_gen(), alpha.into_bigint()),
        };

        (msk, mpk)
    }

    fn keygen(&self, mut rng: impl Rng, msk: &MSK, identity: String) -> USK {
        let g1 = G1::generator();
        let g2 = G2::generator();
        let r = Fr::rand(&mut rng);
        let bid = hash_to_g1(&identity);

        // Unexpectedly, a VariableBaseMSM here is slightly slower than the naive computation
        let k = g1 * msk.alpha + bid * r;

        USK {
            identity: identity,
            r: g2 * r,
            k,
        }
    }

    fn encrypt(&self, mut rng: impl Rng, msg: &Gt, mpk: &MPK, identity: String) -> CT {
        let g2 = G2::generator();

        let s = Fr::rand(&mut rng);
        let bid = hash_to_g1(&identity);

        CT {
            identity: identity,
            msg: k_ary_gt(mpk.a, s.into_bigint()) * msg,
            s: g2 * s,
            c: bid * s,
        }
    }

    fn decrypt(&self, usk: &USK, ct: &CT) -> Option<Gt> {
        if &usk.identity != &ct.identity {
            return None;
        }

        let result = Bls12_381::multi_pairing([usk.k, -ct.c], [ct.s, usk.r]).0;
        Some(ct.msg / result)
    }
}

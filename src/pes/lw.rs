use ark_bls12_381::{Bls12_381, Fq12 as Gt, Fr, G1Projective as G1, G2Projective as G2};
use ark_ec::PrimeGroup;
use ark_ec::pairing::Pairing;
use ark_ff::{Field, PrimeField, UniformRand, Zero};
use ark_std::rand::Rng;

use crate::hash_to_fr;

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
    pub identity: Vec<String>,
    pub msg: Gt,
    pub c: G1,
    pub c_i: Vec<G1>,
    pub c_i_alt: Vec<G1>,
}

pub struct LW {}

impl LW {
    pub fn new() -> LW {
        Self {}
    }

    pub fn setup(&self, mut rng: impl Rng) -> (MSK, MPK) {
        let alpha = Fr::rand(&mut rng);
        let b = Fr::rand(&mut rng);
        let b_0 = Fr::rand(&mut rng);
        let b_1 = Fr::rand(&mut rng);
        let msk = MSK { alpha, b, b_0, b_1 };

        let g1 = G1::generator();
        let g2 = G2::generator();

        let mpk = MPK {
            a: Bls12_381::pairing(g1 * alpha, g2).0,
            b_g1: g1 * b,
            b_g2: g2 * b,
            b_0_g1: g1 * b_0,
            b_0_g2: g2 * b_0,
            b_1_g1: g1 * b_1,
            b_1_g2: g2 * b_1,
        };

        (msk, mpk)
    }

    pub fn keygen(&self, mut rng: impl Rng, msk: &MSK, identity: Vec<String>) -> USK {
        let n_k = identity.len();
        assert!(n_k > 0);

        let g2 = G2::generator();
        let rs = sample_fr(&mut rng, n_k);
        let lambdas = share_secret(&mut rng, msk.alpha, n_k);

        let k = rs.iter().map(|r| g2 * r).collect();

        let mut k_1 = Vec::with_capacity(n_k);
        for i in 0..n_k {
            let e = lambdas[i] + rs[i] * msk.b;
            k_1.push(g2 * e);
        }

        let mut k_2 = Vec::with_capacity(n_k);
        for i in 0..n_k {
            let xid = hash_to_fr(&identity[i]);
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

    pub fn encrypt(&self, mut rng: impl Rng, msg: &Gt, mpk: &MPK, identity: Vec<String>) -> CT {
        let n_c = identity.len();
        assert!(n_c > 0);

        let g1 = G1::generator();
        let s = Fr::rand(&mut rng);
        let ss = sample_fr(&mut rng, n_c);

        let c_i_alt = ss.iter().map(|s| g1 * s).collect();

        let mut c_i = Vec::with_capacity(n_c);
        for i in 0..n_c {
            let xid = hash_to_fr(&identity[i]);
            c_i.push(mpk.b_g1 * s + (mpk.b_0_g1 + mpk.b_1_g1 * xid) * ss[i]);
        }

        CT {
            identity: identity.clone(),
            msg: mpk.a.pow(s.into_bigint()) * msg,
            c: g1 * s,
            c_i,
            c_i_alt,
        }
    }

    pub fn delegate(
        &self,
        mut rng: impl Rng,
        mpk: &MPK,
        usk: &USK,
        identity: Vec<String>,
        identity_extension: String,
    ) -> USK {
        let n_k = identity.len();
        assert!(n_k > 0);

        let lambdas = sample_fr(&mut rng, n_k);
        let rs = sample_fr(&mut rng, n_k + 1);

        let mut new_identity = identity.clone();
        new_identity.push(identity_extension.clone());

        let new_k = update_k(&usk, &rs);
        let new_k1 = update_k1(&mpk, &usk, &rs, &lambdas);
        let new_k2 = update_k2(&mpk, &usk, &rs, &new_identity, &identity_extension);

        USK {
            identity: new_identity,
            k: new_k,
            k_1: new_k1,
            k_2: new_k2,
        }
    }

    pub fn decrypt(&self, usk: &USK, ct: &CT) -> Option<Gt> {
        let n_k = usk.identity.len();
        assert!(n_k > 0);

        if !can_decrypt(&usk.identity, &ct.identity) {
            return None;
        }

        let sum: G2 = usk.k_1.iter().sum();
        let mut result = Bls12_381::pairing(ct.c, sum).0;

        for i in 0..n_k {
            result *= Bls12_381::pairing(-ct.c_i[i], usk.k[i]).0;
            result *= Bls12_381::pairing(ct.c_i_alt[i], usk.k_2[i]).0;
        }

        Some(ct.msg / result)
    }
}

fn sample_fr(mut rng: impl Rng, n: usize) -> Vec<Fr> {
    let mut result = Vec::with_capacity(n);
    for _ in 0..n {
        result.push(Fr::rand(&mut rng));
    }
    result
}

fn share_secret(mut rng: impl Rng, secret: Fr, n: usize) -> Vec<Fr> {
    let mut shares = Vec::with_capacity(n);
    let mut sum = Fr::zero();
    shares.push(Fr::zero());
    for _ in 1..n {
        let share_i = Fr::rand(&mut rng);
        sum += share_i;
        shares.push(share_i);
    }
    shares[0] = secret - sum;
    shares
}

fn can_decrypt(key: &Vec<String>, ct: &Vec<String>) -> bool {
    let is_shorter = key.len() <= ct.len();
    let prefix_matches = key.iter().zip(ct.iter()).all(|(x, y)| x == y);
    is_shorter && prefix_matches
}

fn update_k(usk: &USK, rs: &Vec<Fr>) -> Vec<G2> {
    let g2 = G2::generator();
    let mut new_k = usk.k.clone();
    let n_k = new_k.len();
    for i in 0..n_k {
        new_k[i] = new_k[i] + g2 * rs[i];
    }
    new_k.push(g2 * rs[n_k]);
    new_k
}

fn update_k1(mpk: &MPK, usk: &USK, rs: &Vec<Fr>, lambdas: &Vec<Fr>) -> Vec<G2> {
    let g2 = G2::generator();
    let sum: Fr = lambdas.iter().sum();
    let mut new_k1 = usk.k_1.clone();
    let n_k = new_k1.len();
    for i in 0..n_k {
        let k_1 = new_k1[i];
        let k_2 = g2 * lambdas[i];
        let k_3 = mpk.b_g2 * rs[i];
        new_k1[i] = k_1 + k_2 + k_3;
    }
    new_k1.push(g2 * (-sum) + mpk.b_g2 * rs[n_k]);
    new_k1
}

fn update_k2(
    mpk: &MPK,
    usk: &USK,
    rs: &Vec<Fr>,
    new_identity: &Vec<String>,
    identity_extension: &String,
) -> Vec<G2> {
    let mut new_k2 = usk.k_2.clone();
    let n_k = new_k2.len();
    for i in 0..n_k {
        let k_1 = new_k2[i];
        let k_2 = mpk.b_0_g2 * rs[i];
        let xid = hash_to_fr(&new_identity[i]);
        let k_3 = mpk.b_1_g2 * (xid * rs[i]);
        new_k2[i] = k_1 + k_2 + k_3;
    }
    let tmp1 = mpk.b_0_g2 * rs[n_k];
    let xid = hash_to_fr(&identity_extension);
    let tmp2 = mpk.b_1_g2 * (xid * rs[n_k]);
    new_k2.push(tmp1 + tmp2);
    new_k2
}

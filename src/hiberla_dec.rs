use ark_bls12_381::{Bls12_381, Fq12 as Gt, Fr, G1Affine, G1Projective as G1, G2Projective as G2};
use ark_ec::pairing::Pairing;
use ark_ec::{PrimeGroup, VariableBaseMSM};
use ark_ff::{Field, PrimeField, UniformRand, Zero};
use ark_std::rand::Rng;

use crate::{hash_to_fr, hash_to_g1};

pub struct MSK {
    pub alpha: Fr,
}

pub struct MPK {
    pub a: Gt,
}

pub struct USK {
    pub identity: Vec<String>,
    pub k_1: G1,
    pub k_2_0: Vec<G1>,
    pub k_2_1: Vec<G1>,
    pub k_check: Vec<G2>,
}

pub struct CT {
    pub identity: Vec<String>,
    pub msg: Gt,
    pub c: G2,
    pub c_i: Vec<G1>,
}

pub struct HiberlaDec {
    pub l: usize, // partition size
}

impl HiberlaDec {
    pub fn new(l: usize) -> HiberlaDec {
        Self { l }
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

    pub fn keygen(&self, mut rng: impl Rng, msk: &MSK, identity: Vec<String>) -> USK {
        let n_k = identity.len();
        assert!(n_k > 0);

        let m_k = ceil_div(n_k, self.l);
        let rs = sample_fr(&mut rng, m_k);

        let mut k_1 = G1::generator() * msk.alpha;
        for i in 0..n_k {
            let r = rs[self.iota(i)];
            let xid = hash_to_fr(&identity[i]);
            let b_i_0 = hash_common_var(i, 0);
            let b_i_1 = hash_common_var(i, 1);
            let tmp: G1 = VariableBaseMSM::msm(&[b_i_0, b_i_1], &[r, r * xid]).unwrap();
            k_1 += tmp;
        }

        let cap = self.l * m_k - n_k;
        let mut k_2_0 = Vec::with_capacity(cap);
        let mut k_2_1 = Vec::with_capacity(cap);
        let r = rs[m_k - 1];
        let mut i = n_k;
        for _ in 0..cap {
            let b_i_0 = hash_common_var(i, 0);
            let b_i_1 = hash_common_var(i, 1);
            k_2_0.push(b_i_0 * r);
            k_2_1.push(b_i_1 * r);
            i += 1;
        }

        let k_check = rs.iter().map(|r| G2::generator() * r).collect();

        USK {
            identity: identity.clone(),
            k_1,
            k_2_0,
            k_2_1,
            k_check,
        }
    }

    pub fn delegate(
        &self,
        mut rng: impl Rng,
        _mpk: &MPK, // not needed, but kept for uniform interface with LW
        usk: &USK,
        identity: Vec<String>,
        identity_extension: String,
    ) -> USK {
        let n_k = identity.len();
        assert!(n_k > 0);

        let m_k = ceil_div(n_k, self.l);

        let rs = sample_fr(&mut rng, m_k + 1);

        let mut new_identity = identity.clone();
        new_identity.push(identity_extension.clone());

        if n_k + 1 <= self.l * m_k {
            let xid = hash_to_fr(&identity_extension);
            let mut new_k_1 = usk.k_1 + usk.k_2_0[0] + usk.k_2_1[0] * xid;
            for i in 0..n_k + 1 {
                let xid = hash_to_fr(&new_identity[i]);
                let b_i_0 = hash_common_var(i, 0);
                let b_i_1 = hash_common_var(i, 1);
                let r = rs[self.iota(i)];
                let tmp: G1 = VariableBaseMSM::msm(&[b_i_0, b_i_1], &[r, r * xid]).unwrap();
                new_k_1 += tmp;
            }

            // skip first entry which we used above
            let mut new_k_2_0: Vec<G1> = usk.k_2_0.clone().into_iter().skip(1).collect();
            let mut new_k_2_1: Vec<G1> = usk.k_2_1.clone().into_iter().skip(1).collect();
            let mut i = n_k + 2;
            for k in 0..new_k_2_0.len() {
                let r = rs[m_k];
                let b_i_0 = hash_common_var(i, 0);
                new_k_2_0[k] += b_i_0 * r;

                let b_i_1 = hash_common_var(i, 1);
                new_k_2_1[k] += b_i_1 * r;

                i += 1;
            }

            let g2 = G2::generator();
            let mut new_k_check = usk.k_check.clone();
            for i in 0..m_k {
                let r = rs[i];
                new_k_check[i] = new_k_check[i] + g2 * r;
            }

            USK {
                identity: new_identity,
                k_1: new_k_1,
                k_2_0: new_k_2_0,
                k_2_1: new_k_2_1,
                k_check: new_k_check,
            }
        } else {
            let mut new_k_1 = usk.k_1;
            for i in 0..n_k + 1 {
                let xid = hash_to_fr(&new_identity[i]);
                let b_i_0 = hash_common_var(i, 0);
                let b_i_1 = hash_common_var(i, 1);
                let r = rs[self.iota(i)];
                let tmp: G1 = VariableBaseMSM::msm(&[b_i_0, b_i_1], &[r, r * xid]).unwrap();
                new_k_1 += tmp;
            }

            let cap = self.l * (m_k + 1) - (n_k + 2) + 1;
            let mut new_k_2_0 = Vec::with_capacity(cap);
            let mut new_k_2_1 = Vec::with_capacity(cap);
            let r = rs[m_k];
            for i in n_k + 2..self.l * (m_k + 1) {
                let b_i_0 = hash_common_var(i, 0);
                let b_i_1 = hash_common_var(i, 1);
                new_k_2_0.push(b_i_0 * r);
                new_k_2_1.push(b_i_1 * r);
            }

            let g2 = G2::generator();
            let mut new_k_check = usk.k_check.clone();
            for i in 0..m_k {
                let r = rs[i];
                new_k_check[i] = new_k_check[i] + g2 * r;
            }
            new_k_check.push(g2 * rs[m_k]);

            USK {
                identity: new_identity,
                k_1: new_k_1,
                k_2_0: new_k_2_0,
                k_2_1: new_k_2_1,
                k_check: new_k_check,
            }
        }
    }

    pub fn encrypt(&self, mut rng: impl Rng, msg: &Gt, mpk: &MPK, identity: Vec<String>) -> CT {
        let n_c = identity.len();
        assert!(n_c > 0);

        let s = Fr::rand(&mut rng);

        let mut c_i = Vec::with_capacity(n_c);
        for i in 0..n_c {
            let xid = hash_to_fr(&identity[i]);
            let b_i_0 = hash_common_var(i, 0);
            let b_i_1 = hash_common_var(i, 1);
            let tmp: G1 = VariableBaseMSM::msm(&[b_i_0, b_i_1], &[s, s * xid]).unwrap();
            c_i.push(tmp);
        }

        CT {
            identity: identity.clone(),
            msg: mpk.a.pow(s.into_bigint()) * msg,
            c: G2::generator() * s,
            c_i,
        }
    }

    pub fn decrypt(&self, usk: &USK, ct: &CT) -> Option<Gt> {
        let n_k = usk.identity.len();
        assert!(n_k > 0);

        if !can_decrypt(&usk.identity, &ct.identity) {
            return None;
        }

        let mut result = Bls12_381::pairing(usk.k_1, ct.c).0;

        // We exploit the facts that
        // 1) e(x, y1) * e(x, y2) = e(x, y1 + y2), and
        // 2) self.iota(i) is identical for multiple consecutive `i` in `0..n_k`.
        //
        // To do so, we split the loop over `n_k`
        // for i in 0..n_k {
        //     result *= Bls12_381::pairing(-ct.c_i[i], usk.k_check[self.iota(i)]).0;
        // }
        // into `m_k-1` fully filled partitions of size `l` plus
        // an additional `n_last` items in the last (possibly partially filled or empty) partition.

        // Process the first `m_k` "fully filled" partitions of size `l`
        let m_k = n_k / self.l;
        for i in 0..m_k {
            let k = usk.k_check[i];
            let mut c = G1::zero();
            for j in 0..self.l {
                let idx = i * self.l + j;
                c += ct.c_i[idx];
            }
            result *= Bls12_381::pairing(-c, k).0;
        }

        // Process the last "partially filled" (or empty) partition with only `n_last` items
        let n_last = n_k % self.l;
        let k = usk.k_check.last().unwrap();
        let mut c = G1::zero();
        for j in 0..n_last {
            c += ct.c_i[m_k * self.l + j];
        }
        if n_last != 0 {
            result *= Bls12_381::pairing(-c, k).0;
        }

        Some(ct.msg / result)
    }

    fn iota(&self, i: usize) -> usize {
        i / self.l
    }
}

fn sample_fr(mut rng: impl Rng, n: usize) -> Vec<Fr> {
    let mut result = Vec::with_capacity(n);
    for _ in 0..n {
        result.push(Fr::rand(&mut rng));
    }
    result
}

fn ceil_div(x: usize, y: usize) -> usize {
    (x + y - 1) / y
}

fn hash_common_var(i: usize, j: usize) -> G1Affine {
    const DOMAIN_SEP: &str = "$";
    let mut hash_arg = String::new();
    hash_arg += &j.to_string();
    hash_arg += &DOMAIN_SEP;
    hash_arg += &i.to_string();
    hash_to_g1(&hash_arg)
}

fn can_decrypt(key: &Vec<String>, ct: &Vec<String>) -> bool {
    let not_longer = key.len() <= ct.len();
    let prefix_matches = key.iter().zip(ct.iter()).all(|(x, y)| x == y);
    not_longer && prefix_matches
}

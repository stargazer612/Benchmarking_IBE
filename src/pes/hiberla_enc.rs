use std::cmp::min;

use ark_bls12_381::{Bls12_381, Fq12 as Gt, Fr, G1Affine, G1Projective as G1, G2Projective as G2};
use ark_ec::PrimeGroup;
use ark_ec::pairing::Pairing;
use ark_ff::{Field, PrimeField, UniformRand};
use ark_std::rand::Rng;

use crate::{hash_to_fr, hash_to_g1, pes::HIBEScheme};

pub struct MSK {
    pub alpha: Fr,
}

pub struct MPK {
    pub a: Gt,
}

pub struct USK {
    pub identity: Vec<String>,
    pub k_1: G1,
    pub k_2: Vec<G1>,
    pub k_check: Vec<G2>,
}

pub struct CT {
    pub identity: Vec<String>,
    pub msg: Gt,
    pub c: G2,
    pub c_i: Vec<G1>,
}

pub struct HiberlaEnc {
    pub l: usize, // partition size
}

impl HiberlaEnc {
    pub fn new(l: usize) -> HiberlaEnc {
        Self { l }
    }
}

impl HIBEScheme for HiberlaEnc {
    type MPK = MPK;
    type MSK = MSK;
    type USK = USK;
    type CT = CT;

    fn name(&self) -> String {
        String::from("hiberla_enc")
    }

    fn setup(&self, mut rng: impl Rng) -> (MSK, MPK) {
        let alpha = Fr::rand(&mut rng);
        let msk = MSK { alpha };

        let g1 = G1::generator();
        let g2 = G2::generator();

        let mpk = MPK {
            a: Bls12_381::pairing(g1 * alpha, g2).0,
        };
        (msk, mpk)
    }

    fn keygen(&self, mut rng: impl Rng, msk: &MSK, identity: Vec<String>) -> USK {
        let n_k = identity.len();
        assert!(n_k > 0);

        let m_k = ceil_div(n_k, self.l);
        let rs = sample_fr(&mut rng, m_k);

        let mut k_1 = G1::generator() * msk.alpha;
        for (i, (l, h)) in chunks(n_k, self.l) {
            let r = rs[i];
            let mut b_prime_l: G1 = hash_common_var(2, i).into();
            // TODO: maybe one could use MSM for the loop? A bit tricky, since size is not constant/known?
            for j in l..h {
                let xid = hash_to_fr(&identity[j]);
                let b_i = hash_common_var(1, j);
                b_prime_l += b_i * xid;
            }
            k_1 += b_prime_l * r;
        }

        let cap = self.l * m_k - n_k;
        let mut k_2 = Vec::with_capacity(cap);
        let r = rs[m_k - 1];
        for i in n_k..n_k + cap {
            let b_i = hash_common_var(1, i);
            k_2.push(b_i * r);
        }

        let k_check = rs.iter().map(|r| G2::generator() * r).collect();

        USK {
            identity: identity.clone(),
            k_1,
            k_2,
            k_check,
        }
    }

    fn encrypt(&self, mut rng: impl Rng, msg: &Gt, mpk: &MPK, identity: Vec<String>) -> CT {
        let n_c = identity.len();
        assert!(n_c > 0);

        let s = Fr::rand(&mut rng);

        let m_c = ceil_div(n_c, self.l);
        let mut c_i = Vec::with_capacity(m_c);
        for (i, (l, h)) in chunks(n_c, self.l) {
            let mut b_prime_l: G1 = hash_common_var(2, i).into();
            // TODO: maybe one could use MSM for the loop? A bit tricky, since size is not constant/known?
            for j in l..h {
                let xid = hash_to_fr(&identity[j]);
                let b_i = hash_common_var(1, j);
                b_prime_l += b_i * xid;
            }
            c_i.push(b_prime_l * s);
        }

        CT {
            identity: identity.clone(),
            msg: mpk.a.pow(s.into_bigint()) * msg,
            c: G2::generator() * s,
            c_i,
        }
    }

    fn delegate(
        &self,
        mut rng: impl Rng,
        _mpk: &MPK, // not needed, but kept for trait compliance
        usk: &USK,
        identity_extension: String,
    ) -> USK {
        let n_k = usk.identity.len();
        assert!(n_k > 0);

        let m_k = ceil_div(n_k, self.l);

        let rs = sample_fr(&mut rng, m_k + 1);

        let mut new_identity = usk.identity.clone();
        new_identity.push(identity_extension.clone());

        if n_k + 1 <= self.l * m_k {
            let xid = hash_to_fr(&identity_extension);
            let mut new_k_1 = usk.k_1 + usk.k_2[0] * xid;
            for (i, (l, h)) in chunks(n_k + 1, self.l) {
                let mut b_prime_l: G1 = hash_common_var(2, i).into();
                let r = rs[i];
                // TODO: maybe one could use MSM for the loop? A bit tricky, since size is not constant/known?
                for j in l..h {
                    let xid = hash_to_fr(&new_identity[j]);
                    let b_i = hash_common_var(1, j);
                    b_prime_l += b_i * xid;
                }
                new_k_1 += b_prime_l * r;
            }

            // skip the first entry which we used above
            let mut new_k_2: Vec<G1> = usk.k_2.clone().into_iter().skip(1).collect();
            let mut i = n_k + 2;
            for k in 0..new_k_2.len() {
                let b_i = hash_common_var(1, i);
                let r = rs[m_k];
                new_k_2[k] += b_i * r;
                i += 1;
            }

            let g2 = G2::generator();
            let mut new_k_check = usk.k_check.clone();
            for i in 0..m_k {
                let r = rs[i];
                new_k_check[i] = new_k_check[i] + g2 * r;
            }

            USK {
                identity: new_identity.clone(),
                k_1: new_k_1,
                k_2: new_k_2,
                k_check: new_k_check,
            }
        } else {
            let mut new_k_1 = usk.k_1;
            for (i, (l, h)) in chunks(n_k + 1, self.l) {
                let mut b_prime_l: G1 = hash_common_var(2, i).into();
                let r = rs[i];
                // TODO: maybe one could use MSM for the loop? A bit tricky, since size is not constant/known?
                for j in l..h {
                    let xid = hash_to_fr(&new_identity[j]);
                    let b_i = hash_common_var(1, j);
                    b_prime_l += b_i * xid;
                }
                new_k_1 += b_prime_l * r;
            }

            let cap = self.l * (m_k + 1) - (n_k + 2) + 1;
            let mut new_k_2 = Vec::with_capacity(cap);
            let r = rs[m_k];
            for i in n_k + 2..self.l * (m_k + 1) {
                let b_i = hash_common_var(i, 0);
                new_k_2.push(b_i * r);
            }

            let g2 = G2::generator();
            let mut new_k_check = usk.k_check.clone();
            for i in 0..m_k {
                let r = rs[i];
                new_k_check[i] = new_k_check[i] + g2 * r;
            }
            new_k_check.push(g2 * rs[m_k]);

            USK {
                identity: new_identity.clone(),
                k_1: new_k_1,
                k_2: new_k_2,
                k_check: new_k_check,
            }
        }
    }

    fn decrypt(&self, usk: &USK, ct: &CT) -> Option<Gt> {
        let n_k = usk.identity.len();
        assert!(n_k > 0);

        let n_c = ct.identity.len();
        let m_k = ceil_div(n_k, self.l);
        let m_c = ceil_div(n_c, self.l);

        if !can_decrypt(&usk.identity, &ct.identity) {
            return None;
        }

        // Delegation is only required if
        // 1) n_c > n_k and
        // 2) user identity has a partially filled partition (i.e. n_k % l != 0)
        let mut k_prime_1 = usk.k_1;
        if n_k < n_c && n_k % self.l != 0 {
            let x_k = n_k % self.l;
            let x_c;
            if m_c - m_k >= 1 {
                // Example (l=3):
                // user_id: A.B.C|D
                // ct_id: A.B.C|D.E.F|G
                // extension: A.B.C|D -> A.B.C|D.E.F
                x_c = self.l;
            } else if n_c % self.l == 0 {
                // Example (l=3):
                // user_id: A
                // ct_id: A.B.C
                // extension: A -> A.B.C
                x_c = self.l;
            } else {
                // Example (l=3):
                // user_id: A.B
                // ct_id: A.B.C
                // extension: A.B -> A.B.C
                x_c = n_c % self.l;
            }
            let diff = x_c - x_k;
            let mut j = 0;
            // TODO: maybe one could use MSM for the loop? A bit tricky, since size is not constant/known?
            for i in n_k..n_k + diff {
                let xid = hash_to_fr(&ct.identity[i]);
                k_prime_1 += usk.k_2[j] * xid;
                j += 1;
            }
        }

        let mut result = Bls12_381::pairing(k_prime_1, ct.c).0;
        for l in 0..m_k {
            result *= Bls12_381::pairing(-ct.c_i[l], usk.k_check[l]).0;
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

fn chunks(range: usize, size: usize) -> impl Iterator<Item = (usize, (usize, usize))> {
    let chunks = Chunks::new(0, range, size);
    (0..).zip(chunks)
}

struct Chunks {
    start: usize,
    end: usize,
    size: usize,
    curr: usize,
}

impl Chunks {
    fn new(start: usize, end: usize, size: usize) -> Self {
        assert!(start < end);
        assert!(size > 0);
        Chunks {
            start,
            end,
            size,
            curr: 0,
        }
    }
}

impl Iterator for Chunks {
    type Item = (usize, usize);

    fn next(&mut self) -> Option<Self::Item> {
        if self.curr * self.size >= self.end - self.start {
            return None;
        }

        let low = self.start + self.curr * self.size;
        let high = min(low + self.size, self.end);
        self.curr += 1;
        Some((low, high))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_chunk() {
        let chunks = Chunks::new(0, 4, 10);
        let res = chunks.collect::<Vec<(usize, usize)>>();
        assert_eq!(res.len(), 1);
        assert_eq!(res[0], (0, 4));
    }

    #[test]
    fn test_multi_chunks() {
        let chunks = Chunks::new(0, 7, 3);
        let res = chunks.collect::<Vec<(usize, usize)>>();
        assert_eq!(res.len(), 3);
        assert_eq!(res[0], (0, 3));
        assert_eq!(res[1], (3, 6));
        assert_eq!(res[2], (6, 7));
    }

    #[test]
    fn test_multi_chunks_even_divide() {
        let chunks = Chunks::new(0, 7, 2);
        let res = chunks.collect::<Vec<(usize, usize)>>();
        assert_eq!(res.len(), 4);
        assert_eq!(res[0], (0, 2));
        assert_eq!(res[1], (2, 4));
        assert_eq!(res[2], (4, 6));
        assert_eq!(res[3], (6, 7));
    }

    #[test]
    fn test_unary_chunks() {
        let chunks = Chunks::new(0, 3, 1);
        let res = chunks.collect::<Vec<(usize, usize)>>();
        assert_eq!(res.len(), 3);
        assert_eq!(res[0], (0, 1));
        assert_eq!(res[1], (1, 2));
        assert_eq!(res[2], (2, 3));
    }

    #[test]
    fn test_chunks_offset() {
        let chunks = Chunks::new(5, 14, 4);
        let res = chunks.collect::<Vec<(usize, usize)>>();
        assert_eq!(res.len(), 3);
        assert_eq!(res[0], (5, 9));
        assert_eq!(res[1], (9, 13));
        assert_eq!(res[2], (13, 14));
    }
}

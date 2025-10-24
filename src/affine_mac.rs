use crate::f_functions::*;
use crate::field_utils::*;
use crate::group_ctx::*;
use crate::types::*;

use ark_bls12_381::G2Projective as G2;
use ark_ec::ProjectiveCurve;
use ark_ff::{PrimeField, Zero};

pub struct SecretKey {
    pub b: Matrix<FieldElement>,
    pub x_matrices: Vec<Matrix<FieldElement>>,
    pub x_prime: Vec<Vector>,
}

pub struct Tag {
    pub t_g2: Vec<G2>,
    pub u_g2: Vec<G2>,
    pub t_field: Vector,
}

pub struct AffineMAC {
    pub k: usize,
    pub l: usize,
    pub l_prime: usize,
    pub group: GroupCtx,
}

impl AffineMAC {
    pub fn new(k: usize, l: usize, l_prime: usize) -> Self {
        Self {
            k,
            l,
            l_prime,
            group: GroupCtx::bls12_381(),
        }
    }

    pub fn gen_mac(&self) -> SecretKey {
        let b = random_matrix(self.k, self.k);
        let mut x_matrices = Vec::with_capacity(self.l + 1);
        for _ in 0..=self.l {
            x_matrices.push(random_matrix(2 * self.k, self.k));
        }
        let mut x_prime = Vec::with_capacity(self.l_prime + 1);
        for _ in 0..=self.l_prime {
            x_prime.push(random_vector(2 * self.k));
        }
        SecretKey {
            b,
            x_matrices,
            x_prime,
        }
    }

    pub fn tag(&self, sk: &SecretKey, message: &[u8]) -> Tag {
        let s = random_vector(self.k);
        let t_field = matrix_vector_mul(&sk.b, &s);

        let mut u_field = vector_zero::<FieldElement>(2 * self.k);

        for i in 0..=self.l {
            let fi = f_i(i, self.l, message);
            if !fi.is_zero() {
                let xi_t = matrix_vector_mul(&sk.x_matrices[i], &t_field);
                u_field = vector_add(&u_field, &xi_t);
            }
        }

        for i in 0..=self.l_prime {
            let fi_prime = f_prime_i(i);
            if !fi_prime.is_zero() {
                u_field = vector_add(&u_field, &sk.x_prime[i]);
            }
        }

        let t_g2: Vec<G2> = vector_lift_g2(&t_field, &self.group);
        let u_g2: Vec<G2> = vector_lift_g2(&u_field, &self.group);

        Tag {
            t_g2,
            u_g2,
            t_field,
        }
    }

    pub fn verify(&self, sk: &SecretKey, message: &[u8], tag: &Tag) -> bool {
        let mut expected = vector_zero::<G2>(2 * self.k);

        for i in 0..=self.l {
            let fi = f_i(i, self.l, message);
            if !fi.is_zero() {
                let xi = &sk.x_matrices[i];
                for r in 0..(2 * self.k) {
                    let mut accum = G2::zero();
                    for j in 0..self.k {
                        if !xi[r][j].is_zero() {
                            accum += tag.t_g2[j].mul(xi[r][j].into_repr());
                        }
                    }
                    expected[r] += accum;
                }
            }
        }

        for i in 0..=self.l_prime {
            let fi_prime = f_prime_i(i);
            if !fi_prime.is_zero() {
                let row_vec = &sk.x_prime[i];
                assert_eq!(row_vec.len(), 2 * self.k);
                for r in 0..(2 * self.k) {
                    if !row_vec[r].is_zero() {
                        expected[r] += self.group.scalar_mul_p2(row_vec[r]);
                    }
                }
            }
        }

        assert_eq!(expected.len(), tag.u_g2.len());
        expected.iter().zip(tag.u_g2.iter()).all(|(e, u)| e == u)
    }
}

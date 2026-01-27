use crate::field_utils::*;
use crate::types::*;

use ark_bls12_381::G2Projective as G2;
use bit_vec::BitVec;

pub struct SecretKey {
    pub b: Matrix<FieldElement>,
    // x_matrices = [x_{0,0}, x_{0,1}, x_{1,0}, x_{1,1}, ..., x_{l-1,0}, x_{l-1,1}]
    pub x_matrices: Vec<Matrix<FieldElement>>,
    // x_prime = [x'_{0}]
    pub x_prime: Vec<Vector>,
}

pub struct Tag {
    pub t_g2: Vec<G2>,
    pub u_g2: Vec<G2>,
    pub t_field: Vector,
}

pub struct AffineMAC {
    pub k: usize,
    pub msg_len: usize,
}

fn bit_at(i: usize, m: &[u8]) -> usize {
    let msg_bits = BitVec::from_bytes(m);
    if msg_bits[i] { 1 } else { 0 }
}

impl AffineMAC {
    pub fn new(k: usize, msg_len: usize) -> Self {
        assert_eq!(msg_len % 8, 0);
        Self { k, msg_len }
    }

    pub fn gen_mac(&self) -> SecretKey {
        let b = random_matrix(self.k, self.k);
        let mut x_matrices = Vec::with_capacity(2 * self.msg_len);
        for _ in 0..2 * self.msg_len {
            x_matrices.push(random_matrix(2 * self.k, self.k));
        }
        let x_prime = vec![random_vector(2 * self.k)];
        SecretKey {
            b,
            x_matrices,
            x_prime,
        }
    }

    pub fn tag(&self, sk: &SecretKey, message: &[u8]) -> Tag {
        assert_eq!(message.len() * 8, self.msg_len);

        let s = random_vector(self.k);
        let t_field = matrix_vector_mul(&sk.b, &s);

        let mut x_m = matrix_zero(2 * self.k, self.k);
        for i in 0..self.msg_len {
            let b = bit_at(i, message);
            let x_i = &sk.x_matrices[2 * i + b];
            x_m = matrix_add(&x_m, x_i);
        }

        let mut u_field = matrix_vector_mul(&x_m, &t_field);
        u_field = vector_add(&u_field, &sk.x_prime[0]);

        let t_g2: Vec<G2> = vector_lift_g2(&t_field);
        let u_g2: Vec<G2> = vector_lift_g2(&u_field);

        Tag {
            t_g2,
            u_g2,
            t_field,
        }
    }

    pub fn verify(&self, sk: &SecretKey, message: &[u8], tag: &Tag) -> bool {
        assert_eq!(message.len() * 8, self.msg_len);
        assert_eq!(tag.u_g2.len(), 2 * self.k);

        let mut x_m = matrix_zero(2 * self.k, self.k);
        for i in 0..self.msg_len {
            let b = bit_at(i, message);
            let x_i = &sk.x_matrices[2 * i + b];
            x_m = matrix_add(&x_m, x_i);
        }

        let x_prime = vector_lift_g2(&sk.x_prime[0]);
        let mut expected = matrix_vector_g2_mul_msm(&x_m, &tag.t_g2);
        expected = vector_add_g2(&expected, &x_prime);

        expected.iter().zip(tag.u_g2.iter()).all(|(e, u)| e == u)
    }
}

use crate::affine_mac::{AffineMAC, SecretKey as MACSecretKey};
use crate::bit_utils::bit_at;
use crate::field_utils::*;
use crate::group_functions::{multi_pairing, pairing};
use crate::types::*;

use ark_bls12_381::{G1Projective as G1, G2Projective as G2};
use ark_ec::PrimeGroup;

pub struct IBKEM1PublicKey {
    pub m_matrix: Matrix<G1>,
    // z_matrices = [z_{0,0}, z_{0,1}, z_{1,0}, z_{1,1}, ..., z_{l-1,0}, z_{l-1,1}]
    pub z_matrices: Vec<Matrix<G1>>,
    pub z_prime_vectors: Matrix<G1>,
}

pub struct IBKEM1SecretKey {
    pub mac_sk: MACSecretKey,
    pub y_matrices: Vec<Matrix<FieldElement>>,
    pub y_prime_vectors: Vec<Vector>,
}

pub struct IBKEM1UserSecretKey {
    pub t_g2: Vec<G2>,
    pub u_g2: Vec<G2>,
    pub v_g2: Vec<G2>,
}

pub struct IBKEM1Ciphertext {
    pub c0_g1: Vec<G1>,
    pub c1_g1: Vec<G1>,
}

pub struct IBKEM1 {
    pub k: usize,
    pub msg_len: usize,
    pub mac: AffineMAC,
}

impl IBKEM1 {
    pub fn new(k: usize, msg_len: usize) -> Self {
        Self {
            k,
            msg_len,
            mac: AffineMAC::new(k, msg_len),
        }
    }

    pub fn setup(&self) -> (IBKEM1PublicKey, IBKEM1SecretKey) {
        // we fix eta = 2k s.t. matrix formats for (y^T || x^T) * M
        let eta = 2 * self.k;
        let m_matrix = random_matrix(self.k + eta, self.k);
        let mac_sk = self.mac.gen_mac();

        let l = mac_sk.x_matrices.len();

        let mut y_matrices = Vec::with_capacity(l);
        let mut z_matrices = Vec::with_capacity(l);

        for i in 0..l {
            // we use (k x k) instead of (k x n) to ensure format of y_i and x_i matches for concat
            let y_i = random_matrix(self.k, self.k);
            let y_i_transposed = matrix_transpose(&y_i);
            let x_i_transposed = matrix_transpose(&mac_sk.x_matrices[i]);
            let combined = matrix_concat(&y_i_transposed, &x_i_transposed);
            let z_i = matrix_multiply(&combined, &m_matrix);

            y_matrices.push(y_i);
            z_matrices.push(z_i);
        }

        // specialized to l_prime = 0 based on the MAC we use
        let l_prime = 0;
        let mut y_prime_vectors = Vec::with_capacity(l_prime + 1);
        let mut z_prime_vectors = Vec::with_capacity(l_prime + 1);

        for i in 0..=l_prime {
            let y_prime_i = random_vector(self.k);
            let combined = vector_concat(&y_prime_i, &mac_sk.x_prime[i]);
            let m_matrix_transposed = matrix_transpose(&m_matrix);
            let z_prime_i = matrix_vector_mul(&m_matrix_transposed, &combined);

            y_prime_vectors.push(y_prime_i);
            z_prime_vectors.push(z_prime_i);
        }

        let m_g1 = matrix_lift_g1(&m_matrix);

        let z_matrices_g1: Vec<Matrix<G1>> = z_matrices
            .iter()
            .map(|matrix| matrix_lift_g1(&matrix))
            .collect();

        let z_prime_vectors_g1 = matrix_lift_g1(&z_prime_vectors);

        let pk = IBKEM1PublicKey {
            m_matrix: m_g1,
            z_matrices: z_matrices_g1,
            z_prime_vectors: z_prime_vectors_g1,
        };

        let sk = IBKEM1SecretKey {
            mac_sk,
            y_matrices,
            y_prime_vectors,
        };

        (pk, sk)
    }

    pub fn extract(&self, sk: &IBKEM1SecretKey, identity: &[u8]) -> IBKEM1UserSecretKey {
        assert_eq!(identity.len() * 8, self.msg_len);

        let tag = self.mac.tag(&sk.mac_sk, identity);

        // f_i(m) is specialized to the MAC we use
        let mut v_g2 = vector_zero::<G2>(self.k);
        for i in 0..self.msg_len {
            let b = bit_at(i, identity);
            let y_i = &sk.y_matrices[2 * i + b];

            let y_i_g2 = matrix_vector_g2_mul_msm(&y_i, &tag.t_g2);
            v_g2 = vector_add_g2(&v_g2, &y_i_g2);
        }

        // Specialized to l_prime = 0 and f'_0(m) = 1 based on the MAC we use
        let y_prime = vector_lift_g2(&sk.y_prime_vectors[0]);
        v_g2 = vector_add_g2(&v_g2, &y_prime);

        IBKEM1UserSecretKey {
            t_g2: tag.t_g2,
            u_g2: tag.u_g2,
            v_g2,
        }
    }

    pub fn encrypt(&self, pk: &IBKEM1PublicKey, identity: &[u8]) -> (IBKEM1Ciphertext, GTElement) {
        assert_eq!(identity.len() * 8, self.msg_len);

        let r = random_vector(self.k);
        let c0_g1 = group_matrix_vector_mul_msm(&pk.m_matrix, &r);

        let n = pk.z_matrices[0].len();
        let mut z_i_sum = matrix_zero::<G1>(n, self.k);

        // f_i(m) is specialized to the MAC we use here
        for i in 0..self.msg_len {
            let b = bit_at(i, identity);
            let z_i = &pk.z_matrices[2 * i + b];
            z_i_sum = matrix_add(&z_i_sum, &z_i);
        }
        let c1_g1 = group_matrix_vector_mul_msm(&z_i_sum, &r);

        // Specialized to l_prime = 0 and f'_0(m) = 1 based on the MAC we use
        let z_prime = &pk.z_prime_vectors[0];
        let k_g1 = vector_dot_g1(&r, &z_prime);

        let k_gt = pairing(&k_g1, &G2::generator());

        let ciphertext = IBKEM1Ciphertext { c0_g1, c1_g1 };
        (ciphertext, k_gt)
    }

    pub fn decrypt(&self, usk: &IBKEM1UserSecretKey, ciphertext: &IBKEM1Ciphertext) -> GTElement {
        let mut w_g2 = usk.v_g2.clone();
        w_g2.extend_from_slice(&usk.u_g2);

        let c0_g1 = &ciphertext.c0_g1;
        let c1_g1 = &ciphertext.c1_g1;
        assert_ne!(c0_g1.len(), 0);
        assert_ne!(c1_g1.len(), 0);
        assert_eq!(c0_g1.len(), w_g2.len());
        assert_eq!(c1_g1.len(), usk.t_g2.len());

        let first_term: Vec<_> = (0..c0_g1.len())
            .map(|i| (c0_g1[i].clone(), w_g2[i].clone()))
            .collect();

        let second_term: Vec<_> = (0..c1_g1.len())
            .map(|i| (c1_g1[i].clone(), usk.t_g2[i].clone()))
            .collect();

        multi_pairing(&first_term) / multi_pairing(&second_term)
    }
}

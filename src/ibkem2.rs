use crate::affine_mac::{AffineMAC, SecretKey as MACSecretKey};
use crate::bit_utils::bit_at;
use crate::field_utils::*;
use crate::group_functions::{multi_pairing, pairing};
use crate::qanizk::{CRS, QANIZK, QANIZKProof as Proof};
use crate::types::*;

use ark_bls12_381::{G1Projective as G1, G2Projective as G2};
use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::{BigInteger, PrimeField};

pub struct IBKEM2PublicKey {
    pub m_matrix: Matrix<G1>,
    // z_matrices = [z_{0,0}, z_{0,1}, z_{1,0}, z_{1,1}, ..., z_{l-1,0}, z_{l-1,1}]
    pub z_matrices: Vec<Matrix<G1>>,
    pub z_prime_vectors: Matrix<G1>,
    pub crs: CRS,
}

pub struct IBKEM2SecretKey {
    pub mac_sk: MACSecretKey,
    pub y_matrices: Vec<Matrix<FieldElement>>,
    pub y_prime_vectors: Vec<Vector>,
}

pub struct IBKEM2UserSecretKey {
    pub t_g2: Vec<G2>,
    pub u_g2: Vec<G2>,
    pub v_g2: Vec<G2>,
}

pub struct IBKEM2Ciphertext {
    pub c0_g1: Vec<G1>,
    pub c1_g1: Vec<G1>,
    pub proof: Proof,
}

pub struct IBKEM2 {
    pub k: usize,
    pub msg_len: usize,
    pub mac: AffineMAC,
    pub qanizk: QANIZK,
}

impl IBKEM2 {
    pub fn new(k: usize, msg_len: usize, lambda: usize) -> Self {
        Self {
            k,
            msg_len,
            mac: AffineMAC::new(k, msg_len),
            qanizk: QANIZK::new(k, lambda),
        }
    }

    pub fn setup(&self) -> (IBKEM2PublicKey, IBKEM2SecretKey) {
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
            // let combined = matrix_concat(&y_i_transposed, &x_i_transposed);
            // let z_i = matrix_multiply(&combined, &m_matrix);
            let z_i = matrix_concat_multiply(&y_i_transposed, &x_i_transposed, &m_matrix);

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
            // let m_matrix_transposed = matrix_transpose(&m_matrix);
            // let z_prime_i = matrix_vector_mul(&m_matrix_transposed, &combined);
            let z_prime_i = matrix_transpose_vector_mul(&m_matrix, &combined);

            y_prime_vectors.push(y_prime_i);
            z_prime_vectors.push(z_prime_i);
        }

        let m_g1 = matrix_lift_g1(&m_matrix);

        let z_matrices_g1: Vec<Matrix<G1>> = z_matrices
            .iter()
            .map(|matrix| matrix_lift_g1(&matrix))
            .collect();

        let z_prime_vectors_g1 = matrix_lift_g1(&z_prime_vectors);

        let (crs, _) = self.qanizk.gen_crs(&m_g1);

        let pk = IBKEM2PublicKey {
            m_matrix: m_g1,
            z_matrices: z_matrices_g1,
            z_prime_vectors: z_prime_vectors_g1,
            crs,
        };

        let sk = IBKEM2SecretKey {
            mac_sk,
            y_matrices,
            y_prime_vectors,
        };

        (pk, sk)
    }

    pub fn extract(&self, sk: &IBKEM2SecretKey, identity: &[u8]) -> IBKEM2UserSecretKey {
        assert_eq!(identity.len() * 8, self.msg_len);

        let tag = self.mac.tag(&sk.mac_sk, identity);

        // f_i(m) is specialized to the MAC we use
        let mut v_field = vector_zero::<FieldElement>(self.k);
        for i in 0..self.msg_len {
            let b = bit_at(i, identity);
            let y_i = &sk.y_matrices[2 * i + b];

            let y_i_t = matrix_vector_mul(&y_i, &tag.t_field);
            v_field = vector_add(&v_field, &y_i_t);
        }

        // Specialized to l_prime = 0 and f'_0(m) = 1 based on the MAC we use
        let y_prime = &sk.y_prime_vectors[0];
        v_field = vector_add(&v_field, &y_prime);

        let v_g2 = vector_lift_g2(&v_field);

        IBKEM2UserSecretKey {
            t_g2: tag.t_g2,
            u_g2: tag.u_g2,
            v_g2,
        }
    }

    pub fn encrypt(&self, pk: &IBKEM2PublicKey, identity: &[u8]) -> (IBKEM2Ciphertext, GTElement) {
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

        let mut tag = Vec::new();
        tag.extend_from_slice(identity);
        for point in &c0_g1 {
            let affine = point.into_affine();
            tag.extend_from_slice(&affine.x.into_bigint().to_bytes_le());
            tag.extend_from_slice(&affine.y.into_bigint().to_bytes_le());
        }

        let proof = self.qanizk.prove(&pk.crs, &tag, &c0_g1, &r);

        let ciphertext = IBKEM2Ciphertext {
            c0_g1,
            c1_g1,
            proof,
        };

        (ciphertext, k_gt)
    }

    pub fn decrypt(
        &self,
        pk: &IBKEM2PublicKey,
        usk: &IBKEM2UserSecretKey,
        identity: &[u8],
        ciphertext: &IBKEM2Ciphertext,
    ) -> Option<GTElement> {
        let crs = &pk.crs;
        // tag (identity || c0)
        let mut tag = Vec::new();
        tag.extend_from_slice(identity);
        for point in &ciphertext.c0_g1 {
            let affine = point.into_affine();
            tag.extend_from_slice(&affine.x.into_bigint().to_bytes_le());
            tag.extend_from_slice(&affine.y.into_bigint().to_bytes_le());
        }

        let c0_g1 = &ciphertext.c0_g1;
        let c1_g1 = &ciphertext.c1_g1;

        let is_valid = self.qanizk.verify(crs, &tag, c0_g1, &ciphertext.proof);
        if !is_valid {
            return None;
        }

        let mut w_g2 = usk.v_g2.clone();
        w_g2.extend_from_slice(&usk.u_g2);

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

        Some(multi_pairing(&first_term) / multi_pairing(&second_term))
    }
}

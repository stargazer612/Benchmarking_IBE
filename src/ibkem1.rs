use crate::affine_mac::{AffineMAC, SecretKey as MACSecretKey};
use crate::field_utils::*;
use crate::group_ctx::*;
use crate::types::*;

use ark_bls12_381::{G1Projective as G1, G2Projective as G2};
use ark_ec::ProjectiveCurve;
use ark_ff::{One, PrimeField, Zero};

pub struct IBKEM1PublicKey {
    pub m_matrix: Matrix<G1>,
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
    pub l: usize, // 2*len + 1
    pub l_prime: usize,
    pub mac: AffineMAC,
    pub group: GroupCtx,
}

impl IBKEM1 {
    pub fn new(k: usize, l: usize, l_prime: usize) -> Self {
        Self {
            k,
            l,
            l_prime,
            mac: AffineMAC::new(k, l, l_prime),
            group: GroupCtx::bls12_381(),
        }
    }

    pub fn setup(&self) -> (IBKEM1PublicKey, IBKEM1SecretKey) {
        let eta = 2 * self.k;
        let m_matrix = random_matrix(self.k + eta, self.k);
        let mac_sk = self.mac.gen_mac();

        assert_eq!(mac_sk.x_matrices.len(), self.l + 1);

        let mut y_matrices = Vec::with_capacity(self.l);
        let mut z_matrices = Vec::with_capacity(self.l);

        for i in 0..=self.l {
            let y_i = random_matrix(self.k, self.k);
            let y_i_transposed = matrix_transpose(&y_i);
            let x_i_transposed = matrix_transpose(&mac_sk.x_matrices[i]);
            let combined = matrix_concat(&y_i_transposed, &x_i_transposed);
            let z_i = matrix_multiply(&combined, &m_matrix);

            y_matrices.push(y_i);
            z_matrices.push(z_i);
        }

        let mut y_prime_vectors = Vec::with_capacity(self.l_prime);
        let mut z_prime_vectors = Vec::with_capacity(self.l_prime);

        for i in 0..=self.l_prime {
            let y_prime_i = random_vector(self.k);
            let combined = vector_concat(&y_prime_i, &mac_sk.x_prime[i]);
            let m_matrix_transposed = matrix_transpose(&m_matrix);
            let z_prime_i = matrix_vector_mul(&m_matrix_transposed, &combined);

            y_prime_vectors.push(y_prime_i);
            z_prime_vectors.push(z_prime_i);
        }

        let m_g1 = matrix_lift_g1(&m_matrix, &self.group);

        let z_matrices_g1: Vec<Matrix<G1>> = z_matrices
            .iter()
            .map(|matrix| matrix_lift_g1(&matrix, &self.group))
            .collect();

        let z_prime_vectors_g1: Matrix<G1> = matrix_lift_g1(&z_prime_vectors, &self.group);

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
        let tag = self.mac.tag(&sk.mac_sk, identity);
        let mut v_field = vector_zero::<FieldElement>(self.k);

        for i in 0..=self.l {
            let fi = self.mac.f_i(i, identity);
            if !fi.is_zero() {
                let yi_t = matrix_vector_mul(&sk.y_matrices[i], &tag.t_field);
                let scaled = scalar_vector_mul(fi, &yi_t);
                v_field = vector_add(&v_field, &scaled);
            }
        }

        for i in 0..=self.l_prime {
            let fi_prime = self.mac.f_prime_i(i, identity);
            if !fi_prime.is_zero() {
                let scaled_y_prime = scalar_vector_mul(fi_prime, &sk.y_prime_vectors[i]);
                v_field = vector_add(&v_field, &scaled_y_prime);
            }
        }

        let v_g2 = vector_lift_g2(&v_field, &self.group);

        IBKEM1UserSecretKey {
            t_g2: tag.t_g2,
            u_g2: tag.u_g2,
            v_g2,
        }
    }

    pub fn encrypt(&self, pk: &IBKEM1PublicKey, identity: &[u8]) -> (IBKEM1Ciphertext, GTElement) {
        let r = random_vector(self.k);
        let c0_g1 = group_matrix_vector_mul_msm(&pk.m_matrix, &r);

        let n = pk.z_matrices[0].len();
        let mut z_i_sum = matrix_zero::<G1>(n, self.k);

        for i in 0..=self.l {
            let fi = self.mac.f_i(i, identity);
            if !fi.is_zero() {
                let tmp = matrix_multiply_scalar(&pk.z_matrices[i], fi);
                z_i_sum = matrix_add_g1(&z_i_sum, &tmp);
            }
        }

        let c1_g1 = group_matrix_vector_mul_msm(&z_i_sum, &r);

        let mut pairing_pairs = Vec::with_capacity(self.l_prime);

        for i in 0..=self.l_prime {
            let fi_prime = self.mac.f_prime_i(i, identity);
            if !fi_prime.is_zero() {
                let zi_prime_dot_r = vector_dot_g1(&r, &pk.z_prime_vectors[i]);
                let scaling = zi_prime_dot_r.mul(fi_prime.into_repr());
                pairing_pairs.push((scaling, self.group.p2.clone()));
            }
        }

        let k_gt = if pairing_pairs.is_empty() {
            GTElement::one()
        } else {
            self.group.multi_pairing(&pairing_pairs)
        };

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

        self.group.multi_pairing(&first_term) / self.group.multi_pairing(&second_term)
    }
}

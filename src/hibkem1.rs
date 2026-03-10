use crate::affine_mac_levels1::{AffineMacLevels1, AffineMacLevels1SecretKey, AffineMacLevels1Tag};
use crate::bit_utils::bit_at;
use crate::field_utils::*;
use crate::group_functions::{multi_pairing, pairing};
use crate::types::*;
use ark_bls12_381::{G1Projective as G1, G2Projective as G2};
use ark_ec::PrimeGroup;

pub struct HIBKEM1PublicKey {
    pub a_g1: Matrix<G1>,
    pub z_g1: Vec<Vec<Vec<Matrix<G1>>>>,
    pub z_prime_g1: Vec<G1>,
}

pub struct HIBKEM1DelegationKey {
    pub b_g2: Matrix<G2>,
    pub d_g2: Vec<Vec<Vec<Matrix<G2>>>>,
    pub e_g2: Vec<Vec<Vec<Matrix<G2>>>>,
}

pub struct HIBKEM1SecretKey {
    pub sk_mac: AffineMacLevels1SecretKey,
    pub y_matrices: Vec<Vec<Vec<Matrix<FieldElement>>>>,
    pub y_prime: Vector,
}

pub struct HIBKEM1UserSecretKey {
    pub t_g2: Vec<G2>,
    pub u_g2: Vec<G2>,
    pub v_g2: Vec<G2>,
}

pub struct HIBKEM1UserDelegationKey {
    pub d_g2: Vec<Vec<Vec<Vec<G2>>>>,
    pub e_g2: Vec<Vec<Vec<Vec<G2>>>>,
}

pub struct HIBKEM1Ciphertext {
    pub c0_g1: Vec<G1>,
    pub c1_g1: Vec<G1>,
}

pub struct HIBKEM1 {
    pub k: usize,
    pub max_levels: usize,
    pub identity_len: usize,
    pub mac: AffineMacLevels1,
}

impl HIBKEM1 {
    pub fn new(k: usize, max_levels: usize, identity_len: usize) -> Self {
        Self {
            k,
            max_levels,
            identity_len,
            mac: AffineMacLevels1::new(k, max_levels, identity_len),
        }
    }

    pub fn setup(&self) -> (HIBKEM1PublicKey, HIBKEM1DelegationKey, HIBKEM1SecretKey) {
        let sk_mac = self.mac.gen_mac();

        let a_matrix = random_matrix(2 * self.k, self.k); 

        let mut y_matrices = Vec::with_capacity(self.max_levels);
        let mut z_g1 = Vec::with_capacity(self.max_levels);
        let mut d_g2 = Vec::with_capacity(self.max_levels);
        let mut e_g2 = Vec::with_capacity(self.max_levels);

        for i in 1..=self.max_levels {
            let num_j = i * self.identity_len;
            let mut y_j = Vec::with_capacity(num_j);
            let mut z_j = Vec::with_capacity(num_j);
            let mut d_j = Vec::with_capacity(num_j);
            let mut e_j = Vec::with_capacity(num_j);

            for j in 1..=num_j {
                let mut y_b = Vec::with_capacity(2);
                let mut z_b = Vec::with_capacity(2);
                let mut d_b = Vec::with_capacity(2);
                let mut e_b = Vec::with_capacity(2);

                for b in 0..2 {
                    let y_matrix = random_matrix(self.k, 3 * self.k);
                    y_b.push(y_matrix.clone());

                    let x_t = matrix_transpose(&sk_mac.x_matrices[i - 1][j - 1][b]);
                    let y_t = matrix_transpose(&y_matrix);
                    let y_x = matrix_concat(&y_t, &x_t);
                    
                    let z_matrix = matrix_multiply(&y_x, &a_matrix);
                    z_b.push(matrix_lift_g1(&z_matrix));

                    let d_matrix = matrix_multiply(&sk_mac.x_matrices[i - 1][j - 1][b], &sk_mac.b);
                    d_b.push(matrix_lift_g2(&d_matrix));

                    let e_matrix = matrix_multiply(&y_matrix, &sk_mac.b);
                    e_b.push(matrix_lift_g2(&e_matrix));
                }

                y_j.push(y_b);
                z_j.push(z_b);
                d_j.push(d_b);
                e_j.push(e_b);
            }

            y_matrices.push(y_j);
            z_g1.push(z_j);
            d_g2.push(d_j);
            e_g2.push(e_j);
        }

        let y_prime = random_vector(self.k);
        let y_x_prime = vector_concat(&y_prime, &sk_mac.x_prime);

        let z_field = vector_matrix_mul(&y_x_prime, &a_matrix);
        let z_prime_g1 = vector_lift_g1(&z_field);

        let b_g2 = matrix_lift_g2(&sk_mac.b);
        let a_g1 = matrix_lift_g1(&a_matrix);

        let pk = HIBKEM1PublicKey {
            a_g1,
            z_g1,
            z_prime_g1,
        };
        let dk = HIBKEM1DelegationKey { b_g2, d_g2, e_g2 };
        let sk = HIBKEM1SecretKey {
            sk_mac,
            y_matrices,
            y_prime,
        };

        (pk, dk, sk)
    }

    pub fn extract(
        &self,
        sk: &HIBKEM1SecretKey,
        id: &[Vec<u8>],
    ) -> (HIBKEM1UserSecretKey, HIBKEM1UserDelegationKey) {
        let p = id.len();
        assert!(p > 0 && p <= self.max_levels);

        let tag: AffineMacLevels1Tag = self.mac.tag(&sk.sk_mac, id);
        let t_field = tag.t_field;
        let t_g2 = tag.t_g2;
        let u_g2 = tag.u_g2;

        let mut v = sk.y_prime.clone();

        for i in 1..=p {
            for j in 1..=(i * self.identity_len) {
                let msg_idx = (j - 1) / self.identity_len;
                let bit_in_msg = (j - 1) % self.identity_len;
                let b = bit_at(bit_in_msg, &id[msg_idx]);

                let y_i_j_b = &sk.y_matrices[i - 1][j - 1][b];

                let y_t = matrix_vector_mul(y_i_j_b, &t_field);

                v = vector_add(&v, &y_t);
            }
        }

        let v_g2 = vector_lift_g2(&v);

        let mut d_g2 = Vec::with_capacity(self.max_levels - p);
        let mut e_g2 = Vec::with_capacity(self.max_levels - p);

        for i in (p + 1)..=self.max_levels {
            let num_j = i * self.identity_len;
            let mut i_d = Vec::with_capacity(num_j);
            let mut i_e = Vec::with_capacity(num_j);

            for j in 1..=num_j {
                let mut j_d = Vec::with_capacity(2);
                let mut j_e = Vec::with_capacity(2);

                for b in 0..=1 {
                    let x_i_j_b = &sk.sk_mac.x_matrices[i - 1][j - 1][b];
                    let d_field = matrix_vector_mul(x_i_j_b, &t_field);
                    let d_g2_v = vector_lift_g2(&d_field);
                    j_d.push(d_g2_v);

                    let y_i_j_b = &sk.y_matrices[i - 1][j - 1][b];
                    let e_field = matrix_vector_mul(y_i_j_b, &t_field);
                    let e_g2_v = vector_lift_g2(&e_field);
                    j_e.push(e_g2_v);
                }

                i_d.push(j_d);
                i_e.push(j_e);
            }

            d_g2.push(i_d);
            e_g2.push(i_e);
        }

        let usk = HIBKEM1UserSecretKey { t_g2, u_g2, v_g2 };
        let udk = HIBKEM1UserDelegationKey { d_g2, e_g2 };

        (usk, udk)
    }

    pub fn delegate(
        &self,
        dk: &HIBKEM1DelegationKey,
        usk: &HIBKEM1UserSecretKey,
        udk: &HIBKEM1UserDelegationKey,
        id_prefix: &[Vec<u8>],
        id_next: Vec<u8>,
    ) -> (HIBKEM1UserSecretKey, HIBKEM1UserDelegationKey) {
        let p = id_prefix.len();
        assert!(p > 0 && p < self.max_levels);

        let s_prime = random_vector(self.k);

        let bs_prime = group2_matrix_vector_mul_msm(&dk.b_g2, &s_prime);
        let t_prime_g2 = vector_add_g2(&usk.t_g2, &bs_prime);

        let mut id_prime = id_prefix.to_vec();
        id_prime.push(id_next);

        let mut u_prime_g2 = usk.u_g2.clone();

        let num_j = (p + 1) * self.identity_len;
        for j in 1..=num_j {
            let msg_idx = (j - 1) / self.identity_len;
            let bit_idx = (j - 1) % self.identity_len;
            let b = bit_at(bit_idx, &id_prime[msg_idx]);

            let d_vec_g2 = &udk.d_g2[0][j - 1][b];
            u_prime_g2 = vector_add_g2(&u_prime_g2, &d_vec_g2);
        }

        for i in 1..=(p + 1) {
            let num_j = i * self.identity_len;
            for j in 1..=num_j {
                let msg_idx = (j - 1) / self.identity_len;
                let bit_idx = (j - 1) % self.identity_len;
                let b = bit_at(bit_idx, &id_prime[msg_idx]);

                let d_cap_g2 = &dk.d_g2[i - 1][j - 1][b];
                let d_cap_s_prime = group2_matrix_vector_mul_msm(&d_cap_g2, &s_prime);
                u_prime_g2 = vector_add_g2(&u_prime_g2, &d_cap_s_prime);
            }
        }

        let mut v_prime_g2 = usk.v_g2.clone();

        let num_j_p1 = (p + 1) * self.identity_len;
        for j in 1..=num_j_p1 {
            let msg_idx = (j - 1) / self.identity_len;
            let bit_idx = (j - 1) % self.identity_len;
            let b = bit_at(bit_idx, &id_prime[msg_idx]);

            let e_vec_g2 = &udk.e_g2[0][j - 1][b];
            v_prime_g2 = vector_add_g2(&v_prime_g2, &e_vec_g2);
        }

        for i in 1..=(p + 1) {
            let num_j = i * self.identity_len;
            for j in 1..=num_j {
                let msg_idx = (j - 1) / self.identity_len;
                let bit_idx = (j - 1) % self.identity_len;
                let b = bit_at(bit_idx, &id_prime[msg_idx]);

                let e_cap_g2 = &dk.e_g2[i - 1][j - 1][b];
                let e_cap_s_prime = group2_matrix_vector_mul_msm(&e_cap_g2, &s_prime);
                v_prime_g2 = vector_add_g2(&v_prime_g2, &e_cap_s_prime);
            }
        }

        //udk
        let mut d_prime = Vec::with_capacity(self.max_levels - p);
        let mut e_prime = Vec::with_capacity(self.max_levels - p);

        for i in (p + 2)..=self.max_levels {
            let udk_idx = i - (p + 1);
            let num_j = i * self.identity_len;
            let mut i_d = Vec::with_capacity(num_j);
            let mut i_e = Vec::with_capacity(num_j);

            for j in 1..=num_j {
                let mut j_d = Vec::with_capacity(2);
                let mut j_e = Vec::with_capacity(2);

                for b in 0..=1 {
                    let d_g2 = &udk.d_g2[udk_idx][j - 1][b];

                    let d_cap_g2 = &dk.d_g2[i - 1][j - 1][b];
                    let d_cap_s_prime_g2 = group2_matrix_vector_mul_msm(&d_cap_g2, &s_prime);

                    let d_new_g2 = vector_add_g2(&d_g2, &d_cap_s_prime_g2);
                    j_d.push(d_new_g2);

                    let e_g2 = &udk.e_g2[udk_idx][j - 1][b];

                    let e_cap_g2 = &dk.e_g2[i - 1][j - 1][b as usize];
                    let e_cap_s_prime = group2_matrix_vector_mul_msm(&e_cap_g2, &s_prime);

                    let e_new = vector_add_g2(&e_g2, &e_cap_s_prime);
                    j_e.push(e_new);
                }

                i_d.push(j_d);
                i_e.push(j_e);
            }

            d_prime.push(i_d);
            e_prime.push(i_e);
        }

        let usk_prime = HIBKEM1UserSecretKey {
            t_g2: t_prime_g2,
            u_g2: u_prime_g2,
            v_g2: v_prime_g2,
        };
        let udk_prime = HIBKEM1UserDelegationKey {
            d_g2: d_prime,
            e_g2: e_prime,
        };

        (usk_prime, udk_prime)
    }

    pub fn encrypt(&self, pk: &HIBKEM1PublicKey, id: &[Vec<u8>]) -> (GTElement, HIBKEM1Ciphertext) {
        let p = id.len();
        assert!(p > 0 && p <= self.max_levels);

        let r = random_vector(self.k);
        let c0_g1 = group_matrix_vector_mul_msm(&pk.a_g1, &r);

        let n = pk.z_g1[0][0][0].len();
        let mut z_i_sum = matrix_zero::<G1>(n, self.k);

        for i in 1..=p {
            let num_j = i * self.identity_len;
            for j in 1..=num_j {
                let msg_idx = (j - 1) / self.identity_len;
                let bit_in_msg = (j - 1) % self.identity_len;
                let b = bit_at(bit_in_msg, &id[msg_idx]);

                let z_i_j = &pk.z_g1[i - 1][j - 1][b];
                z_i_sum = matrix_add(&z_i_sum, &z_i_j);
            }
        }
        let c1_g1 = group_matrix_vector_mul_msm(&z_i_sum, &r);

        let k_g1 = vector_dot_g1(&r, &pk.z_prime_g1);
        let k_t = pairing(&k_g1, &G2::generator());

        let ct = HIBKEM1Ciphertext { c0_g1, c1_g1 };

        (k_t, ct)
    }

    pub fn decrypt(&self, usk: &HIBKEM1UserSecretKey, ct: &HIBKEM1Ciphertext) -> GTElement {
        let mut v_u_g2 = usk.v_g2.clone();
        v_u_g2.extend_from_slice(&usk.u_g2);

        let c0_g1 = &ct.c0_g1;
        let c1_g1 = &ct.c1_g1;

        assert_ne!(c0_g1.len(), 0);
        assert_ne!(c1_g1.len(), 0);
        assert_eq!(c0_g1.len(), v_u_g2.len());
        assert_eq!(c1_g1.len(), usk.t_g2.len());

        let first_term: Vec<_> = (0..c0_g1.len())
            .map(|i| (c0_g1[i].clone(), v_u_g2[i].clone()))
            .collect();

        let second_term: Vec<_> = (0..c1_g1.len())
            .map(|i| (c1_g1[i].clone(), usk.t_g2[i].clone()))
            .collect();

        multi_pairing(&first_term) / multi_pairing(&second_term)
    }
}

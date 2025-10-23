use crate::field_utils::*;
use crate::group_ctx::*;
use crate::hashing::*;
use crate::types::*;

use ark_bls12_381::{G1Affine, G1Projective as G1, G2Projective as G2};
use ark_ec::{ProjectiveCurve, msm::VariableBaseMSM};
use ark_ff::{BigInteger, One, PrimeField};

pub struct CRS {
    pub a_g2: Matrix<G2>,
    pub ka_g2: Matrix<G2>,
    pub b_g1: Matrix<G1>,
    pub mk_g1: Matrix<G1>,
    pub kjb_a_g2: Vec<Vec<Matrix<G2>>>,
    pub b_kjb_g1: Vec<Vec<Matrix<G1>>>,
}

pub struct Trapdoor {
    pub k_matrix: Matrix<FieldElement>,
}

pub struct QANIZKProof {
    pub t1_g1: Vec<G1>,
    pub u1_g1: Vec<G1>,
}

pub struct QANIZK {
    pub k: usize,
    pub lambda: usize,
    pub group: GroupCtx,
}

impl QANIZK {
    pub fn new(k: usize, lambda: usize) -> Self {
        Self {
            k,
            lambda,
            group: GroupCtx::bls12_381(),
        }
    }

    pub fn gen_crs(&self, m1_matrix: &Matrix<G1>) -> (CRS, Trapdoor) {
        let a_matrix = random_matrix(self.k + 1, self.k);
        let b_matrix = random_matrix(self.k, self.k);
        let k_matrix = random_matrix(m1_matrix.len(), self.k + 1);

        let a_g2: Matrix<G2> = matrix_lift_g2(&a_matrix, &self.group);
        let ka_matrix = matrix_multiply(&k_matrix, &a_matrix);
        let ka_g2: Matrix<G2> = matrix_lift_g2(&ka_matrix, &self.group);
        let b_g1: Matrix<G1> = matrix_lift_g1(&b_matrix, &self.group);

        let m_transpose_matrix = matrix_transpose(&m1_matrix);
        let mk_g1 = g1_matrix_field_multiply(&m_transpose_matrix, &k_matrix);

        let mut kjb_a_g2 = Vec::with_capacity(self.lambda);
        let mut b_kjb_g1 = Vec::with_capacity(self.lambda);

        for _ in 0..self.lambda {
            let mut kjb_row_a = Vec::with_capacity(2);
            let mut b_kjb_row = Vec::with_capacity(2);

            for _ in 0..2 {
                let kjb_matrix = random_matrix(self.k, self.k + 1);
                let kjb_a = matrix_multiply(&kjb_matrix, &a_matrix);
                let kjb_row_a_g2: Matrix<G2> = matrix_lift_g2(&kjb_a, &self.group);
                kjb_row_a.push(kjb_row_a_g2);

                let b_transpose = matrix_transpose(&b_matrix);
                let b_kjb = matrix_multiply(&b_transpose, &kjb_matrix);
                let b_kjb_row_g1: Matrix<G1> = matrix_lift_g1(&b_kjb, &self.group);
                b_kjb_row.push(b_kjb_row_g1);
            }

            kjb_a_g2.push(kjb_row_a);
            b_kjb_g1.push(b_kjb_row);
        }

        let crs = CRS {
            a_g2,
            ka_g2,
            b_g1,
            mk_g1,
            kjb_a_g2,
            b_kjb_g1,
        };
        let trapdoor = Trapdoor { k_matrix };

        (crs, trapdoor)
    }

    fn hash_tag_c0_t1(&self, tag: &[u8], c0_g1: &[G1], t1: &[G1]) -> Vec<u8> {
        let mut input = Vec::new();

        input.extend_from_slice(tag);

        for point in c0_g1 {
            input.extend_from_slice(&point.into_affine().x.into_repr().to_bytes_le());
            input.extend_from_slice(&point.into_affine().y.into_repr().to_bytes_le());
        }

        for point in t1 {
            input.extend_from_slice(&point.into_affine().x.into_repr().to_bytes_le());
            input.extend_from_slice(&point.into_affine().y.into_repr().to_bytes_le());
        }

        input
    }

    pub fn compute_s_times_b_k_tau(
        &self,
        s: &Vector,
        b_kjb_g1: &Vec<Vec<Matrix<G1>>>,
        tau: &Vec<usize>,
    ) -> Vec<G1> {
        let lambda = tau.len();
        let cols = b_kjb_g1[0][0][0].len();

        let mut result = vector_zero::<G1>(cols);

        for col in 0..cols {
            let mut bases = Vec::with_capacity(lambda * s.len());
            let mut scalars = Vec::with_capacity(lambda * s.len());

            for j in 0..lambda {
                let tau_j = tau[j];
                for row in 0..s.len() {
                    bases.push(b_kjb_g1[j][tau_j][row][col]);
                    scalars.push(s[row]);
                }
            }

            let bases_affine: Vec<G1Affine> = bases.iter().map(|g| g.into_affine()).collect();
            let scalars_repr: Vec<_> = scalars.iter().map(|s| s.into_repr()).collect();
            result[col] = VariableBaseMSM::multi_scalar_mul(&bases_affine, &scalars_repr);
        }

        result
    }

    pub fn prove(&self, crs: &CRS, tag: &[u8], c0_g1: &Vec<G1>, r: &Vector) -> QANIZKProof {
        let s = random_vector(self.k);
        let t1_g1 = group_matrix_vector_mul_msm(&crs.b_g1, &s);

        let hash_input = self.hash_tag_c0_t1(tag, c0_g1, &t1_g1);
        let tau = blake3_hash_to_bits(&hash_input, self.lambda);

        let mk_g1_transpose = matrix_transpose(&crs.mk_g1);
        let r_mk = group_matrix_vector_mul_msm(&mk_g1_transpose, &r);
        let s_b_k_tau = self.compute_s_times_b_k_tau(&s, &crs.b_kjb_g1, &tau);

        let u1_g1 = vector_add_g1(&r_mk, &s_b_k_tau);

        QANIZKProof { t1_g1, u1_g1 }
    }

    fn compute_k_tau_a_from_crs(&self, kjb_a_g2: &[Vec<Matrix<G2>>], tau: &[usize]) -> Matrix<G2> {
        let lambda = tau.len();
        assert_eq!(kjb_a_g2.len(), lambda);
        assert_ne!(lambda, 0);

        let rows = kjb_a_g2[0][0].len();
        let cols = kjb_a_g2[0][0][0].len();

        let mut k_tau_a = matrix_zero::<G2>(rows, cols);

        for j in 0..lambda {
            let tau_j = tau[j];
            assert!(tau_j <= 1);

            let kj_tauj_a = &kjb_a_g2[j][tau_j];

            for row in 0..rows {
                for col in 0..cols {
                    k_tau_a[row][col] = k_tau_a[row][col] + kj_tauj_a[row][col];
                }
            }
        }
        k_tau_a
    }

    pub fn verify(&self, crs: &CRS, tag: &[u8], c0_g1: &Vec<G1>, pi: &QANIZKProof) -> bool {
        let t1_g1 = &pi.t1_g1;
        let u1_g1 = &pi.u1_g1;

        let hash_input = self.hash_tag_c0_t1(tag, c0_g1, t1_g1);
        let tau = blake3_hash_to_bits(&hash_input, self.lambda);

        assert_eq!(u1_g1.len(), self.k + 1);
        assert_eq!(t1_g1.len(), self.k);
        assert_eq!(c0_g1.len(), crs.ka_g2.len());
        assert_eq!(tau.len(), self.lambda);
        assert_eq!(crs.kjb_a_g2.len(), self.lambda);
        assert_eq!(crs.a_g2.len(), self.k + 1);
        assert_eq!(crs.a_g2[0].len(), self.k);

        let k_tau_a = self.compute_k_tau_a_from_crs(&crs.kjb_a_g2, &tau);

        let mut all_pairings = Vec::new();
        for (i, &u1_elem) in u1_g1.iter().enumerate() {
            for &a_elem in crs.a_g2[i].iter() {
                all_pairings.push((u1_elem, a_elem));
            }
        }

        for (i, &c0_elem) in c0_g1.iter().enumerate() {
            for &ka_elem in crs.ka_g2[i].iter() {
                all_pairings.push((-c0_elem, ka_elem));
            }
        }

        assert_eq!(k_tau_a.len(), t1_g1.len());
        for (i, &t1_elem) in t1_g1.iter().enumerate() {
            for &ktau_elem in k_tau_a[i].iter() {
                all_pairings.push((-t1_elem, ktau_elem));
            }
        }

        assert!(!all_pairings.is_empty());
        self.group.multi_pairing(&all_pairings) == GTElement::one()
    }
}

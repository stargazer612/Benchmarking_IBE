use ark_bls12_381::{G1Affine, G1Projective, G2Projective};
use ark_ec::{ProjectiveCurve, msm::VariableBaseMSM};
use ark_ff::{PrimeField, UniformRand, Zero};
use blake3;
use rand::{Rng, thread_rng};

use crate::{FieldElement, Matrix, Vector};

pub trait FieldUtils {
    fn random_field_element() -> FieldElement;
    fn random_vector(len: usize) -> Vector;
    fn random_matrix(rows: usize, cols: usize) -> Matrix;
    fn matrix_vector_mul(matrix: &Matrix, vector: &Vector) -> Vector;
    fn vector_add(a: &Vector, b: &Vector) -> Vector;
    fn scalar_vector_mul(scalar: FieldElement, vector: &Vector) -> Vector;
    fn matrix_multiply(&self, a: &Matrix, b: &Matrix) -> Matrix;
    fn concatenate_matrices(&self, a: &Matrix, b: &Matrix) -> Matrix;
    fn concatenate_vectors(&self, a: &Vector, b: &Vector) -> Vector;
    fn transpose_matrix(&self, matrix: &Matrix) -> Matrix;
    fn group_matrix_vector_mul_msm(
        matrix_g1: &Vec<Vec<G1Projective>>,
        vector: &Vector,
    ) -> Vec<G1Projective>;
    fn g1_matrix_field_multiply(
        &self,
        left_g1: &Vec<Vec<G1Projective>>,
        right_field: &Matrix,
    ) -> Vec<Vec<G1Projective>>;
    fn transpose_g1_matrix(&self, matrix: &Vec<Vec<G1Projective>>) -> Vec<Vec<G1Projective>>;
    fn transpose_g2_matrix(&self, matrix: &Vec<Vec<G2Projective>>) -> Vec<Vec<G2Projective>>;
}

impl FieldUtils for () {
    fn random_field_element() -> FieldElement {
        let mut rng = thread_rng();
        FieldElement::rand(&mut rng)
    }

    fn random_vector(len: usize) -> Vector {
        (0..len).map(|_| Self::random_field_element()).collect()
    }

    fn random_matrix(rows: usize, cols: usize) -> Matrix {
        (0..rows).map(|_| Self::random_vector(cols)).collect()
    }

    fn matrix_vector_mul(matrix: &Matrix, vector: &Vector) -> Vector {
        matrix
            .iter()
            .map(|row| {
                row.iter()
                    .zip(vector.iter())
                    .map(|(&a, &b)| a * b)
                    .fold(FieldElement::zero(), |acc, x| acc + x)
            })
            .collect()
    }

    fn vector_add(a: &Vector, b: &Vector) -> Vector {
        a.iter().zip(b.iter()).map(|(&x, &y)| x + y).collect()
    }

    fn scalar_vector_mul(scalar: FieldElement, vector: &Vector) -> Vector {
        vector.iter().map(|&x| scalar * x).collect()
    }

    fn matrix_multiply(&self, a: &Matrix, b: &Matrix) -> Matrix {
        let rows_a = a.len();
        let cols_a = a[0].len();
        let cols_b = b[0].len();
        assert_eq!(
            cols_a,
            b.len(),
            "Matrix dimensions don't match for multiplication"
        );

        let mut result = vec![vec![FieldElement::zero(); cols_b]; rows_a];
        for i in 0..rows_a {
            for j in 0..cols_b {
                for k in 0..cols_a {
                    result[i][j] += a[i][k] * b[k][j];
                }
            }
        }
        result
    }

    fn concatenate_matrices(&self, a: &Matrix, b: &Matrix) -> Matrix {
        assert_eq!(a.len(), b.len(), "Matrices must have same number of rows");
        let mut result = Vec::with_capacity(a.len());
        for i in 0..a.len() {
            let mut row = a[i].clone();
            row.extend_from_slice(&b[i]);
            result.push(row);
        }
        result
    }

    fn concatenate_vectors(&self, a: &Vector, b: &Vector) -> Vector {
        let mut result = a.clone();
        result.extend_from_slice(b);
        result
    }

    fn transpose_matrix(&self, matrix: &Matrix) -> Matrix {
        if matrix.is_empty() {
            return Vec::new();
        }

        let rows = matrix.len();
        let cols = matrix[0].len();
        let mut result = vec![vec![FieldElement::zero(); rows]; cols];
        for i in 0..rows {
            for j in 0..cols {
                result[j][i] = matrix[i][j];
            }
        }
        result
    }

    fn group_matrix_vector_mul_msm(
        matrix_g1: &Vec<Vec<G1Projective>>,
        vector: &Vector,
    ) -> Vec<G1Projective> {
        matrix_g1
            .iter()
            .map(|row| {
                let row_affine: Vec<G1Affine> = row.iter().map(|g| g.into_affine()).collect();

                let scalars_repr: Vec<<FieldElement as PrimeField>::BigInt> =
                    vector.iter().map(|s| s.into_repr()).collect();

                VariableBaseMSM::multi_scalar_mul(&row_affine, &scalars_repr)
            })
            .collect()
    }

    fn g1_matrix_field_multiply(
        &self,
        left_g1: &Vec<Vec<G1Projective>>,
        right_field: &Matrix,
    ) -> Vec<Vec<G1Projective>> {
        let rows_left = left_g1.len();
        let cols_left = left_g1[0].len();
        let rows_right = right_field.len();
        let cols_right = right_field[0].len();

        assert_eq!(
            cols_left, rows_right,
            "Matrix dimensions don't match for multiplication"
        );

        let mut result = vec![vec![G1Projective::zero(); cols_right]; rows_left];

        for i in 0..rows_left {
            for j in 0..cols_right {
                let mut sum = G1Projective::zero();
                for k in 0..cols_left {
                    let scaled = left_g1[i][k].mul(right_field[k][j].into_repr());
                    sum = sum + scaled;
                }
                result[i][j] = sum;
            }
        }

        result
    }

    fn transpose_g1_matrix(&self, matrix: &Vec<Vec<G1Projective>>) -> Vec<Vec<G1Projective>> {
        if matrix.is_empty() {
            return Vec::new();
        }

        let rows = matrix.len();
        let cols = matrix[0].len();
        let mut transposed = vec![vec![G1Projective::zero(); rows]; cols];
        for i in 0..rows {
            for j in 0..cols {
                transposed[j][i] = matrix[i][j];
            }
        }

        transposed
    }

    fn transpose_g2_matrix(&self, matrix: &Vec<Vec<G2Projective>>) -> Vec<Vec<G2Projective>> {
        if matrix.is_empty() {
            return Vec::new();
        }

        let rows = matrix.len();
        let cols = matrix[0].len();
        let mut transposed = vec![vec![G2Projective::zero(); rows]; cols];
        for i in 0..rows {
            for j in 0..cols {
                transposed[j][i] = matrix[i][j];
            }
        }

        transposed
    }
}

pub fn blake3_hash_to_bits(input: &[u8], num_bits: usize) -> Vec<usize> {
    let hash = blake3::hash(input);
    let hash_bytes = hash.as_bytes();
    let mut bits = Vec::new();

    for i in 0..num_bits {
        let byte_idx = i / 8;
        let bit_idx = i % 8;

        if byte_idx < hash_bytes.len() {
            let bit = (hash_bytes[byte_idx] >> bit_idx) & 1;
            bits.push(bit as usize);
        } else {
            bits.push(0);
        }
    }

    bits
}

pub fn blake3_hash_bytes(input: &[u8]) -> Vec<u8> {
    let hash = blake3::hash(input);
    hash.as_bytes().to_vec()
}

pub fn generate_random_message_128() -> Vec<u8> {
    (0..16).map(|_| rand::random::<u8>()).collect()
}

pub fn generate_random_email() -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let chars = b"abcdefghijklmnopqrstuvwxyz0123456789";

    let name_len = rng.gen_range(6..12);
    let domain_len = rng.gen_range(5..10);

    let name: String = (0..name_len)
        .map(|_| chars[rng.gen_range(0..chars.len())] as char)
        .collect();

    let domain: String = (0..domain_len)
        .map(|_| chars[rng.gen_range(0..chars.len())] as char)
        .collect();

    let tld_chars = b"abcdefghijklmnopqrstuvwxyz";
    let tld_len = rng.gen_range(2..4);
    let tld: String = (0..tld_len)
        .map(|_| tld_chars[rng.gen_range(0..tld_chars.len())] as char)
        .collect();

    let email = format!("{}@{}.{}", name, domain, tld);
    email.into_bytes()
}

pub fn generate_email_and_hash_identity(bits: usize) -> (Vec<u8>, Vec<u8>) {
    let email = generate_random_email();
    let hash_bits = blake3_hash_to_bits(&email, bits);

    let mut identity = Vec::new();
    for chunk in hash_bits.chunks(8) {
        let mut byte = 0u8;
        for (i, &bit) in chunk.iter().enumerate() {
            if bit == 1 {
                byte |= 1 << i;
            }
        }
        identity.push(byte);
    }

    (email, identity)
}

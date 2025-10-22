use ark_bls12_381::{G1Affine, G1Projective, G2Projective};
use ark_ec::{ProjectiveCurve, msm::VariableBaseMSM};
use ark_ff::{PrimeField, UniformRand, Zero};
use rand::thread_rng;

use crate::{FieldElement, Matrix, Vector};

pub fn random_field_element() -> FieldElement {
    let mut rng = thread_rng();
    FieldElement::rand(&mut rng)
}

pub fn random_vector(len: usize) -> Vector {
    (0..len).map(|_| random_field_element()).collect()
}

pub fn random_matrix(rows: usize, cols: usize) -> Matrix {
    (0..rows).map(|_| random_vector(cols)).collect()
}

pub fn matrix_vector_mul(matrix: &Matrix, vector: &Vector) -> Vector {
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

pub fn vector_add(a: &Vector, b: &Vector) -> Vector {
    a.iter().zip(b.iter()).map(|(&x, &y)| x + y).collect()
}

pub fn scalar_vector_mul(scalar: FieldElement, vector: &Vector) -> Vector {
    vector.iter().map(|&x| scalar * x).collect()
}

pub fn matrix_multiply(a: &Matrix, b: &Matrix) -> Matrix {
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

pub fn concatenate_matrices(a: &Matrix, b: &Matrix) -> Matrix {
    assert_eq!(a.len(), b.len(), "Matrices must have same number of rows");
    let mut result = Vec::with_capacity(a.len());
    for i in 0..a.len() {
        let mut row = a[i].clone();
        row.extend_from_slice(&b[i]);
        result.push(row);
    }
    result
}

pub fn concatenate_vectors(a: &Vector, b: &Vector) -> Vector {
    let mut result = a.clone();
    result.extend_from_slice(b);
    result
}

pub fn transpose_matrix(matrix: &Matrix) -> Matrix {
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

pub fn group_matrix_vector_mul_msm(
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

pub fn g1_matrix_field_multiply(
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

pub fn transpose_g1_matrix(matrix: &Vec<Vec<G1Projective>>) -> Vec<Vec<G1Projective>> {
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

pub fn transpose_g2_matrix(matrix: &Vec<Vec<G2Projective>>) -> Vec<Vec<G2Projective>> {
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

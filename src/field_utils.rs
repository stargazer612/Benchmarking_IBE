use ark_bls12_381::{G1Affine, G1Projective as G1, G2Affine, G2Projective as G2};
use ark_ec::{CurveGroup, VariableBaseMSM};
use ark_ff::{UniformRand, Zero};
use ark_std::ops::Add;
use rand::thread_rng;

use crate::group_functions::{scalar_mul_g1, scalar_mul_g2};
use crate::{FieldElement, Matrix, Vector};

pub fn random_field_element() -> FieldElement {
    let mut rng = thread_rng();
    FieldElement::rand(&mut rng)
}

pub fn random_vector(len: usize) -> Vector {
    (0..len).map(|_| random_field_element()).collect()
}

pub fn random_matrix(rows: usize, cols: usize) -> Matrix<FieldElement> {
    (0..rows).map(|_| random_vector(cols)).collect()
}

pub fn matrix_vector_mul(matrix: &Matrix<FieldElement>, vector: &Vector) -> Vector {
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

pub fn vector_add_g1(a: &Vec<G1>, b: &Vec<G1>) -> Vec<G1> {
    a.iter().zip(b.iter()).map(|(x, y)| *x + *y).collect()
}

pub fn vector_add_g2(a: &Vec<G2>, b: &Vec<G2>) -> Vec<G2> {
    a.iter().zip(b.iter()).map(|(x, y)| *x + *y).collect()
}

pub fn vector_dot_g1(a: &Vector, b: &Vec<G1>) -> G1 {
    assert_eq!(a.len(), b.len());
    let mut sum = G1::zero();
    for i in 0..a.len() {
        sum += b[i] * a[i];
    }
    sum
}

pub fn scalar_vector_mul(scalar: FieldElement, vector: &Vector) -> Vector {
    vector.iter().map(|&x| scalar * x).collect()
}

pub fn matrix_multiply(a: &Matrix<FieldElement>, b: &Matrix<FieldElement>) -> Matrix<FieldElement> {
    let rows_a = a.len();
    let cols_a = a[0].len();
    let cols_b = b[0].len();
    assert_eq!(cols_a, b.len());

    let mut result = matrix_zero::<FieldElement>(rows_a, cols_b);
    for i in 0..rows_a {
        for j in 0..cols_b {
            for k in 0..cols_a {
                result[i][j] += a[i][k] * b[k][j];
            }
        }
    }
    result
}

pub fn matrix_multiply_scalar(a: &Matrix<G1>, x: FieldElement) -> Matrix<G1> {
    assert!(!a.is_empty());
    assert!(!a[0].is_empty());
    let rows = a.len();
    let cols = a[0].len();
    let mut result = matrix_zero::<G1>(rows, cols);
    for i in 0..rows {
        for j in 0..cols {
            result[i][j] = a[i][j] * x;
        }
    }
    result
}

pub fn matrix_add<T: Zero + Copy + Add>(a: &Matrix<T>, b: &Matrix<T>) -> Matrix<T> {
    let rows_a = a.len();
    let cols_a = a[0].len();
    let rows_b = b.len();
    let cols_b = b[0].len();
    assert_eq!(rows_a, rows_b);
    assert_eq!(cols_a, cols_b);

    let mut result = matrix_zero::<T>(rows_a, cols_a);
    for i in 0..rows_a {
        for j in 0..cols_a {
            result[i][j] = a[i][j] + b[i][j];
        }
    }
    result
}

pub fn matrix_zero<T: Zero + Copy>(rows: usize, cols: usize) -> Matrix<T> {
    vec![vec![T::zero(); cols]; rows]
}

pub fn vector_zero<T: Zero + Copy>(len: usize) -> Vec<T> {
    vec![T::zero(); len]
}

pub fn vector_lift_g1(v: &Vector) -> Vec<G1> {
    v.iter().map(|&e| scalar_mul_g1(e)).collect()
}

pub fn vector_lift_g2(v: &Vector) -> Vec<G2> {
    v.iter().map(|&e| scalar_mul_g2(e)).collect()
}

pub fn matrix_lift_g1(m: &Matrix<FieldElement>) -> Matrix<G1> {
    m.iter()
        .map(|row| row.iter().map(|&e| scalar_mul_g1(e)).collect())
        .collect()
}

pub fn matrix_lift_g2(m: &Matrix<FieldElement>) -> Matrix<G2> {
    m.iter()
        .map(|row| row.iter().map(|&e| scalar_mul_g2(e)).collect())
        .collect()
}

pub fn matrix_concat<T: Copy>(a: &Matrix<T>, b: &Matrix<T>) -> Matrix<T> {
    assert_eq!(a.len(), b.len());
    let mut result = Vec::with_capacity(a.len());
    for i in 0..a.len() {
        let mut row = a[i].clone();
        row.extend_from_slice(&b[i]);
        result.push(row);
    }
    result
}

pub fn vector_concat(a: &Vector, b: &Vector) -> Vector {
    let mut result = a.clone();
    result.extend_from_slice(b);
    result
}

pub fn matrix_transpose<T: Zero + Copy>(matrix: &Matrix<T>) -> Matrix<T> {
    assert!(!matrix.is_empty());

    let rows = matrix.len();
    let cols = matrix[0].len();
    let mut result = matrix_zero::<T>(cols, rows);
    for i in 0..rows {
        for j in 0..cols {
            result[j][i] = matrix[i][j];
        }
    }
    result
}

pub fn group_matrix_vector_mul_msm(matrix_g1: &Matrix<G1>, vector: &Vector) -> Vec<G1> {
    matrix_g1
        .iter()
        .map(|row| {
            let row_affine: Vec<G1Affine> = row.iter().map(|g| g.into_affine()).collect();
            G1::msm(&row_affine, &vector).unwrap()
        })
        .collect()
}

pub fn matrix_vector_g2_mul_msm(matrix: &Matrix<FieldElement>, vector_g2: &Vec<G2>) -> Vec<G2> {
    let vec_g2_affine: Vec<G2Affine> = vector_g2.iter().map(|g| g.into_affine()).collect();

    matrix
        .iter()
        .map(|row| G2::msm(&vec_g2_affine, &row).unwrap())
        .collect()
}

pub fn g1_matrix_field_multiply(
    left_g1: &Matrix<G1>,
    right_field: &Matrix<FieldElement>,
) -> Matrix<G1> {
    let rows_left = left_g1.len();
    let cols_left = left_g1[0].len();
    let rows_right = right_field.len();
    let cols_right = right_field[0].len();

    assert_eq!(cols_left, rows_right);

    let mut result = matrix_zero::<G1>(rows_left, cols_right);

    for i in 0..rows_left {
        for j in 0..cols_right {
            let mut sum = G1::zero();
            for k in 0..cols_left {
                let scaled = left_g1[i][k] * right_field[k][j];
                sum = sum + scaled;
            }
            result[i][j] = sum;
        }
    }

    result
}

////Joint operations
// Computes A^T * v 
pub fn matrix_transpose_vector_mul(matrix: &Matrix<FieldElement>, vector: &Vector) -> Vector {
    assert!(!matrix.is_empty());
    let rows = matrix.len();
    let cols = matrix[0].len();
    assert_eq!(rows, vector.len());
    
    let mut result = vec![FieldElement::zero(); cols];
    for j in 0..cols {
        for i in 0..rows {
            result[j] += matrix[i][j] * vector[i];
        }
    }
    result
}

// Computes (A || B) * C 
pub fn matrix_concat_multiply(a: &Matrix<FieldElement>, b: &Matrix<FieldElement>, c: &Matrix<FieldElement>) -> Matrix<FieldElement> {
    assert_eq!(a.len(), b.len());
    let rows = a.len();
    let cols_a = a[0].len();
    let cols_b = b[0].len();
    let cols_c = c[0].len();
    assert_eq!(cols_a + cols_b, c.len());
    
    let mut result = matrix_zero::<FieldElement>(rows, cols_c);
    for i in 0..rows {
        for j in 0..cols_c {
            for k in 0..cols_a {
                result[i][j] += a[i][k] * c[k][j];
            }
            for k in 0..cols_b {
                result[i][j] += b[i][k] * c[cols_a + k][j];
            }
        }
    }
    result
}

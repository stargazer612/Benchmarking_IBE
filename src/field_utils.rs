use ark_bls12_381::{G1Affine, G1Projective as G1, G2Projective as G2};
use ark_ec::{ProjectiveCurve, msm::VariableBaseMSM};
use ark_ff::{PrimeField, UniformRand, Zero};
use rand::thread_rng;

use crate::GroupCtx;
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
            result[i][j] = a[i][j].mul(x.into_repr());
        }
    }
    result
}

pub fn matrix_add_g1(a: &Matrix<G1>, b: &Matrix<G1>) -> Matrix<G1> {
    let rows_a = a.len();
    let cols_a = a[0].len();
    let rows_b = b.len();
    let cols_b = b[0].len();
    assert_eq!(rows_a, rows_b);
    assert_eq!(cols_a, cols_b);

    let mut result = matrix_zero::<G1>(rows_a, cols_a);
    for i in 0..rows_a {
        for j in 0..cols_a {
            result[i][j] = a[i][j] + b[i][j];
        }
    }
    result
}

pub fn matrix_add_g2(a: &Matrix<G2>, b: &Matrix<G2>) -> Matrix<G2> {
    let rows_a = a.len();
    let cols_a = a[0].len();
    let rows_b = b.len();
    let cols_b = b[0].len();
    assert_eq!(rows_a, rows_b);
    assert_eq!(cols_a, cols_b);

    let mut result = matrix_zero::<G2>(rows_a, cols_a);
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

pub fn vector_lift_g1(v: &Vector, group: &GroupCtx) -> Vec<G1> {
    v.iter().map(|&e| group.scalar_mul_p1(e)).collect()
}

pub fn vector_lift_g2(v: &Vector, group: &GroupCtx) -> Vec<G2> {
    v.iter().map(|&e| group.scalar_mul_p2(e)).collect()
}

pub fn matrix_lift_g1(m: &Matrix<FieldElement>, group: &GroupCtx) -> Matrix<G1> {
    m.iter()
        .map(|row| row.iter().map(|&e| group.scalar_mul_p1(e)).collect())
        .collect()
}

pub fn matrix_lift_g2(m: &Matrix<FieldElement>, group: &GroupCtx) -> Matrix<G2> {
    m.iter()
        .map(|row| row.iter().map(|&e| group.scalar_mul_p2(e)).collect())
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

            let scalars_repr: Vec<<FieldElement as PrimeField>::BigInt> =
                vector.iter().map(|s| s.into_repr()).collect();

            VariableBaseMSM::multi_scalar_mul(&row_affine, &scalars_repr)
        })
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
                let scaled = left_g1[i][k].mul(right_field[k][j].into_repr());
                sum = sum + scaled;
            }
            result[i][j] = sum;
        }
    }

    result
}

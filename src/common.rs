use ark_ec::{PairingEngine, ProjectiveCurve, msm::VariableBaseMSM};
use ark_bls12_381::{Bls12_381, Fr, G1Projective, G2Projective, G1Affine, G2Affine, Fq12};
use ark_ff::{PrimeField, UniformRand, Zero, Field};
use rand::thread_rng;
// use blake3;

pub type FieldElement = Fr;
pub type Matrix = Vec<Vec<FieldElement>>;
pub type Vector = Vec<FieldElement>;
pub type GTElement = Fq12;


pub struct GroupCtx {
    pub p1: G1Projective,
    pub p2: G2Projective,
    pub pt: GTElement,
}

impl GroupCtx {
    pub fn bls12_381() -> Self {
        let p1 = G1Projective::prime_subgroup_generator();
        let p2 = G2Projective::prime_subgroup_generator();
        //pt = e(p1,p2)
        let g1_affine: G1Affine = p1.into_affine();
        let g2_affine: G2Affine = p2.into_affine();
        let pt = Bls12_381::pairing(g1_affine, g2_affine);
        Self { p1, p2, pt }
    }

    pub fn scalar_mul_p1(&self, s: FieldElement) -> G1Projective {
        self.p1.mul(s.into_repr())
    }

    pub fn scalar_mul_p2(&self, s: FieldElement) -> G2Projective {
        self.p2.mul(s.into_repr())
    }

    pub fn scalar_expo_gt(&self, s: FieldElement) -> GTElement {
        // e(p1,p2)^s = pt^s
        self.pt.pow(s.into_repr())
    }

    pub fn pairing(&self, g1_elem: &G1Projective, g2_elem: &G2Projective) -> GTElement {
        let g1_affine: G1Affine = g1_elem.into_affine();
        let g2_affine: G2Affine = g2_elem.into_affine();
        Bls12_381::pairing(g1_affine, g2_affine)
    }

    pub fn multi_pairing(&self, pairs: &[(G1Projective, G2Projective)]) -> GTElement {
        let prepared_pairs: Vec<_> = pairs
            .iter()
            .map(|(g1, g2)| (
                <Bls12_381 as PairingEngine>::G1Prepared::from(g1.into_affine()),
                <Bls12_381 as PairingEngine>::G2Prepared::from(g2.into_affine())
            ))
            .collect();
        Bls12_381::product_of_pairings(prepared_pairs.iter())
    }
}

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
    fn group_matrix_vector_mul_direct(matrix_g1: &Vec<Vec<G1Projective>>,vector: &Vector) -> Vec<G1Projective>;    
    fn group_matrix_vector_mul_msm(matrix_g1: &Vec<Vec<G1Projective>>,vector: &Vector) -> Vec<G1Projective>;
    fn g1_matrix_field_multiply(&self, left_g1: &Vec<Vec<G1Projective>>, right_field: &Matrix) -> Vec<Vec<G1Projective>>;
    fn field_matrix_g1_multiply(&self,left_field: &Matrix,right_g1: &Vec<Vec<G1Projective>>) -> Vec<Vec<G1Projective>>;
    fn g1_matrix_field_vector_multiply(&self,matrix_g1: &Vec<Vec<G1Projective>>,vector_field: &Vector) -> Vec<G1Projective>;
    fn transpose_g1_matrix(&self, matrix: &Vec<Vec<G1Projective>>) -> Vec<Vec<G1Projective>>;
    fn transpose_g2_matrix(&self, matrix: &Vec<Vec<G2Projective>>) -> Vec<Vec<G2Projective>>;
    fn vector_g1_matrix_multiply(&self,vector_field: &Vector,matrix_g1: &Vec<Vec<G1Projective>>) -> Vec<G1Projective>;
    fn g1_vector_field_vector_dot(&self,g1_vector: &Vec<G1Projective>,field_vector: &Vector) -> G1Projective;
    fn vector_g2_matrix_multiply(&self,vector_field: &Vector,matrix_g2: &Vec<Vec<G2Projective>>) -> Vec<G2Projective>;
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
        matrix.iter().map(|row| {
            row.iter().zip(vector.iter())
                .map(|(&a, &b)| a * b)
                .fold(FieldElement::zero(), |acc, x| acc + x)
        }).collect()
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
        assert_eq!(cols_a, b.len(), "Matrix dimensions don't match for multiplication");

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

    fn group_matrix_vector_mul_direct(matrix_g1: &Vec<Vec<G1Projective>>, vector: &Vector) -> Vec<G1Projective> {
        matrix_g1.iter().map(|row| {
            
            let mut result = G1Projective::zero();
            for (g, &s) in row.iter().zip(vector.iter()) {
                if !s.is_zero() {
                    result += g.mul(s.into_repr());
                }
            }
            result
        }).collect()
    }
    
    fn group_matrix_vector_mul_msm(matrix_g1: &Vec<Vec<G1Projective>>, vector: &Vector) -> Vec<G1Projective> {
        matrix_g1.iter().map(|row| {
            
            let row_affine: Vec<G1Affine> = row.iter().map(|g| g.into_affine()).collect();
            
            let scalars_repr: Vec<<FieldElement as PrimeField>::BigInt> = vector.iter().map(|s| s.into_repr()).collect();
            
            VariableBaseMSM::multi_scalar_mul(&row_affine, &scalars_repr)
        }).collect()
    }

    fn g1_matrix_field_multiply(&self, left_g1: &Vec<Vec<G1Projective>>, right_field: &Matrix) -> Vec<Vec<G1Projective>> {
        let rows_left = left_g1.len();
        let cols_left = left_g1[0].len();
        let rows_right = right_field.len();
        let cols_right = right_field[0].len();
        
        assert_eq!(cols_left, rows_right, "Matrix dimensions don't match for multiplication");
        
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
    
    fn field_matrix_g1_multiply(&self,left_field: &Matrix,right_g1: &Vec<Vec<G1Projective>>) -> Vec<Vec<G1Projective>> {
        let rows_left = left_field.len();
        let cols_left = left_field[0].len();
        let rows_right = right_g1.len();
        let cols_right = right_g1[0].len();
        
        assert_eq!(cols_left, rows_right, "Matrix dimensions don't match for multiplication");
        let mut result = vec![vec![G1Projective::zero(); cols_right]; rows_left];
        for i in 0..rows_left {
            for j in 0..cols_right {
                let mut sum = G1Projective::zero();
                for k in 0..cols_left {
                    let scaled = right_g1[k][j].mul(left_field[i][k].into_repr());
                    sum = sum + scaled;
                }
                result[i][j] = sum;
            }
        }
        
        result
    }
    
    fn g1_matrix_field_vector_multiply(&self,matrix_g1: &Vec<Vec<G1Projective>>,vector_field: &Vector) -> Vec<G1Projective> {
        let rows = matrix_g1.len();
        let cols = matrix_g1[0].len();
        
        assert_eq!(cols, vector_field.len(), "Matrix-vector dimensions don't match");
        let mut result = vec![G1Projective::zero(); rows];
        for i in 0..rows {
            let mut sum = G1Projective::zero();
            for j in 0..cols {
                let scaled = matrix_g1[i][j].mul(vector_field[j].into_repr());
                sum = sum + scaled;
            }
            result[i] = sum;
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

    fn vector_g1_matrix_multiply(&self,vector_field: &Vector,matrix_g1: &Vec<Vec<G1Projective>>) -> Vec<G1Projective> {
        let vector_len = vector_field.len();
        let matrix_rows = matrix_g1.len();
        let matrix_cols = matrix_g1[0].len();
        
        assert_eq!(vector_len, matrix_rows, "Vector length must match matrix rows");
        
        let mut result = vec![G1Projective::zero(); matrix_cols];
        for j in 0..matrix_cols {
            let mut sum = G1Projective::zero();
            for i in 0..vector_len {
                let scaled = matrix_g1[i][j].mul(vector_field[i].into_repr());
                sum = sum + scaled;
            }
            result[j] = sum;
        }
        
        result
    }
    
    fn g1_vector_field_vector_dot(&self, g1_vector: &Vec<G1Projective>,field_vector: &Vector) -> G1Projective {
        assert_eq!(g1_vector.len(), field_vector.len(), "Vectors must have same length");
        
        let mut result = G1Projective::zero();
        
        for (g1_elem, &field_elem) in g1_vector.iter().zip(field_vector.iter()) {
            let scaled = g1_elem.mul(field_elem.into_repr());
            result = result + scaled;
        }
        
        result
    }

    fn vector_g2_matrix_multiply(&self, vector_field: &Vector,matrix_g2: &Vec<Vec<G2Projective>>) -> Vec<G2Projective> {
        let vector_len = vector_field.len();
        let matrix_rows = matrix_g2.len();
        let matrix_cols = matrix_g2[0].len();
        
        assert_eq!(vector_len, matrix_rows, "Vector length must match matrix rows");
        
        let mut result = vec![G2Projective::zero(); matrix_cols];
        
        for j in 0..matrix_cols {
            let mut sum = G2Projective::zero();
            for i in 0..vector_len {
                let scaled = matrix_g2[i][j].mul(vector_field[i].into_repr());
                sum = sum + scaled;
            }
            result[j] = sum;
        }
        
        result
    }
}

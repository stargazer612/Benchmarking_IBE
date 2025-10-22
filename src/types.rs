use ark_bls12_381::{Fq12, Fr};

pub type FieldElement = Fr;
pub type Matrix<T> = Vec<Vec<T>>;
pub type Vector = Vec<FieldElement>;
pub type GTElement = Fq12;

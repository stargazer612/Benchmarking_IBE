use ark_bls12_381::{Fq12, Fr};

pub type FieldElement = Fr;
pub type Matrix = Vec<Vec<FieldElement>>;
pub type Vector = Vec<FieldElement>;
pub type GTElement = Fq12;

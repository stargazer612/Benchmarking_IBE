use ark_bls12_381::{Bls12_381, G1Projective as G1, G2Projective as G2};
use ark_ec::{PrimeGroup, pairing::Pairing};

use ibe_schemes::gt_gen::gt_gen;

#[test]
fn gt_gen_correct() {
    let g1 = G1::generator();
    let g2 = G2::generator();

    let exp = Bls12_381::pairing(g1, g2).0;
    let rec = gt_gen();

    assert_eq!(exp, rec);
}

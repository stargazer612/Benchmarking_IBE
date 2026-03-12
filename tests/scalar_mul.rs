use ark_bls12_381::{Fq12 as Gt, Fr, G1Projective as G1, G2Projective as G2};
use ark_ff::Field;

use rand::thread_rng;

use ark_ff::{PrimeField, UniformRand};

use ibe_schemes::scalar_mul::*;

#[test]
fn test_random_k_ary_g1() {
    let mut rng = thread_rng();
    for _ in 0..100 {
        let g = G1::rand(&mut rng);
        let x = Fr::rand(&mut rng);

        let r1 = g * x;
        let r2 = k_ary_g1(g, x.into_bigint());
        assert_eq!(r1, r2);
    }
}

#[test]
fn test_random_k_ary_g2() {
    let mut rng = thread_rng();
    for _ in 0..100 {
        let g = G2::rand(&mut rng);
        let x = Fr::rand(&mut rng);

        let r1 = g * x;
        let r2 = k_ary_g2(g, x.into_bigint());
        assert_eq!(r1, r2);
    }
}

#[test]
fn test_random_k_ary_gt() {
    let mut rng = thread_rng();
    for _ in 0..100 {
        let gt = Gt::rand(&mut rng);
        let x = Fr::rand(&mut rng);

        let r1 = gt.pow(x.into_bigint());
        let r2 = k_ary_gt(gt, x.into_bigint());
        assert_eq!(r1, r2);
    }
}

#[test]
fn test_random_wnaf_g1() {
    let mut rng = thread_rng();
    for _ in 0..100 {
        let g1 = G1::rand(&mut rng);
        let x = Fr::rand(&mut rng);

        let r1 = g1 * x;
        let r2 = naf_g1(g1, x.into_bigint());
        assert_eq!(r1, r2);
    }
}

#[test]
fn test_random_wnaf_g2() {
    let mut rng = thread_rng();
    for _ in 0..100 {
        let g2 = G2::rand(&mut rng);
        let x = Fr::rand(&mut rng);

        let r1 = g2 * x;
        let r2 = naf_g2(g2, x.into_bigint());
        assert_eq!(r1, r2);
    }
}

#[test]
fn test_random_wnaf_gt() {
    let mut rng = thread_rng();
    for _ in 0..100 {
        let gt = Gt::rand(&mut rng);
        let x = Fr::rand(&mut rng);

        let r1 = gt.pow(x.into_bigint());
        let r2 = naf_gt(gt, x.into_bigint());
        assert_eq!(r1, r2);
    }
}

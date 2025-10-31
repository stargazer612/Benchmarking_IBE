use ark_bls12_381::Fq12 as Gt;
use ark_ff::UniformRand;

use ibe_schemes::bb::*;

use rand::thread_rng;

fn run_scheme(user_identity: &str, ct_identity: &str) -> (Gt, Option<Gt>) {
    let mut rng = thread_rng();

    let bb = BB::new();
    let (msk, mpk) = bb.setup(&mut rng);

    let usk = bb.keygen(&mut rng, &msk, String::from(user_identity));

    let k = Gt::rand(&mut rng);
    let ct = bb.encrypt(&mut rng, &k, &mpk, String::from(ct_identity));

    let dec = bb.decrypt(&usk, &ct);
    return (k, dec);
}

fn test_decrypt_ok(user_identity: &str, ct_identity: &str) {
    let (k, dec) = run_scheme(user_identity, ct_identity);
    assert!(dec.is_some_and(|k_dec| k_dec == k));
}

fn test_decrypt_fail(user_identity: &str, ct_identity: &str) {
    let (_, dec) = run_scheme(user_identity, ct_identity);
    assert!(dec.is_none());
}

#[test]
fn bb_minimal_ok() {
    test_decrypt_ok("A", "A");
}

#[test]
fn bb_longer_ok() {
    test_decrypt_ok("ABCDEFG", "ABCDEFG");
}

#[test]
fn bb_minimal_fail() {
    test_decrypt_fail("A", "B");
}

#[test]
fn bb_longer_fail() {
    test_decrypt_fail("ABCDEFG", "ABCDeFG");
}

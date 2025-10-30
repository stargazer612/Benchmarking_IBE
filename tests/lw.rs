use ark_bls12_381::Fq12 as Gt;
use ark_ff::UniformRand;

use ibe_schemes::*;

use rand::thread_rng;

fn parse_identity(id: &str) -> Vec<String> {
    id.split(".").map(|s| String::from(s)).collect()
}

#[test]
fn lw_decrypt_minimal_ok() {
    let mut rng = thread_rng();

    let lw = LW::new();
    let (msk, mpk) = lw.setup(&mut rng);

    let identity = parse_identity("A");

    let usk = lw.keygen(&mut rng, &msk, identity.clone());
    let k = Gt::rand(&mut rng);
    let ct = lw.encrypt(&mut rng, &k, &mpk, identity);
    let dec = lw.decrypt(&usk, &ct);

    assert!(dec.is_some_and(|k_dec| k_dec == k));
}

#[test]
fn lw_decrypt_exact_match_ok() {
    let mut rng = thread_rng();

    let lw = LW::new();
    let (msk, mpk) = lw.setup(&mut rng);

    let identity = parse_identity("A.B.C.D");

    let usk = lw.keygen(&mut rng, &msk, identity.clone());
    let k = Gt::rand(&mut rng);
    let ct = lw.encrypt(&mut rng, &k, &mpk, identity);
    let dec = lw.decrypt(&usk, &ct);

    assert!(dec.is_some_and(|k_dec| k_dec == k));
}

#[test]
fn lw_decrypt_superior_ok() {
    let mut rng = thread_rng();

    let lw = LW::new();
    let (msk, mpk) = lw.setup(&mut rng);

    let superior = parse_identity("A.B.C");
    let identity = parse_identity("A.B.C.D");

    let usk = lw.keygen(&mut rng, &msk, superior);
    let k = Gt::rand(&mut rng);
    let ct = lw.encrypt(&mut rng, &k, &mpk, identity);
    let dec = lw.decrypt(&usk, &ct);

    assert!(dec.is_some_and(|k_dec| k_dec == k));
}

#[test]
fn lw_decrypt_root_ok() {
    let mut rng = thread_rng();

    let lw = LW::new();
    let (msk, mpk) = lw.setup(&mut rng);

    let boss = parse_identity("A");
    let identity = parse_identity("A.B.C.D");

    let usk = lw.keygen(&mut rng, &msk, boss);
    let k = Gt::rand(&mut rng);
    let ct = lw.encrypt(&mut rng, &k, &mpk, identity);
    let dec = lw.decrypt(&usk, &ct);

    assert!(dec.is_some_and(|k_dec| k_dec == k));
}

#[test]
fn lw_decrypt_minimal_fail() {
    let mut rng = thread_rng();

    let lw = LW::new();
    let (msk, mpk) = lw.setup(&mut rng);

    let identity = parse_identity("A");
    let other = parse_identity("B");

    let usk = lw.keygen(&mut rng, &msk, identity);
    let k = Gt::rand(&mut rng);
    let ct = lw.encrypt(&mut rng, &k, &mpk, other);
    let dec = lw.decrypt(&usk, &ct);

    assert!(dec.is_none());
}

#[test]
fn lw_decrypt_hierarchy_mismatch_fail() {
    let mut rng = thread_rng();

    let lw = LW::new();
    let (msk, mpk) = lw.setup(&mut rng);

    let identity = parse_identity("A.B.C.D");
    let other = parse_identity("A.b.C.D");

    let usk = lw.keygen(&mut rng, &msk, identity);
    let k = Gt::rand(&mut rng);
    let ct = lw.encrypt(&mut rng, &k, &mpk, other);
    let dec = lw.decrypt(&usk, &ct);

    assert!(dec.is_none());
}

#[test]
fn lw_decrypt_inferior_fail() {
    let mut rng = thread_rng();

    let lw = LW::new();
    let (msk, mpk) = lw.setup(&mut rng);

    let inferior = parse_identity("A.B.C.D");
    let identity = parse_identity("A.B.C");

    let usk = lw.keygen(&mut rng, &msk, inferior);
    let k = Gt::rand(&mut rng);
    let ct = lw.encrypt(&mut rng, &k, &mpk, identity);
    let dec = lw.decrypt(&usk, &ct);

    assert!(dec.is_none());
}

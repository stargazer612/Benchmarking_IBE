use ark_bls12_381::Fq12 as Gt;
use ark_ff::UniformRand;

use ibe_schemes::lw::*;

use rand::thread_rng;

fn parse_identity(id: &str) -> Vec<String> {
    id.split(".").map(|s| String::from(s)).collect()
}

fn run_scheme(
    user_identity: &str,
    ct_identity: &str,
    identity_extension: Option<&str>,
) -> (Gt, Option<Gt>) {
    let mut rng = thread_rng();

    let lw = LW::new();
    let (msk, mpk) = lw.setup(&mut rng);

    let k = Gt::rand(&mut rng);
    let ct_identity = parse_identity(ct_identity);
    let ct = lw.encrypt(&mut rng, &k, &mpk, ct_identity);

    let user_identity = parse_identity(user_identity);
    let usk = lw.keygen(&mut rng, &msk, user_identity.clone());
    let usk = match identity_extension {
        None => usk,
        Some(id) => lw.delegate(
            &mut rng,
            &mpk,
            &usk,
            user_identity.clone(),
            String::from(id),
        ),
    };

    let dec = lw.decrypt(&usk, &ct);
    return (k, dec);
}

fn test_decrypt_ok(user_identity: &str, ct_identity: &str, identity_extension: Option<&str>) {
    let (k, dec) = run_scheme(user_identity, ct_identity, identity_extension);
    assert!(dec.is_some_and(|k_dec| k_dec == k));
}

fn test_decrypt_fail(user_identity: &str, ct_identity: &str, identity_extension: Option<&str>) {
    let (_, dec) = run_scheme(user_identity, ct_identity, identity_extension);
    assert!(dec.is_none());
}

#[test]
fn lw_minimal_ok() {
    test_decrypt_ok("A", "A", None);
}

#[test]
fn lw_exact_match_ok() {
    test_decrypt_ok("A.B.C.D", "A.B.C.D", None);
}

#[test]
fn lw_superior_ok() {
    test_decrypt_ok("A.B.C", "A.B.C.D", None);
}

#[test]
fn lw_root_ok() {
    test_decrypt_ok("A", "A.B.C", None);
}

#[test]
fn lw_minimal_fail() {
    test_decrypt_fail("A", "B", None);
}

#[test]
fn lw_hierarchy_mismatch_fail() {
    test_decrypt_fail("A.B.C.D", "A.b.C.D", None);
}

#[test]
fn lw_inferior_fail() {
    test_decrypt_fail("A.B.C.D", "A.B.C", None);
}

#[test]
fn lw_delegate_ok() {
    test_decrypt_ok("A.B.C", "A.B.C.D", Some("D"));
}

#[test]
fn lw_delegate_minimal_ok() {
    test_decrypt_ok("A", "A.B", Some("B"));
}

#[test]
fn lw_delegate_superior_ok() {
    test_decrypt_ok("A.B", "A.B.C.D", Some("C"));
}

#[test]
fn lw_delegate_hierarchy_mismatch_fail() {
    test_decrypt_fail("A.b.C", "A.B.C.D", Some("D"));
}

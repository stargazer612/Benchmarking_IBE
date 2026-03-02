use ark_bls12_381::Fq12 as Gt;
use ark_ff::UniformRand;

use ibe_schemes::pes::hiberla_dec::*;

use rand::thread_rng;

fn parse_identity(id: &str) -> Vec<String> {
    id.split(".").map(|s| String::from(s)).collect()
}

fn run_scheme(
    l: usize,
    user_identity: &str,
    ct_identity: &str,
    identity_extension: Option<&str>,
) -> (Gt, Option<Gt>) {
    let mut rng = thread_rng();

    let scheme = HiberlaDec::new(l);
    let (msk, mpk) = scheme.setup(&mut rng);

    let k = Gt::rand(&mut rng);
    let ct_identity = parse_identity(ct_identity);
    let ct = scheme.encrypt(&mut rng, &k, &mpk, ct_identity);

    let user_identity = parse_identity(user_identity);
    let usk = scheme.keygen(&mut rng, &msk, user_identity.clone());
    let usk = match identity_extension {
        None => usk,
        Some(id) => scheme.delegate(&mut rng, &mpk, &usk, String::from(id)),
    };

    let dec = scheme.decrypt(&usk, &ct);
    return (k, dec);
}

fn test_decrypt_ok(
    l: usize,
    user_identity: &str,
    ct_identity: &str,
    identity_extension: Option<&str>,
) {
    let (k, dec) = run_scheme(l, user_identity, ct_identity, identity_extension);
    assert!(dec.is_some_and(|k_dec| k_dec == k));
}

fn test_decrypt_fail(
    l: usize,
    user_identity: &str,
    ct_identity: &str,
    identity_extension: Option<&str>,
) {
    let (_, dec) = run_scheme(l, user_identity, ct_identity, identity_extension);
    assert!(dec.is_none());
}

#[test]
fn hiberla_minimal_ok() {
    test_decrypt_ok(1, "A", "A", None);
}

#[test]
fn hiberla_minimal_large_partition_ok() {
    test_decrypt_ok(3, "A", "A", None);
}

#[test]
fn hiberla_exact_match_ok() {
    test_decrypt_ok(4, "A.B.C.D", "A.B.C.D", None);
}

#[test]
fn hiberla_exact_match_perfect_partition_ok() {
    test_decrypt_ok(4, "A.B.C.D", "A.B.C.D", None);
}

#[test]
fn hiberla_exact_match_multi_partition_ok() {
    test_decrypt_ok(2, "A.B.C.D", "A.B.C.D", None);
}

#[test]
fn hiberla_exact_match_minimal_partition_ok() {
    test_decrypt_ok(1, "A.B.C.D", "A.B.C.D", None);
}

#[test]
fn hiberla_superior_single_partition_ok() {
    test_decrypt_ok(7, "A.B.C", "A.B.C.D", None);
}

#[test]
fn hiberla_superior_multi_partition_ok() {
    test_decrypt_ok(2, "A.B.C", "A.B.C.D", None);
}

#[test]
fn hiberla_root_single_partition_ok() {
    test_decrypt_ok(3, "A", "A.B.C", None);
}

#[test]
fn hiberla_root_minimal_partition_ok() {
    test_decrypt_ok(1, "A", "A.B.C", None);
}

#[test]
fn hiberla_minimal_fail() {
    test_decrypt_fail(1, "A", "B", None);
}

#[test]
fn hiberla_hierarchy_mismatch_single_partition_fail() {
    test_decrypt_fail(5, "A.B.C.D", "A.b.C.D", None);
}

#[test]
fn hiberla_hierarchy_mismatch_perfect_partition_fail() {
    test_decrypt_fail(4, "a.B.C.D", "A.b.C.D", None);
}

#[test]
fn hiberla_hierarchy_mismatch_multi_partition_fail() {
    test_decrypt_fail(3, "a.b.c.d", "A.b.C.D", None);
}

#[test]
fn hiberla_inferior_fail() {
    test_decrypt_fail(3, "A.B.C.D", "A.B.C", None);
}

#[test]
fn hiberla_inferior_minimal_partition_fail() {
    test_decrypt_fail(1, "A.B.C.D", "A.B.C", None);
}

#[test]
fn hiberla_inferior_large_parition_fail() {
    test_decrypt_fail(6, "A.B.C.D", "A.B.C", None);
}

#[test]
fn hiberla_delegate_single_partition_space_left_ok() {
    test_decrypt_ok(6, "A.B.C", "A.B.C.D", Some("D"));
}

#[test]
fn hiberla_delegate_single_partition_fully_filled_ok() {
    test_decrypt_ok(4, "A.B.C", "A.B.C.D", Some("D"));
}

#[test]
fn hiberla_delegate_multi_partition_space_left_ok() {
    test_decrypt_ok(3, "A.B.C.D", "A.B.C.D.E", Some("E"));
}

#[test]
fn hiberla_delegate_multi_partition_fully_filled_ok() {
    test_decrypt_ok(2, "A.B.C", "A.B.C.D", Some("D"));
}

#[test]
fn hiberla_delegate_single_partition_new_partition_ok() {
    test_decrypt_ok(3, "A.B.C", "A.B.C.D", Some("D"));
}

#[test]
fn hiberla_delegate_multi_partition_new_partition_ok() {
    test_decrypt_ok(3, "A.B.C.D.E.F", "A.B.C.D.E.F.G", Some("G"));
}

#[test]
fn hiberla_delegate_hierarchy_mismatch_fail() {
    test_decrypt_fail(4, "A.b.C", "A.B.C.D", Some("D"));
}

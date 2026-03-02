mod common;
use common::*;

use ibe_schemes::pes::lw::LW;

#[test]
fn lw_minimal_ok() {
    let scheme = LW::new();
    test_hibe_decrypt_ok(scheme, "A", "A", None);
}

#[test]
fn lw_exact_match_ok() {
    let scheme = LW::new();
    test_hibe_decrypt_ok(scheme, "A.B.C.D", "A.B.C.D", None);
}

#[test]
fn lw_superior_ok() {
    let scheme = LW::new();
    test_hibe_decrypt_ok(scheme, "A.B.C", "A.B.C.D", None);
}

#[test]
fn lw_root_ok() {
    let scheme = LW::new();
    test_hibe_decrypt_ok(scheme, "A", "A.B.C", None);
}

#[test]
fn lw_minimal_fail() {
    let scheme = LW::new();
    test_hibe_decrypt_fail(scheme, "A", "B", None);
}

#[test]
fn lw_hierarchy_mismatch_fail() {
    let scheme = LW::new();
    test_hibe_decrypt_fail(scheme, "A.B.C.D", "A.b.C.D", None);
}

#[test]
fn lw_inferior_fail() {
    let scheme = LW::new();
    test_hibe_decrypt_fail(scheme, "A.B.C.D", "A.B.C", None);
}

#[test]
fn lw_delegate_ok() {
    let scheme = LW::new();
    test_hibe_decrypt_ok(scheme, "A.B.C", "A.B.C.D", Some("D"));
}

#[test]
fn lw_delegate_minimal_ok() {
    let scheme = LW::new();
    test_hibe_decrypt_ok(scheme, "A", "A.B", Some("B"));
}

#[test]
fn lw_delegate_superior_ok() {
    let scheme = LW::new();
    test_hibe_decrypt_ok(scheme, "A.B", "A.B.C.D", Some("C"));
}

#[test]
fn lw_delegate_hierarchy_mismatch_fail() {
    let scheme = LW::new();
    test_hibe_decrypt_fail(scheme, "A.b.C", "A.B.C.D", Some("D"));
}

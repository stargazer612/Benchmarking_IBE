mod common;
pub use common::*;

use ibe_schemes::pes::hiberla_dec::HiberlaDec;

#[test]
fn hiberla_minimal_ok() {
    const PARTITION_SIZE: usize = 1;
    let scheme = HiberlaDec::new(PARTITION_SIZE);
    test_hibe_decrypt_ok(scheme, "A", "A");
}

#[test]
fn hiberla_minimal_large_partition_ok() {
    const PARTITION_SIZE: usize = 3;
    let scheme = HiberlaDec::new(PARTITION_SIZE);
    test_hibe_decrypt_ok(scheme, "A", "A");
}

#[test]
fn hiberla_exact_match_ok() {
    const PARTITION_SIZE: usize = 4;
    let scheme = HiberlaDec::new(PARTITION_SIZE);
    test_hibe_decrypt_ok(scheme, "A.B.C.D", "A.B.C.D");
}

#[test]
fn hiberla_exact_match_perfect_partition_ok() {
    const PARTITION_SIZE: usize = 4;
    let scheme = HiberlaDec::new(PARTITION_SIZE);
    test_hibe_decrypt_ok(scheme, "A.B.C.D", "A.B.C.D");
}

#[test]
fn hiberla_exact_match_multi_partition_ok() {
    const PARTITION_SIZE: usize = 2;
    let scheme = HiberlaDec::new(PARTITION_SIZE);
    test_hibe_decrypt_ok(scheme, "A.B.C.D", "A.B.C.D");
}

#[test]
fn hiberla_exact_match_minimal_partition_ok() {
    const PARTITION_SIZE: usize = 1;
    let scheme = HiberlaDec::new(PARTITION_SIZE);
    test_hibe_decrypt_ok(scheme, "A.B.C.D", "A.B.C.D");
}

#[test]
fn hiberla_superior_single_partition_ok() {
    const PARTITION_SIZE: usize = 7;
    let scheme = HiberlaDec::new(PARTITION_SIZE);
    test_hibe_decrypt_ok(scheme, "A.B.C", "A.B.C.D");
}

#[test]
fn hiberla_superior_multi_partition_ok() {
    const PARTITION_SIZE: usize = 2;
    let scheme = HiberlaDec::new(PARTITION_SIZE);
    test_hibe_decrypt_ok(scheme, "A.B.C", "A.B.C.D");
}

#[test]
fn hiberla_root_single_partition_ok() {
    const PARTITION_SIZE: usize = 3;
    let scheme = HiberlaDec::new(PARTITION_SIZE);
    test_hibe_decrypt_ok(scheme, "A", "A.B.C");
}

#[test]
fn hiberla_root_minimal_partition_ok() {
    const PARTITION_SIZE: usize = 1;
    let scheme = HiberlaDec::new(PARTITION_SIZE);
    test_hibe_decrypt_ok(scheme, "A", "A.B.C");
}

#[test]
fn hiberla_minimal_fail() {
    const PARTITION_SIZE: usize = 1;
    let scheme = HiberlaDec::new(PARTITION_SIZE);
    test_hibe_decrypt_fail(scheme, "A", "B");
}

#[test]
fn hiberla_hierarchy_mismatch_single_partition_fail() {
    const PARTITION_SIZE: usize = 5;
    let scheme = HiberlaDec::new(PARTITION_SIZE);
    test_hibe_decrypt_fail(scheme, "A.B.C.D", "A.b.C.D");
}

#[test]
fn hiberla_hierarchy_mismatch_perfect_partition_fail() {
    const PARTITION_SIZE: usize = 4;
    let scheme = HiberlaDec::new(PARTITION_SIZE);
    test_hibe_decrypt_fail(scheme, "a.B.C.D", "A.b.C.D");
}

#[test]
fn hiberla_hierarchy_mismatch_multi_partition_fail() {
    const PARTITION_SIZE: usize = 3;
    let scheme = HiberlaDec::new(PARTITION_SIZE);
    test_hibe_decrypt_fail(scheme, "a.b.c.d", "A.b.C.D");
}

#[test]
fn hiberla_inferior_fail() {
    const PARTITION_SIZE: usize = 3;
    let scheme = HiberlaDec::new(PARTITION_SIZE);
    test_hibe_decrypt_fail(scheme, "A.B.C.D", "A.B.C");
}

#[test]
fn hiberla_inferior_minimal_partition_fail() {
    const PARTITION_SIZE: usize = 1;
    let scheme = HiberlaDec::new(PARTITION_SIZE);
    test_hibe_decrypt_fail(scheme, "A.B.C.D", "A.B.C");
}

#[test]
fn hiberla_inferior_large_parition_fail() {
    const PARTITION_SIZE: usize = 6;
    let scheme = HiberlaDec::new(PARTITION_SIZE);
    test_hibe_decrypt_fail(scheme, "A.B.C.D", "A.B.C");
}

#[test]
fn hiberla_delegate_single_partition_space_left_ok() {
    const PARTITION_SIZE: usize = 6;
    let scheme = HiberlaDec::new(PARTITION_SIZE);
    test_hibe_delegate_ok(scheme, "A.B.C", "A.B.C.D", "D");
}

#[test]
fn hiberla_delegate_single_partition_fully_filled_ok() {
    const PARTITION_SIZE: usize = 4;
    let scheme = HiberlaDec::new(PARTITION_SIZE);
    test_hibe_delegate_ok(scheme, "A.B.C", "A.B.C.D", "D");
}

#[test]
fn hiberla_delegate_multi_partition_space_left_ok() {
    const PARTITION_SIZE: usize = 3;
    let scheme = HiberlaDec::new(PARTITION_SIZE);
    test_hibe_delegate_ok(scheme, "A.B.C.D", "A.B.C.D.E", "E");
}

#[test]
fn hiberla_delegate_multi_partition_fully_filled_ok() {
    const PARTITION_SIZE: usize = 2;
    let scheme = HiberlaDec::new(PARTITION_SIZE);
    test_hibe_delegate_ok(scheme, "A.B.C", "A.B.C.D", "D");
}

#[test]
fn hiberla_delegate_single_partition_new_partition_ok() {
    const PARTITION_SIZE: usize = 3;
    let scheme = HiberlaDec::new(PARTITION_SIZE);
    test_hibe_delegate_ok(scheme, "A.B.C", "A.B.C.D", "D");
}

#[test]
fn hiberla_delegate_multi_partition_new_partition_ok() {
    const PARTITION_SIZE: usize = 3;
    let scheme = HiberlaDec::new(PARTITION_SIZE);
    test_hibe_delegate_ok(scheme, "A.B.C.D.E.F", "A.B.C.D.E.F.G", "G");
}

#[test]
fn hiberla_delegate_hierarchy_mismatch_fail() {
    const PARTITION_SIZE: usize = 4;
    let scheme = HiberlaDec::new(PARTITION_SIZE);
    test_hibe_delegate_fail(scheme, "A.b.C", "A.B.C.D", "D");
}

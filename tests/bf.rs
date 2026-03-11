mod common;
pub use common::*;

use ibe_schemes::pes::bf::BF;

#[test]
fn bf_minimal_ok() {
    let scheme = BF::new();
    test_ibe_decrypt_ok(scheme, "A", "A");
}

#[test]
fn bf_longer_ok() {
    let scheme = BF::new();
    test_ibe_decrypt_ok(scheme, "ABCDEFG", "ABCDEFG");
}

#[test]
fn bf_minimal_fail() {
    let scheme = BF::new();
    test_ibe_decrypt_fail(scheme, "A", "B");
}

#[test]
fn bf_longer_fail() {
    let scheme = BF::new();
    test_ibe_decrypt_fail(scheme, "ABCDEFG", "ABCDeFG");
}

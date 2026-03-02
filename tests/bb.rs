mod common;
use common::*;

use ibe_schemes::pes::bb::BB;

#[test]
fn bb_minimal_ok() {
    let scheme = BB::new();
    test_ibe_decrypt_ok(scheme, "A", "A");
}

#[test]
fn bb_longer_ok() {
    let scheme = BB::new();
    test_ibe_decrypt_ok(scheme, "ABCDEFG", "ABCDEFG");
}

#[test]
fn bb_minimal_fail() {
    let scheme = BB::new();
    test_ibe_decrypt_fail(scheme, "A", "B");
}

#[test]
fn bb_longer_fail() {
    let scheme = BB::new();
    test_ibe_decrypt_fail(scheme, "ABCDEFG", "ABCDeFG");
}

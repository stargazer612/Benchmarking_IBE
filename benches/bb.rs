use criterion::{Criterion, criterion_group, criterion_main};

use ibe_schemes::pes::bb::*;

mod common;
use common::*;

// Performance of BB scheme should be independent of identity length
// const SIZES: [usize; 9] = [1, 2, 5, 10, 15, 20, 50, 100, 250];
const SIZES: [usize; 1] = [5];

pub fn bench_bb_setup(c: &mut Criterion) {
    bench_ibe_scheme_setup(BB::new(), c);
}

pub fn bench_bb_keygen(c: &mut Criterion) {
    bench_ibe_scheme_keygen(BB::new(), &SIZES, c);
}

pub fn bench_bb_encrypt(c: &mut Criterion) {
    bench_ibe_scheme_encrypt(BB::new(), &SIZES, c);
}

pub fn bench_bb_decrypt(c: &mut Criterion) {
    bench_ibe_scheme_decrypt(BB::new(), &SIZES, c);
}

criterion_group!(
    benches,
    bench_bb_setup,
    bench_bb_keygen,
    bench_bb_encrypt,
    bench_bb_decrypt,
);
criterion_main!(benches);

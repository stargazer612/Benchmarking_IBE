use criterion::{Criterion, criterion_group, criterion_main};

use ibe_schemes::pes::bf::*;

mod common;
use common::*;

// Performance of BF scheme should be independent of identity length
// const SIZES: [usize; 9] = [1, 2, 5, 10, 15, 20, 50, 100, 250];
const SIZES: [usize; 1] = [5];

pub fn bench_bf_setup(c: &mut Criterion) {
    bench_ibe_scheme_setup(BF::new(), c);
}

pub fn bench_bf_keygen(c: &mut Criterion) {
    bench_ibe_scheme_keygen(BF::new(), &SIZES, c);
}

pub fn bench_bf_encrypt(c: &mut Criterion) {
    bench_ibe_scheme_encrypt(BF::new(), &SIZES, c);
}

pub fn bench_bf_decrypt(c: &mut Criterion) {
    bench_ibe_scheme_decrypt(BF::new(), &SIZES, c);
}

criterion_group!(
    benches,
    bench_bf_setup,
    bench_bf_keygen,
    bench_bf_encrypt,
    bench_bf_decrypt,
);
criterion_main!(benches);

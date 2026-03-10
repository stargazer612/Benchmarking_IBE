use criterion::{Criterion, criterion_group, criterion_main};

use ibe_schemes::pes::lw::*;

mod common;
use common::*;

const DEPTHS: [usize; 9] = [1, 2, 5, 10, 15, 20, 50, 100, 250];
const ID_SIZE: usize = 5;

pub fn bench_lw_setup(c: &mut Criterion) {
    bench_hibe_scheme_setup(LW::new(), c);
}

pub fn bench_lw_keygen(c: &mut Criterion) {
    bench_hibe_scheme_keygen(LW::new(), &DEPTHS, ID_SIZE, c);
}

pub fn bench_lw_encrypt(c: &mut Criterion) {
    bench_hibe_scheme_encrypt(LW::new(), &DEPTHS, ID_SIZE, c);
}

pub fn bench_lw_decrypt(c: &mut Criterion) {
    bench_hibe_scheme_decrypt(LW::new(), &DEPTHS, ID_SIZE, c);
}

pub fn bench_lw_delegate(c: &mut Criterion) {
    bench_hibe_scheme_delegate(LW::new(), &DEPTHS, ID_SIZE, c);
}

criterion_group!(
    benches,
    bench_lw_setup,
    bench_lw_keygen,
    bench_lw_encrypt,
    bench_lw_decrypt,
    bench_lw_delegate
);
criterion_main!(benches);

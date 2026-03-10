use criterion::{Criterion, criterion_group, criterion_main};

use ibe_schemes::pes::hiberla_dec::*;

mod common;
use common::*;

const DEPTHS: [usize; 9] = [1, 2, 5, 10, 15, 20, 50, 100, 250];
const ID_SIZE: usize = 5;
const PARTITION_SIZE: usize = 4;

pub fn bench_hiberla_dec_setup(c: &mut Criterion) {
    bench_hibe_scheme_setup(HiberlaDec::new(PARTITION_SIZE), c);
}

pub fn bench_hiberla_dec_keygen(c: &mut Criterion) {
    bench_hibe_scheme_keygen(HiberlaDec::new(PARTITION_SIZE), &DEPTHS, ID_SIZE, c);
}

pub fn bench_hiberla_dec_encrypt(c: &mut Criterion) {
    bench_hibe_scheme_encrypt(HiberlaDec::new(PARTITION_SIZE), &DEPTHS, ID_SIZE, c);
}

pub fn bench_hiberla_dec_decrypt(c: &mut Criterion) {
    bench_hibe_scheme_decrypt(HiberlaDec::new(PARTITION_SIZE), &DEPTHS, ID_SIZE, c);
}

pub fn bench_hiberla_dec_delegate(c: &mut Criterion) {
    bench_hibe_scheme_delegate(HiberlaDec::new(PARTITION_SIZE), &DEPTHS, ID_SIZE, c);
}

criterion_group!(
    benches,
    bench_hiberla_dec_setup,
    bench_hiberla_dec_keygen,
    bench_hiberla_dec_encrypt,
    bench_hiberla_dec_decrypt,
    bench_hiberla_dec_delegate
);
criterion_main!(benches);

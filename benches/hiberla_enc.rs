use criterion::{Criterion, criterion_group, criterion_main};

use ibe_schemes::pes::hiberla_enc::*;

mod common;
use common::*;

const DEPTHS: [usize; 9] = [1, 2, 5, 10, 15, 20, 50, 100, 250];
const ID_SIZE: usize = 5;
const PARTITION_SIZE: usize = 4;

pub fn bench_hiberla_enc_setup(c: &mut Criterion) {
    bench_hibe_scheme_setup(HiberlaEnc::new(PARTITION_SIZE), c);
}

pub fn bench_hiberla_enc_keygen(c: &mut Criterion) {
    bench_hibe_scheme_keygen(HiberlaEnc::new(PARTITION_SIZE), &DEPTHS, ID_SIZE, c);
}

pub fn bench_hiberla_enc_encrypt(c: &mut Criterion) {
    bench_hibe_scheme_encrypt(HiberlaEnc::new(PARTITION_SIZE), &DEPTHS, ID_SIZE, c);
}

pub fn bench_hiberla_enc_decrypt(c: &mut Criterion) {
    bench_hibe_scheme_decrypt(HiberlaEnc::new(PARTITION_SIZE), &DEPTHS, ID_SIZE, c);
}

pub fn bench_hiberla_enc_delegate(c: &mut Criterion) {
    bench_hibe_scheme_delegate(HiberlaEnc::new(PARTITION_SIZE), &DEPTHS, ID_SIZE, c);
}

criterion_group!(
    benches,
    bench_hiberla_enc_setup,
    bench_hiberla_enc_keygen,
    bench_hiberla_enc_encrypt,
    bench_hiberla_enc_decrypt,
    bench_hiberla_enc_delegate
);
criterion_main!(benches);

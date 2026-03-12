use ark_bls12_381::{Fq12 as Gt, Fr, G1Projective as G1, G2Projective as G2};
use ark_ff::{Field, PrimeField, UniformRand};

use rand::thread_rng;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};

use ibe_schemes::scalar_mul::*;

pub fn bench_g1_k_ary(c: &mut Criterion) {
    let mut rng = thread_rng();
    c.bench_function("g1_k_ary", |b| {
        b.iter_batched(
            || {
                let g1 = G1::rand(&mut rng);
                let x = Fr::rand(&mut rng);
                (g1, x)
            },
            |(g1, x)| k_ary_g1(g1, x.into_bigint()),
            BatchSize::SmallInput,
        )
    });
}

pub fn bench_g1_naf(c: &mut Criterion) {
    let mut rng = thread_rng();
    c.bench_function("g1_naf", |b| {
        b.iter_batched(
            || {
                let g1 = G1::rand(&mut rng);
                let x = Fr::rand(&mut rng);
                (g1, x)
            },
            |(g1, x)| naf_g1(g1, x.into_bigint()),
            BatchSize::SmallInput,
        )
    });
}

pub fn bench_g1_scalar_mul(c: &mut Criterion) {
    let mut rng = thread_rng();
    c.bench_function("g1_scalar_mul", |b| {
        b.iter_batched(
            || {
                let g1 = G1::rand(&mut rng);
                let x = Fr::rand(&mut rng);
                (g1, x)
            },
            |(g1, x)| g1 * x,
            BatchSize::SmallInput,
        )
    });
}

pub fn bench_g2_k_ary(c: &mut Criterion) {
    let mut rng = thread_rng();
    c.bench_function("g2_k_ary", |b| {
        b.iter_batched(
            || {
                let g2 = G2::rand(&mut rng);
                let x = Fr::rand(&mut rng);
                (g2, x)
            },
            |(g2, x)| k_ary_g2(g2, x.into_bigint()),
            BatchSize::SmallInput,
        )
    });
}

pub fn bench_g2_naf(c: &mut Criterion) {
    let mut rng = thread_rng();
    c.bench_function("g2_naf", |b| {
        b.iter_batched(
            || {
                let g2 = G2::rand(&mut rng);
                let x = Fr::rand(&mut rng);
                (g2, x)
            },
            |(g2, x)| naf_g2(g2, x.into_bigint()),
            BatchSize::SmallInput,
        )
    });
}

pub fn bench_g2_scalar_mul(c: &mut Criterion) {
    let mut rng = thread_rng();
    c.bench_function("g2_scalar_mul", |b| {
        b.iter_batched(
            || {
                let g2 = G2::rand(&mut rng);
                let x = Fr::rand(&mut rng);
                (g2, x)
            },
            |(g2, x)| g2 * x,
            BatchSize::SmallInput,
        )
    });
}

pub fn bench_gt_k_ary(c: &mut Criterion) {
    let mut rng = thread_rng();
    c.bench_function("gt_k_ary", |b| {
        b.iter_batched(
            || {
                let gt = Gt::rand(&mut rng);
                let x = Fr::rand(&mut rng);
                (gt, x)
            },
            |(gt, x)| k_ary_gt(gt, x.into_bigint()),
            BatchSize::SmallInput,
        )
    });
}

pub fn bench_gt_naf(c: &mut Criterion) {
    let mut rng = thread_rng();
    c.bench_function("gt_k_naf", |b| {
        b.iter_batched(
            || {
                let gt = Gt::rand(&mut rng);
                let x = Fr::rand(&mut rng);
                (gt, x)
            },
            |(gt, x)| naf_gt(gt, x.into_bigint()),
            BatchSize::SmallInput,
        )
    });
}

pub fn bench_gt_pow(c: &mut Criterion) {
    let mut rng = thread_rng();
    c.bench_function("gt_pow", |b| {
        b.iter_batched(
            || {
                let gt = Gt::rand(&mut rng);
                let x = Fr::rand(&mut rng);
                (gt, x)
            },
            |(gt, x)| gt.pow(x.into_bigint()),
            BatchSize::SmallInput,
        )
    });
}

criterion_group!(
    benches,
    bench_g1_k_ary,
    bench_g1_naf,
    bench_g1_scalar_mul,
    bench_g2_k_ary,
    bench_g2_naf,
    bench_g2_scalar_mul,
    bench_gt_k_ary,
    bench_gt_naf,
    bench_gt_pow,
);
criterion_main!(benches);

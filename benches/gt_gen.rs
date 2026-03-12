use ark_bls12_381::{Bls12_381, G1Projective as G1, G2Projective as G2};
use ark_ec::{PrimeGroup, pairing::Pairing};

use ibe_schemes::gt_gen::gt_gen;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};

pub fn bench_pairing(c: &mut Criterion) {
    c.bench_function("pairing", |b| {
        b.iter_batched(
            || {
                let g1 = G1::generator();
                let g2 = G2::generator();
                (g1, g2)
            },
            |(g1, g2)| Bls12_381::pairing(g1, g2).0,
            BatchSize::SmallInput,
        )
    });
}

pub fn bench_gt_gen(c: &mut Criterion) {
    c.bench_function("gt_gen", |b| b.iter(|| gt_gen()));
}

criterion_group!(benches, bench_pairing, bench_gt_gen,);
criterion_main!(benches);

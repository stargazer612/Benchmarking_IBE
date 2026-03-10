use ark_bls12_381::Fq12 as Gt;
use ark_ff::UniformRand;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::time::Instant;

use std::hint::black_box as blb;

use ibe_schemes::pes::{IBEScheme, bb::*};

use rand::{Rng, thread_rng};

// Performance of BB scheme should be independent of identity length
// const SIZES: [usize; 9] = [1, 2, 5, 10, 15, 20, 50, 100, 250];
const SIZES: [usize; 1] = [5];

fn rand_string(len: usize) -> String {
    let mut rng = thread_rng();
    let chars = b"abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    (0..len)
        .map(|_| chars[rng.gen_range(0..chars.len())] as char)
        .collect()
}

pub fn bench_bb_new(c: &mut Criterion) {
    c.bench_function("bb_new", |b| b.iter(|| BB::new()));
}

pub fn bench_bb_setup(c: &mut Criterion) {
    let mut rng = thread_rng();
    let bb = BB::new();

    c.bench_function("bb_setup", |b| b.iter(|| bb.setup(&mut rng)));
}

pub fn bench_bb_keygen(c: &mut Criterion) {
    let mut rng = thread_rng();

    let mut group = c.benchmark_group("bb_keygen");
    for size in SIZES.iter() {
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            b.iter_custom(|n| {
                let bb = BB::new();
                let (msk, _) = bb.setup(&mut rng);

                let ids = (0..n).map(|_| rand_string(size)).collect::<Vec<_>>();

                let start = Instant::now();
                let res = ids
                    .into_iter()
                    .map(|id| bb.keygen(&mut rng, &msk, id))
                    .collect::<Vec<_>>();
                let time = start.elapsed();
                let _ = blb(res);
                time
            })
        });
    }
    group.finish();
}

pub fn bench_bb_encrypt(c: &mut Criterion) {
    let mut rng = thread_rng();

    let mut group = c.benchmark_group("bb_encrypt");
    for size in SIZES.iter() {
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            b.iter_custom(|n| {
                let bb = BB::new();
                let (_, mpk) = bb.setup(&mut rng);

                let ids = (0..n).map(|_| rand_string(size)).collect::<Vec<_>>();
                let ks = (0..n).map(|_| Gt::rand(&mut rng)).collect::<Vec<_>>();

                let start = Instant::now();
                let res = ids
                    .into_iter()
                    .zip(ks)
                    .map(|(id, k)| bb.encrypt(&mut rng, &k, &mpk, id))
                    .collect::<Vec<_>>();
                let time = start.elapsed();
                let _ = blb(res);
                time
            })
        });
    }
    group.finish();
}

pub fn bench_bb_decrypt(c: &mut Criterion) {
    let mut rng = thread_rng();

    let mut group = c.benchmark_group("bb_decrypt");
    for size in SIZES.iter() {
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            b.iter_custom(|n| {
                let bb = BB::new();
                let (msk, mpk) = bb.setup(&mut rng);

                let ids = (0..n).map(|_| rand_string(size)).collect::<Vec<_>>();
                let usks = ids
                    .iter()
                    .map(|i| bb.keygen(&mut rng, &msk, i.clone()))
                    .collect::<Vec<_>>();
                let ks = ids.iter().map(|_| Gt::rand(&mut rng)).collect::<Vec<_>>();
                let cts = ids
                    .iter()
                    .zip(ks)
                    .map(|(i, k)| bb.encrypt(&mut rng, &k, &mpk, i.clone()))
                    .collect::<Vec<_>>();

                let start = Instant::now();
                let res = usks
                    .iter()
                    .zip(cts)
                    .map(|(usk, ct)| bb.decrypt(&usk, &ct))
                    .collect::<Vec<_>>();
                let time = start.elapsed();
                let _ = blb(res);
                time
            })
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_bb_new,
    bench_bb_setup,
    bench_bb_keygen,
    bench_bb_encrypt,
    bench_bb_decrypt,
);
criterion_main!(benches);

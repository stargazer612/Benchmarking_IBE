use ark_bls12_381::Fq12 as Gt;
use ark_ff::UniformRand;

use rand::{Rng, thread_rng};

use criterion::{BenchmarkId, Criterion};
use std::time::Instant;

use std::hint::black_box as blb;

use ibe_schemes::pes::IBEScheme;

fn rand_string(len: usize) -> String {
    let mut rng = thread_rng();
    let chars = b"abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    (0..len)
        .map(|_| chars[rng.gen_range(0..chars.len())] as char)
        .collect()
}

pub fn bench_ibe_scheme_setup<T: IBEScheme>(scheme: T, c: &mut Criterion) {
    let desc = format!("{}_setup", scheme.name());
    let mut rng = thread_rng();
    c.bench_function(&desc, |b| b.iter(|| scheme.setup(&mut rng)));
}

pub fn bench_ibe_scheme_keygen<T: IBEScheme>(scheme: T, sizes: &[usize], c: &mut Criterion) {
    let mut rng = thread_rng();

    let desc = format!("{}_keygen", scheme.name());
    let mut group = c.benchmark_group(&desc);
    for size in sizes {
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            b.iter_custom(|n| {
                let (msk, _) = scheme.setup(&mut rng);

                let ids = (0..n).map(|_| rand_string(size)).collect::<Vec<_>>();

                let start = Instant::now();
                let res = ids
                    .into_iter()
                    .map(|id| scheme.keygen(&mut rng, &msk, id))
                    .collect::<Vec<_>>();
                let time = start.elapsed();
                let _ = blb(res);
                time
            })
        });
    }
    group.finish();
}

pub fn bench_ibe_scheme_encrypt<T: IBEScheme>(scheme: T, sizes: &[usize], c: &mut Criterion) {
    let mut rng = thread_rng();

    let desc = format!("{}_encrypt", scheme.name());
    let mut group = c.benchmark_group(&desc);
    for size in sizes {
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            b.iter_custom(|n| {
                let (_, mpk) = scheme.setup(&mut rng);

                let ids = (0..n).map(|_| rand_string(size)).collect::<Vec<_>>();
                let ks = (0..n).map(|_| Gt::rand(&mut rng)).collect::<Vec<_>>();

                let start = Instant::now();
                let res = ids
                    .into_iter()
                    .zip(ks)
                    .map(|(id, k)| scheme.encrypt(&mut rng, &k, &mpk, id))
                    .collect::<Vec<_>>();
                let time = start.elapsed();
                let _ = blb(res);
                time
            })
        });
    }
    group.finish();
}

pub fn bench_ibe_scheme_decrypt<T: IBEScheme>(scheme: T, sizes: &[usize], c: &mut Criterion) {
    let mut rng = thread_rng();

    let desc = format!("{}_decrypt", scheme.name());
    let mut group = c.benchmark_group(&desc);
    for size in sizes {
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            b.iter_custom(|n| {
                let (msk, mpk) = scheme.setup(&mut rng);

                let ids = (0..n).map(|_| rand_string(size)).collect::<Vec<_>>();
                let usks = ids
                    .iter()
                    .map(|i| scheme.keygen(&mut rng, &msk, i.clone()))
                    .collect::<Vec<_>>();
                let ks = ids.iter().map(|_| Gt::rand(&mut rng)).collect::<Vec<_>>();
                let cts = ids
                    .iter()
                    .zip(ks)
                    .map(|(i, k)| scheme.encrypt(&mut rng, &k, &mpk, i.clone()))
                    .collect::<Vec<_>>();

                let start = Instant::now();
                let res = usks
                    .iter()
                    .zip(cts)
                    .map(|(usk, ct)| scheme.decrypt(&usk, &ct))
                    .collect::<Vec<_>>();
                let time = start.elapsed();
                let _ = blb(res);
                time
            })
        });
    }
    group.finish();
}

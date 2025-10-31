use ark_bls12_381::Fq12 as Gt;
use ark_ff::UniformRand;

use criterion::{Criterion, criterion_group, criterion_main};

use std::hint::black_box as bb;

use ibe_schemes::bf::*;

use rand::thread_rng;

pub fn bench_bf_new(c: &mut Criterion) {
    c.bench_function("bf_new", |b| b.iter(|| BF::new()));
}

pub fn bench_bf_setup(c: &mut Criterion) {
    let mut rng = thread_rng();
    let bf = BF::new();

    c.bench_function("bf_setup", |b| b.iter(|| bf.setup(&mut rng)));
}

pub fn bench_bf_keygen(c: &mut Criterion) {
    let mut rng = thread_rng();
    let bf = BF::new();
    let (msk, _) = bf.setup(&mut rng);
    let identity = String::from("ABCDEF");

    c.bench_function("bf_keygen", |b| {
        b.iter(|| bf.keygen(bb(&mut rng), bb(&msk), bb(identity.clone())))
    });
}

pub fn bench_bf_encrypt(c: &mut Criterion) {
    let mut rng = thread_rng();
    let bf = BF::new();
    let (_, mpk) = bf.setup(&mut rng);
    let identity = String::from("ABCDEF");
    let k = Gt::rand(&mut rng);

    c.bench_function("bf_encrypt", |b| {
        b.iter(|| bf.encrypt(bb(&mut rng), bb(&k), bb(&mpk), bb(identity.clone())))
    });
}

pub fn bench_bf_decrypt(c: &mut Criterion) {
    let mut rng = thread_rng();
    let bf = BF::new();
    let (msk, mpk) = bf.setup(&mut rng);
    let identity = String::from("ABCDEF");
    let usk = bf.keygen(&mut rng, &msk, identity.clone());

    let k = Gt::rand(&mut rng);
    let ct = bf.encrypt(&mut rng, &k, &mpk, identity);

    c.bench_function("bf_decrypt", |b| b.iter(|| bf.decrypt(bb(&usk), bb(&ct))));
}

criterion_group!(
    benches,
    bench_bf_new,
    bench_bf_setup,
    bench_bf_keygen,
    bench_bf_encrypt,
    bench_bf_decrypt,
);
criterion_main!(benches);

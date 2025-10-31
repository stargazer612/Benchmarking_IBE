use ark_bls12_381::Fq12 as Gt;
use ark_ff::UniformRand;

use criterion::{Criterion, criterion_group, criterion_main};

use std::hint::black_box as blb;

use ibe_schemes::bb::*;

use rand::thread_rng;

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
    let bb = BB::new();
    let (msk, _) = bb.setup(&mut rng);
    let identity = String::from("ABCDEF");

    c.bench_function("bb_keygen", |b| {
        b.iter(|| bb.keygen(blb(&mut rng), blb(&msk), blb(identity.clone())))
    });
}

pub fn bench_bb_encrypt(c: &mut Criterion) {
    let mut rng = thread_rng();
    let bb = BB::new();
    let (_, mpk) = bb.setup(&mut rng);
    let identity = String::from("ABCDEF");
    let k = Gt::rand(&mut rng);

    c.bench_function("bb_encrypt", |b| {
        b.iter(|| bb.encrypt(blb(&mut rng), blb(&k), blb(&mpk), blb(identity.clone())))
    });
}

pub fn bench_bb_decrypt(c: &mut Criterion) {
    let mut rng = thread_rng();
    let bb = BB::new();
    let (msk, mpk) = bb.setup(&mut rng);
    let identity = String::from("ABCDEF");
    let usk = bb.keygen(&mut rng, &msk, identity.clone());

    let k = Gt::rand(&mut rng);
    let ct = bb.encrypt(&mut rng, &k, &mpk, identity);

    c.bench_function("bb_decrypt", |b| b.iter(|| bb.decrypt(blb(&usk), blb(&ct))));
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

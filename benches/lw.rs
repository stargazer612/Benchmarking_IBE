use ark_bls12_381::Fq12 as Gt;
use ark_ff::UniformRand;

use criterion::{Criterion, criterion_group, criterion_main};

use std::hint::black_box as bb;

use ibe_schemes::lw::*;

use rand::thread_rng;

fn parse_identity(id: &str) -> Vec<String> {
    id.split(".").map(|s| String::from(s)).collect()
}

pub fn bench_lw_new(c: &mut Criterion) {
    c.bench_function("lw_new", |b| b.iter(|| LW::new()));
}

pub fn bench_lw_setup(c: &mut Criterion) {
    let mut rng = thread_rng();
    let lw = LW::new();

    c.bench_function("lw_setup", |b| b.iter(|| lw.setup(&mut rng)));
}

pub fn bench_lw_keygen(c: &mut Criterion) {
    let mut rng = thread_rng();
    let lw = LW::new();
    let (msk, _) = lw.setup(&mut rng);
    let identity = parse_identity("A.B.C.D");

    c.bench_function("lw_keygen", |b| {
        b.iter(|| lw.keygen(bb(&mut rng), bb(&msk), bb(identity.clone())))
    });
}

pub fn bench_lw_encrypt(c: &mut Criterion) {
    let mut rng = thread_rng();
    let lw = LW::new();
    let (_, mpk) = lw.setup(&mut rng);
    let identity = parse_identity("A.B.C.D");
    let k = Gt::rand(&mut rng);

    c.bench_function("lw_encrypt", |b| {
        b.iter(|| lw.encrypt(bb(&mut rng), bb(&k), bb(&mpk), bb(identity.clone())))
    });
}

pub fn bench_lw_decrypt(c: &mut Criterion) {
    let mut rng = thread_rng();
    let lw = LW::new();
    let (msk, mpk) = lw.setup(&mut rng);
    let identity = parse_identity("A.B.C.D");
    let usk = lw.keygen(&mut rng, &msk, identity.clone());

    let k = Gt::rand(&mut rng);
    let ct = lw.encrypt(&mut rng, &k, &mpk, identity);

    c.bench_function("lw_decrypt", |b| b.iter(|| lw.decrypt(bb(&usk), bb(&ct))));
}

pub fn bench_lw_delegate(c: &mut Criterion) {
    let mut rng = thread_rng();
    let lw = LW::new();
    let (msk, mpk) = lw.setup(&mut rng);
    let identity = parse_identity("A.B.C.D");
    let usk = lw.keygen(&mut rng, &msk, identity.clone());

    let extension = String::from("E");

    c.bench_function("lw_delegate", |b| {
        b.iter(|| {
            lw.delegate(
                bb(&mut rng),
                bb(&mpk),
                bb(&usk),
                bb(identity.clone()),
                bb(extension.clone()),
            )
        })
    });
}

criterion_group!(
    benches,
    bench_lw_new,
    bench_lw_setup,
    bench_lw_keygen,
    bench_lw_encrypt,
    bench_lw_decrypt,
    bench_lw_delegate
);
criterion_main!(benches);

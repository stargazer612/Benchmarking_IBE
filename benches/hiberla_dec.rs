use ark_bls12_381::Fq12 as Gt;
use ark_ff::UniformRand;

use criterion::{Criterion, criterion_group, criterion_main};

use std::hint::black_box as bb;

use ibe_schemes::pes::{HIBEScheme, hiberla_dec::*};

use rand::thread_rng;

const PARTITION_SIZE: usize = 4;

fn parse_identity(id: &str) -> Vec<String> {
    id.split(".").map(|s| String::from(s)).collect()
}

pub fn bench_hiberla_dec_new(c: &mut Criterion) {
    let desc = format!("hiberla_dec_new (l={})", PARTITION_SIZE);
    c.bench_function(&desc, |b| b.iter(|| HiberlaDec::new(PARTITION_SIZE)));
}

pub fn bench_hiberla_dec_setup(c: &mut Criterion) {
    let mut rng = thread_rng();
    let scheme = HiberlaDec::new(PARTITION_SIZE);

    let desc = format!("hiberla_dec_setup (l={})", PARTITION_SIZE);
    c.bench_function(&desc, |b| b.iter(|| scheme.setup(&mut rng)));
}

pub fn bench_hiberla_dec_keygen(c: &mut Criterion) {
    let mut rng = thread_rng();
    let scheme = HiberlaDec::new(PARTITION_SIZE);
    let (msk, _) = scheme.setup(&mut rng);
    let identity = parse_identity("A.B.C.D");

    let desc = format!("hiberla_dec_keygen (l={})", PARTITION_SIZE);
    c.bench_function(&desc, |b| {
        b.iter(|| scheme.keygen(bb(&mut rng), bb(&msk), bb(identity.clone())))
    });
}

pub fn bench_hiberla_dec_encrypt(c: &mut Criterion) {
    let mut rng = thread_rng();
    let scheme = HiberlaDec::new(PARTITION_SIZE);
    let (_, mpk) = scheme.setup(&mut rng);
    let identity = parse_identity("A.B.C.D");
    let k = Gt::rand(&mut rng);

    let desc = format!("hiberla_dec_encrypt (l={})", PARTITION_SIZE);
    c.bench_function(&desc, |b| {
        b.iter(|| scheme.encrypt(bb(&mut rng), bb(&k), bb(&mpk), bb(identity.clone())))
    });
}

pub fn bench_hiberla_dec_decrypt(c: &mut Criterion) {
    let mut rng = thread_rng();
    let scheme = HiberlaDec::new(PARTITION_SIZE);
    let (msk, mpk) = scheme.setup(&mut rng);
    let identity = parse_identity("A.B.C.D");
    let usk = scheme.keygen(&mut rng, &msk, identity.clone());

    let k = Gt::rand(&mut rng);
    let ct = scheme.encrypt(&mut rng, &k, &mpk, identity);

    let desc = format!("hiberla_dec_decrypt (l={})", PARTITION_SIZE);
    c.bench_function(&desc, |b| b.iter(|| scheme.decrypt(bb(&usk), bb(&ct))));
}

pub fn bench_hiberla_dec_delegate(c: &mut Criterion) {
    let mut rng = thread_rng();
    let scheme = HiberlaDec::new(PARTITION_SIZE);
    let (msk, mpk) = scheme.setup(&mut rng);
    let identity = parse_identity("A.B.C.D");
    let usk = scheme.keygen(&mut rng, &msk, identity.clone());

    let extension = String::from("E");

    let desc = format!("hiberla_dec_delegate (l={})", PARTITION_SIZE);
    c.bench_function(&desc, |b| {
        b.iter(|| scheme.delegate(bb(&mut rng), bb(&mpk), bb(&usk), bb(extension.clone())))
    });
}

criterion_group!(
    benches,
    bench_hiberla_dec_new,
    bench_hiberla_dec_setup,
    bench_hiberla_dec_keygen,
    bench_hiberla_dec_encrypt,
    bench_hiberla_dec_decrypt,
    bench_hiberla_dec_delegate
);
criterion_main!(benches);

use criterion::{Criterion, criterion_group, criterion_main};

use std::hint::black_box as bb;

use ibe_schemes::*;

pub fn bench_ibkem1_new(c: &mut Criterion) {
    let k = 2;
    let msg_len = 128;

    c.bench_function("ibkem1_new (128)", |b| {
        b.iter(|| IBKEM1::new(bb(k), bb(msg_len)))
    });
}

pub fn bench_ibkem1_setup(c: &mut Criterion) {
    let k = 2;
    let msg_len = 128;
    let ibkem = IBKEM1::new(k, msg_len);

    c.bench_function("ibkem1_setup (128)", |b| b.iter(|| ibkem.setup()));
}

pub fn bench_ibkem1_extract(c: &mut Criterion) {
    let k = 2;
    let msg_len = 128;
    let ibkem = IBKEM1::new(k, msg_len);
    let (_, sk) = ibkem.setup();
    let (_, identity) = generate_email_and_hash_identity(128);

    c.bench_function("ibkem1_extract (128)", |b| {
        b.iter(|| ibkem.extract(bb(&sk), bb(&identity)))
    });
}

pub fn bench_ibkem1_encrypt(c: &mut Criterion) {
    let k = 2;
    let msg_len = 128;
    let ibkem = IBKEM1::new(k, msg_len);
    let (pk, _) = ibkem.setup();
    let (_, identity) = generate_email_and_hash_identity(128);

    c.bench_function("ibkem1_encrypt (128)", |b| {
        b.iter(|| ibkem.encrypt(bb(&pk), bb(&identity)))
    });
}

pub fn bench_ibkem1_decrypt(c: &mut Criterion) {
    let k = 2;
    let msg_len = 128;
    let ibkem = IBKEM1::new(k, msg_len);
    let (pk, sk) = ibkem.setup();
    let (_, identity) = generate_email_and_hash_identity(128);
    let usk = ibkem.extract(&sk, &identity);
    let (ct, _) = ibkem.encrypt(&pk, &identity);

    c.bench_function("ibkem1_decrypt (128)", |b| {
        b.iter(|| ibkem.decrypt(bb(&usk), bb(&ct)))
    });
}

criterion_group!(
    benches,
    bench_ibkem1_new,
    bench_ibkem1_setup,
    bench_ibkem1_extract,
    bench_ibkem1_encrypt,
    bench_ibkem1_decrypt
);
criterion_main!(benches);

use criterion::{Criterion, criterion_group, criterion_main};

use std::hint::black_box as bb;

use ibe_schemes::*;

pub fn bench_ibkem2_new(c: &mut Criterion) {
    let m_len = 128;
    let l = 2 * m_len + 1;
    let lambda = 128;
    let k = 2;

    c.bench_function("ibkem2_new (128)", |b| {
        b.iter(|| IBKEM::new_ibkem2(bb(k), bb(l), bb(0), bb(lambda)))
    });
}

pub fn bench_ibkem2_setup(c: &mut Criterion) {
    let m_len = 128;
    let l = 2 * m_len + 1;
    let lambda = 128;
    let k = 2;
    let ibkem = IBKEM::new_ibkem2(k, l, 0, lambda);

    c.bench_function("ibkem2_setup (128)", |b| b.iter(|| ibkem.setup2()));
}

pub fn bench_ibkem2_extract(c: &mut Criterion) {
    let m_len = 128;
    let l = 2 * m_len + 1;
    let lambda = 128;
    let k = 2;
    let ibkem = IBKEM::new_ibkem2(k, l, 0, lambda);
    let (_, sk) = ibkem.setup2();
    let (_, identity) = generate_email_and_hash_identity(m_len);

    c.bench_function("ibkem2_extract (128)", |b| {
        b.iter(|| ibkem.extract(bb(&sk), bb(&identity)))
    });
}

pub fn bench_ibkem2_encrypt(c: &mut Criterion) {
    let m_len = 128;
    let l = 2 * m_len + 1;
    let lambda = 128;
    let k = 2;
    let ibkem = IBKEM::new_ibkem2(k, l, 0, lambda);
    let (pk, _) = ibkem.setup2();
    let (_, identity) = generate_email_and_hash_identity(m_len);

    c.bench_function("ibkem2_decrypt (128)", |b| {
        b.iter(|| ibkem.encrypt2(bb(&pk), bb(&identity)))
    });
}

pub fn bench_ibkem2_decrypt(c: &mut Criterion) {
    let m_len = 128;
    let l = 2 * m_len + 1;
    let ibkem = IBKEM::new(2, l, 0);
    let (pk, sk) = ibkem.setup2();
    let (_, identity) = generate_email_and_hash_identity(m_len);
    let usk = ibkem.extract(&sk, &identity);
    let (ct, _) = ibkem.encrypt2(&pk, &identity);

    c.bench_function("ibkem2_decrypt (128)", |b| {
        b.iter(|| ibkem.decrypt2(bb(&pk), bb(&usk), bb(&identity), bb(&ct)))
    });
}

criterion_group!(
    benches,
    bench_ibkem2_new,
    bench_ibkem2_setup,
    bench_ibkem2_extract,
    bench_ibkem2_encrypt,
    bench_ibkem2_decrypt
);
criterion_main!(benches);

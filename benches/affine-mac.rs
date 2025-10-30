use criterion::{Criterion, criterion_group, criterion_main};

use std::hint::black_box as bb;

use ibe_schemes::*;

pub fn bench_affine_mac_new(c: &mut Criterion) {
    let m_len = 128;
    let l = 2 * m_len + 1;

    c.bench_function("affine_mac_new (128)", |b| {
        b.iter(|| AffineMAC::new(bb(2), bb(l), bb(0)))
    });
}

pub fn bench_affine_mac_gen(c: &mut Criterion) {
    let m_len = 128;
    let l = 2 * m_len + 1;
    let mac = AffineMAC::new(2, l, 0);

    c.bench_function("affine_mac_gen (128)", |b| b.iter(|| mac.gen_mac()));
}

pub fn bench_affine_mac_tag(c: &mut Criterion) {
    let m_len = 128;
    let l = 2 * m_len + 1;
    let mac = AffineMAC::new(2, l, 0);
    let sk = mac.gen_mac();
    let message = generate_random_message_128();

    c.bench_function("affine_mac_tag (128)", |b| {
        b.iter(|| mac.tag(bb(&sk), bb(&message)))
    });
}

pub fn bench_affine_mac_verify(c: &mut Criterion) {
    let m_len = 128;
    let l = 2 * m_len + 1;
    let mac = AffineMAC::new(2, l, 0);
    let sk = mac.gen_mac();
    let message = generate_random_message_128();
    let tag = mac.tag(&sk, &message);

    c.bench_function("affine_mac_gen (128)", |b| {
        b.iter(|| mac.verify(bb(&sk), bb(&message), bb(&tag)))
    });
}

criterion_group!(
    benches,
    bench_affine_mac_new,
    bench_affine_mac_gen,
    bench_affine_mac_tag,
    bench_affine_mac_verify
);
criterion_main!(benches);

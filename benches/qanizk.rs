use criterion::{Criterion, criterion_group, criterion_main};

use std::hint::black_box as bb;

use ark_bls12_381::G1Projective as G1;
use ibe_schemes::*;

pub fn bench_qanizk_new(c: &mut Criterion) {
    let k = 2;
    let lambda = 128;

    c.bench_function("qanizk_new (128)", |b| {
        b.iter(|| QANIZK::new(bb(k), bb(lambda)))
    });
}

pub fn bench_qanizk_gen_crs(c: &mut Criterion) {
    let k = 2;
    let lambda = 128;
    let qanizk = QANIZK::new(k, lambda);
    let m_matrix = random_matrix(3 * k, k);
    let m_g1_matrix: Matrix<G1> = matrix_lift_g1(&m_matrix);

    c.bench_function("qanizk_gen_crs (128)", |b| {
        b.iter(|| qanizk.gen_crs(bb(&m_g1_matrix)))
    });
}

pub fn bench_qanizk_prove(c: &mut Criterion) {
    let k = 2;
    let lambda = 128;
    let qanizk = QANIZK::new(k, lambda);
    let m_matrix = random_matrix(3 * k, k);
    let m_g1_matrix: Matrix<G1> = matrix_lift_g1(&m_matrix);
    let (crs, _) = qanizk.gen_crs(&m_g1_matrix);

    let tag = generate_random_message_128();
    let r = random_vector(k);
    let c0_field = matrix_vector_mul(&m_matrix, &r);
    let c0_g1: Vec<G1> = vector_lift_g1(&c0_field);

    c.bench_function("qanizk_prove (128)", |b| {
        b.iter(|| qanizk.prove(bb(&crs), bb(&tag), bb(&c0_g1), bb(&r)))
    });
}

pub fn bench_qanizk_verify(c: &mut Criterion) {
    let k = 2;
    let lambda = 128;
    let qanizk = QANIZK::new(k, lambda);
    let m_matrix = random_matrix(3 * k, k);
    let m_g1_matrix: Matrix<G1> = matrix_lift_g1(&m_matrix);
    let (crs, _) = qanizk.gen_crs(&m_g1_matrix);

    let tag = generate_random_message_128();
    let r = random_vector(k);
    let c0_field = matrix_vector_mul(&m_matrix, &r);
    let c0_g1: Vec<G1> = vector_lift_g1(&c0_field);
    let pi = qanizk.prove(&crs, &tag, &c0_g1, &r);

    c.bench_function("qanizk_verify (128)", |b| {
        b.iter(|| qanizk.verify(bb(&crs), bb(&tag), bb(&c0_g1), bb(&pi)))
    });
}

criterion_group!(
    benches,
    bench_qanizk_new,
    bench_qanizk_gen_crs,
    bench_qanizk_prove,
    bench_qanizk_verify
);
criterion_main!(benches);

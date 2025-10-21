use criterion::{Criterion, criterion_group, criterion_main};

use std::hint::black_box as bb;

use ark_bls12_381::{G1Projective, G2Projective};
use ibe_schemes::*;

pub fn bench_bls12_381(c: &mut Criterion) {
    c.bench_function("bls12_381", |b| b.iter(|| GroupCtx::bls12_381()));
}

pub fn bench_scalar_mul_p1(c: &mut Criterion) {
    let group = GroupCtx::bls12_381();
    let scalar = <()>::random_field_element();

    c.bench_function("scalar_mul_p1", |b| {
        b.iter(|| group.scalar_mul_p1(bb(scalar)))
    });
}

pub fn bench_scalar_mul_p2(c: &mut Criterion) {
    let group = GroupCtx::bls12_381();
    let scalar = <()>::random_field_element();

    c.bench_function("scalar_mul_p2", |b| {
        b.iter(|| group.scalar_mul_p2(bb(scalar)))
    });
}

pub fn bench_scalar_expo_gt(c: &mut Criterion) {
    let group = GroupCtx::bls12_381();
    let scalar = <()>::random_field_element();

    c.bench_function("scalar_expo_gt", |b| {
        b.iter(|| group.scalar_expo_gt(bb(scalar)))
    });
}

pub fn bench_pairing(c: &mut Criterion) {
    let group = GroupCtx::bls12_381();
    let a = <()>::random_field_element();
    let b = <()>::random_field_element();
    let g1 = group.scalar_mul_p1(a);
    let g2 = group.scalar_mul_p2(b);

    c.bench_function("pairing", |b| b.iter(|| group.pairing(bb(&g1), bb(&g2))));
}

pub fn bench_multi_pairing(c: &mut Criterion) {
    let group = GroupCtx::bls12_381();

    let length = 5;
    let mut pairs = Vec::new();
    for _ in 0..length {
        let a = <()>::random_field_element();
        let b = <()>::random_field_element();
        let g1 = group.scalar_mul_p1(a);
        let g2 = group.scalar_mul_p2(b);

        pairs.push((g1, g2));
    }

    c.bench_function("multi_pairing (5)", |b| {
        b.iter(|| group.multi_pairing(bb(&pairs)))
    });
}

pub fn bench_random_field_element(c: &mut Criterion) {
    c.bench_function("random_field_element", |b| {
        b.iter(|| <()>::random_field_element())
    });
}

pub fn bench_random_vector(c: &mut Criterion) {
    let length = 100;

    c.bench_function("random_vector (100)", |b| {
        b.iter(|| <()>::random_vector(bb(length)))
    });
}

pub fn bench_random_matrix(c: &mut Criterion) {
    let size = 50;

    c.bench_function("random_matrix (50)", |b| {
        b.iter(|| <()>::random_matrix(bb(size), bb(size)))
    });
}

pub fn bench_vector_add(c: &mut Criterion) {
    let size = 50;
    let v = <()>::random_vector(size);
    let w = <()>::random_vector(size);

    c.bench_function("vector_add (50)", |b| {
        b.iter(|| <()>::vector_add(bb(&v), bb(&w)))
    });
}

pub fn bench_vector_scalar_mul(c: &mut Criterion) {
    let size = 50;
    let scalar = <()>::random_field_element();
    let v = <()>::random_vector(size);

    c.bench_function("vector_scalar_mul (50)", |b| {
        b.iter(|| <()>::scalar_vector_mul(bb(scalar), bb(&v)))
    });
}

pub fn bench_vector_concat(c: &mut Criterion) {
    let size = 100;
    let v = <()>::random_vector(size);
    let w = <()>::random_vector(size);

    c.bench_function("vector_concat (100)", |b| {
        b.iter(|| ().concatenate_vectors(bb(&v), bb(&w)))
    });
}

pub fn bench_matrix_vector_mul(c: &mut Criterion) {
    let size = 50;
    let v = <()>::random_vector(size);
    let m = <()>::random_matrix(size, size);

    c.bench_function("matrix_vector_mul (50)", |b| {
        b.iter(|| <()>::matrix_vector_mul(bb(&m), bb(&v)))
    });
}

pub fn bench_matrix_mul(c: &mut Criterion) {
    let size = 50;
    let m = <()>::random_matrix(size, size);
    let n = <()>::random_matrix(size, size);

    c.bench_function("matrix_mul (50)", |b| {
        b.iter(|| ().matrix_multiply(bb(&m), bb(&n)))
    });
}

pub fn bench_matrix_concat(c: &mut Criterion) {
    let size = 50;
    let m = <()>::random_matrix(size, size);
    let n = <()>::random_matrix(size, size);

    c.bench_function("matrix_concat (50)", |b| {
        b.iter(|| ().concatenate_matrices(bb(&m), bb(&n)))
    });
}

pub fn bench_matrix_transpose(c: &mut Criterion) {
    let size = 50;
    let m = <()>::random_matrix(size, size);

    c.bench_function("matrix_transpose (50)", |b| {
        b.iter(|| ().transpose_matrix(bb(&m)))
    });
}

pub fn bench_group_matrix_vector_mul_msm(c: &mut Criterion) {
    let size = 20;
    let group = GroupCtx::bls12_381();
    let m: Vec<Vec<G1Projective>> = (0..size)
        .map(|_| {
            (0..size)
                .map(|_| group.scalar_mul_p1(<()>::random_field_element()))
                .collect()
        })
        .collect();
    let v = <()>::random_vector(size);

    c.bench_function("group_matrix_vector_mul_msm (20)", |b| {
        b.iter(|| <()>::group_matrix_vector_mul_msm(bb(&m), bb(&v)))
    });
}

pub fn bench_matrix_field_multiply(c: &mut Criterion) {
    let size = 20;
    let group = GroupCtx::bls12_381();
    let m: Vec<Vec<G1Projective>> = (0..size)
        .map(|_| {
            (0..size)
                .map(|_| group.scalar_mul_p1(<()>::random_field_element()))
                .collect()
        })
        .collect();

    let n = <()>::random_matrix(size, size);

    c.bench_function("matrix_field_multiply (20)", |b| {
        b.iter(|| ().g1_matrix_field_multiply(bb(&m), bb(&n)))
    });
}

pub fn bench_g1_matrix_transpose(c: &mut Criterion) {
    let size = 20;
    let group = GroupCtx::bls12_381();
    let m: Vec<Vec<G1Projective>> = (0..size)
        .map(|_| {
            (0..size)
                .map(|_| group.scalar_mul_p1(<()>::random_field_element()))
                .collect()
        })
        .collect();

    c.bench_function("g1_matrix_transpose", |b| {
        b.iter(|| ().transpose_g1_matrix(bb(&m)))
    });
}

pub fn bench_g2_matrix_transpose(c: &mut Criterion) {
    let size = 20;
    let group = GroupCtx::bls12_381();
    let m: Vec<Vec<G2Projective>> = (0..size)
        .map(|_| {
            (0..size)
                .map(|_| group.scalar_mul_p2(<()>::random_field_element()))
                .collect()
        })
        .collect();

    c.bench_function("g2_matrix_transpose", |b| {
        b.iter(|| ().transpose_g2_matrix(bb(&m)))
    });
}

pub fn bench_blake3_hash_to_bits(c: &mut Criterion) {
    let size = 256;
    let input = b"test input data for hashing";

    c.bench_function("blake3_hash_to_bits (256)", |b| {
        b.iter(|| blake3_hash_to_bits(bb(input), bb(size)))
    });
}

pub fn bench_blake3_hash_bytes(c: &mut Criterion) {
    let input = b"test input data for hashing";

    c.bench_function("blake3_hash_bytes", |b| b.iter(|| blake3_hash_bytes(input)));
}

pub fn bench_generate_random_message_128(c: &mut Criterion) {
    c.bench_function("generate_random_message_128", |b| {
        b.iter(|| generate_random_message_128())
    });
}

pub fn bench_generate_random_email(c: &mut Criterion) {
    c.bench_function("generate_random_email", |b| {
        b.iter(|| generate_random_email())
    });
}

pub fn bench_generate_email_and_hash_identity(c: &mut Criterion) {
    let size = 128;

    c.bench_function("generate_email_and_hash_identity (128)", |b| {
        b.iter(|| generate_email_and_hash_identity(size))
    });
}

criterion_group!(
    benches,
    bench_bls12_381,
    bench_scalar_mul_p1,
    bench_scalar_mul_p2,
    bench_scalar_expo_gt,
    bench_pairing,
    bench_multi_pairing,
    bench_random_field_element,
    bench_random_vector,
    bench_random_matrix,
    bench_vector_add,
    bench_vector_scalar_mul,
    bench_vector_concat,
    bench_matrix_vector_mul,
    bench_matrix_mul,
    bench_matrix_concat,
    bench_matrix_transpose,
    bench_group_matrix_vector_mul_msm,
    bench_matrix_field_multiply,
    bench_g1_matrix_transpose,
    bench_g2_matrix_transpose,
    bench_blake3_hash_to_bits,
    bench_blake3_hash_bytes,
    bench_generate_random_message_128,
    bench_generate_random_email,
    bench_generate_email_and_hash_identity
);
criterion_main!(benches);

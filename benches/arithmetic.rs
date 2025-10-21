use ark_bls12_381::{G1Projective, G2Projective};
use ibe_schemes::*;
use std::time::Instant;

fn main() {
    common_runtimes();
}

fn common_runtimes() {
    let start = Instant::now();
    let group = GroupCtx::bls12_381();
    println!("GroupCtx::bls12_381: {:?}", start.elapsed());
    
    let scalar = <()>::random_field_element();
    
    let start = Instant::now();
    let _ = group.scalar_mul_p1(scalar);
    println!("GroupCtx::scalar_mul_p1: {:?}", start.elapsed());
    
    let start = Instant::now();
    let _ = group.scalar_mul_p2(scalar);
    println!("GroupCtx::scalar_mul_p2: {:?}", start.elapsed());
    
    let start = Instant::now();
    let _ = group.scalar_expo_gt(scalar);
    println!("GroupCtx::scalar_expo_gt: {:?}", start.elapsed());
    
    let g1 = group.scalar_mul_p1(scalar);
    let g2 = group.scalar_mul_p2(scalar);
    let start = Instant::now();
    let _ = group.pairing(&g1, &g2);
    println!("GroupCtx::pairing: {:?}", start.elapsed());
    
    let pairs = vec![(g1, g2); 5];
    let start = Instant::now();
    let _ = group.multi_pairing(&pairs);
    println!("GroupCtx::multi_pairing (5 pairs): {:?}\n", start.elapsed());

    let vec_size = 100;
    let matrix_size = 50;
    
    let start = Instant::now();
    let _ = <()>::random_field_element();
    println!("random_field_element: {:?}", start.elapsed());
    
    let start = Instant::now();
    let vec1 = <()>::random_vector(vec_size);
    println!("random_vector (len={}): {:?}", vec_size, start.elapsed());
    
    let start = Instant::now();
    let matrix1 = <()>::random_matrix(matrix_size, matrix_size);
    println!("random_matrix ({}x{}): {:?}", matrix_size, matrix_size, start.elapsed());
    
    let vec2 = <()>::random_vector(vec_size);
    
    let start = Instant::now();
    let _ = <()>::vector_add(&vec1, &vec2);
    println!("vector_add (len={}): {:?}", vec_size, start.elapsed());
    
    let scalar = <()>::random_field_element();
    
    let start = Instant::now();
    let _ = <()>::scalar_vector_mul(scalar, &vec1);
    println!("scalar_vector_mul (len={}): {:?}", vec_size, start.elapsed());
    
    let matrix_for_vec = <()>::random_matrix(vec_size, vec_size);
    let start = Instant::now();
    let _ = <()>::matrix_vector_mul(&matrix_for_vec, &vec1);
    println!("matrix_vector_mul ({}x{}): {:?}", vec_size, vec_size, start.elapsed());
    
    let matrix2 = <()>::random_matrix(matrix_size, matrix_size);
    let start = Instant::now();
    let _ = ().matrix_multiply(&matrix1, &matrix2);
    println!("matrix_multiply ({}x{}): {:?}", matrix_size, matrix_size, start.elapsed());
    
    let start = Instant::now();
    let _ = ().concatenate_matrices(&matrix1, &matrix2);
    println!("concatenate_matrices ({}x{}): {:?}", matrix_size, matrix_size, start.elapsed());
    
    let start = Instant::now();
    let _ = ().concatenate_vectors(&vec1, &vec2);
    println!("concatenate_vectors (len={}): {:?}", vec_size, start.elapsed());
    
    let start = Instant::now();
    let _ = ().transpose_matrix(&matrix1);
    println!("transpose_matrix ({}x{}): {:?}", matrix_size, matrix_size, start.elapsed());
    
    let group = GroupCtx::bls12_381();
    let g1_matrix: Vec<Vec<G1Projective>> = (0..20).map(|_| {
        (0..20).map(|_| group.scalar_mul_p1(<()>::random_field_element())).collect()
    }).collect();

    let g2_matrix: Vec<Vec<G2Projective>> = (0..20).map(|_| {
        (0..20).map(|_| group.scalar_mul_p2(<()>::random_field_element())).collect()
    }).collect();
    let field_vec = <()>::random_vector(20);
    
    let start = Instant::now();
    let _ = <()>::group_matrix_vector_mul_msm(&g1_matrix, &field_vec);
    println!("group_matrix_vector_mul_msm (20x20): {:?}", start.elapsed());
    
    let field_matrix = <()>::random_matrix(20, 20);
    let start = Instant::now();
    let _ = ().g1_matrix_field_multiply(&g1_matrix, &field_matrix);
    println!("g1_matrix_field_multiply (20x20): {:?}", start.elapsed());
    
    let start = Instant::now();
    let _ = ().transpose_g1_matrix(&g1_matrix);
    println!("transpose_g1_matrix (20x20): {:?}", start.elapsed());
    
    let start = Instant::now();
    let _ = ().transpose_g2_matrix(&g2_matrix);
    println!("transpose_g2_matrix (20x20): {:?}", start.elapsed());
    

    let input = b"test input data for hashing";
    let start = Instant::now();
    let _ = blake3_hash_to_bits(input, 256);
    println!("blake3_hash_to_bits (256 bits): {:?}", start.elapsed());
    
    let start = Instant::now();
    let _ = blake3_hash_bytes(input);
    println!("blake3_hash_bytes: {:?}", start.elapsed());
    
    let start = Instant::now();
    let _ = generate_random_message_128();
    println!("generate_random_message_128: {:?}", start.elapsed());
    
    let start = Instant::now();
    let _ = generate_random_email();
    println!("generate_random_email: {:?}", start.elapsed());
    
    let start = Instant::now();
    let _ = generate_email_and_hash_identity(128);
    println!("generate_email_and_hash_identity (128 bits): {:?}\n", start.elapsed());
}

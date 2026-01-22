use ark_bls12_381::G1Projective as G1;
use ibe_schemes::*;
use ark_ec::PrimeGroup;

#[test]
fn qanizk_ok() {
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
    let is_valid = qanizk.verify(&crs, &tag, &c0_g1, &pi);
    assert!(is_valid);
}

#[test]
fn qanizk_fail_wrong_tag() {
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
    
    let wrong_tag = generate_random_message_128();
    let is_valid = qanizk.verify(&crs, &wrong_tag, &c0_g1, &pi);
    assert!(!is_valid, "Verification should fail with wrong tag");
}

#[test]
fn qanizk_fail_wrong_c0() {
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

    let wrong_r = random_vector(k);
    let wrong_c0_field = matrix_vector_mul(&m_matrix, &wrong_r);
    let wrong_c0_g1: Vec<G1> = vector_lift_g1(&wrong_c0_field);
    
    let is_valid = qanizk.verify(&crs, &tag, &wrong_c0_g1, &pi);
    assert!(!is_valid, "Verification should fail with wrong c0");
}

#[test]
fn qanizk_fail_inconsistent_r() {
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
    
    let wrong_r = random_vector(k);
    
    let pi = qanizk.prove(&crs, &tag, &c0_g1, &wrong_r);
    
    let is_valid = qanizk.verify(&crs, &tag, &c0_g1, &pi);
    assert!(!is_valid, "Verification should fail with inconsistent witness");
}

#[test]
fn qanizk_fail_modified_proof() {
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
    
    let mut pi = qanizk.prove(&crs, &tag, &c0_g1, &r);
    
    pi.t1_g1[0] = pi.t1_g1[0] + G1::generator();
    
    let is_valid = qanizk.verify(&crs, &tag, &c0_g1, &pi);
    assert!(!is_valid, "Verification should fail with tampered proof");
}

#[test]
fn qanizk_fail_wrong_crs() {
    let k = 2;
    let lambda = 128;
    let qanizk = QANIZK::new(k, lambda);
    let m_matrix = random_matrix(3 * k, k);
    let m_g1_matrix: Matrix<G1> = matrix_lift_g1(&m_matrix);
    
    let (crs1, _) = qanizk.gen_crs(&m_g1_matrix);
    let (crs2, _) = qanizk.gen_crs(&m_g1_matrix);
    
    let tag = generate_random_message_128();
    let r = random_vector(k);
    let c0_field = matrix_vector_mul(&m_matrix, &r);
    let c0_g1: Vec<G1> = vector_lift_g1(&c0_field);
    
    let pi = qanizk.prove(&crs1, &tag, &c0_g1, &r);
    
    let is_valid = qanizk.verify(&crs2, &tag, &c0_g1, &pi);
    assert!(!is_valid, "Verification should fail with different CRS");
}

use ark_bls12_381::G1Projective as G1;
use ibe_schemes::*;

#[test]
fn qanizk_ok() {
    let k = 2;
    let lambda = 128;
    let qanizk = QANIZK::new(k, lambda);
    let m_matrix = random_matrix(3 * k, k);
    let m_g1_matrix: Matrix<G1> = matrix_lift_g1(&m_matrix, &qanizk.group);

    let (crs, _) = qanizk.gen_crs(&m_g1_matrix);

    let tag = generate_random_message_128();
    let r = random_vector(k);
    let c0_field = matrix_vector_mul(&m_matrix, &r);
    let c0_g1: Vec<G1> = vector_lift_g1(&c0_field, &qanizk.group);

    let pi = qanizk.prove(&crs, &tag, &c0_g1, &r);
    let is_valid = qanizk.verify(&crs, &tag, &c0_g1, &pi);
    assert!(is_valid);
}

#[test]
fn qanizk_fail() {
    // TODO: implement unit test to ensure QANIZK fails when expected
}

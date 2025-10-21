use ark_bls12_381::G1Projective;
use ibe_schemes::*;

#[test]
fn test_qanizk() {
    let k = 2;       
    let lamda = 128;   
    let qanizk = QANIZK::new(k, lamda);
    println!("k={}, lambda={}", k, lamda);
    
    let m_matrix = <()>::random_matrix(3 * k, k);
    println!("matrix M ({}x{})", 3*k, k);
    
    let m_g1_matrix: Vec<Vec<G1Projective>> = m_matrix.iter()
        .map(|row| row.iter()
            .map(|&elem| qanizk.group.scalar_mul_p1(elem))
            .collect())
        .collect();
    
    println!("m_g1_matrix M({}*{})", m_g1_matrix.len(),m_g1_matrix[0].len());
    
    println!("Generating CRS...");
    let (crs, _trapdoor) = qanizk.gen_crs(&m_g1_matrix);
    println!("CRS generation: success");
    
    let tag = generate_random_message_128();
    let r = <()>::random_vector(k);  
    let c0_field = <()>::matrix_vector_mul(&m_matrix, &r); 
    println!("c0_field length: {}", c0_field.len());

    let c0_g1: Vec<G1Projective> = c0_field.iter()
        .map(|&elem| qanizk.group.scalar_mul_p1(elem))
        .collect();
    
    let pie = qanizk.prove(&crs, &tag, &c0_g1, &r);
    println!("Proof generation: success");
    println!("  t1 length: {}", pie.t1_g1.len());
    println!("  u1 length: {}", pie.u1_g1.len());
    
    let is_valid = qanizk.verify(&crs, &tag, &c0_g1, &pie);
    println!("Proof verification: {}", if is_valid { "success" } else { "failed" });
}

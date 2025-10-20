use ark_bls12_381::{G1Projective, G2Projective};
use ibe_schemes::*;
use std::time::Instant;

fn main() {
    println!("Runtime of all common.rs funtions\n");
    common_runtimes();

    println!("\nTesting Affine MAC"); 
    let af_time = Instant::now();
    test_affine_mac();
    let af_duration = af_time.elapsed();
    println!("Affine Mac Runtime: {:.2?}", af_duration);
    
    println!("\n\nTesting IBKEM1");
    let ibkem1_time = Instant::now();
    test_ibkem1();
    let ib1_duration = ibkem1_time.elapsed();
    println!("IBKEM1 Runtime: {:.2?}", ib1_duration);
    
    
    println!("\n\nTesting QANIZK");
    let q_time = Instant::now();
    test_qanizk();
    let q_duration = q_time.elapsed();
    println!("QANIZK Runtime: {:.2?}", q_duration);

    println!("\n\nTesting IBKEM2");
    let ib2_time = Instant::now();
    test_ibkem2();    
    let ib2_duration = ib2_time.elapsed();
    println!("IBKEM2 Runtime: {:.2?}", ib2_duration);

    println!("\n\nTesting IBKEM2 correctness");
    correctness_ibkem2();
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
    println!("matrix_vector_mul ({}x{} * vec): {:?}", vec_size, vec_size, start.elapsed());
    
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

fn test_affine_mac() {
    let m_len = 128;
    let l = 2 * m_len + 1;
    let mac = AffineMAC::new(2, l, 0);     
    
    let sk = mac.gen_mac();

    let message = generate_random_message_128();
    println!("Random Message: {:?}", &message);
    let message = generate_random_message_128();
    println!("Message length: {} bytes = {} bits", message.len(), message.len() * 8);

    let tag = mac.tag(&sk, &message);
    let verified = mac.verify(&sk, &message, &tag);
    
    println!("\nMAC verification: {}", if verified { "Success" } else { "Failed" });
    
    // Test with wrong message
    let wrong_message = generate_random_message_128();
    let wrong_verified = mac.verify(&sk, &wrong_message, &tag);
    println!("Wrong message verification: {}", if !wrong_verified { "Failed" } else { "Success" });
}


fn test_ibkem1() {
    let m_len = 128;
    let l = 2 * m_len + 1;
    let ibkem = IBKEM::new(2, l, 0);
    let (pk, sk) = ibkem.setup();
    println!("\nIBKEM setup: Success");

    let (email, identity) = generate_email_and_hash_identity(128);
    let email_str = String::from_utf8_lossy(&email);    
    println!("  Email: {}", email_str);
    println!("  Identity: {:?}", identity);
    println!("  Identity Length: {} bytes", identity.len());

    let usk1 = ibkem.extract(&sk, &identity);
    let (ct1, k1) = ibkem.encrypt(&pk, &identity);
    let k1_dec = ibkem.decrypt(&usk1, &identity, &ct1);
    println!("IBKEM encryption/decryption: {}", if k1_dec.is_some() { "Success" } else { "Failed" });
    

    if let Some(decrypted_key) = k1_dec {
        if decrypted_key == k1 {
            println!("\nSuccess - Keys match!");
        } else {
            println!("\nFailed - Keys don't match");
        }
    } else {
        println!("\nFailed - Decryption returned");
    }   

    // Test with different identity
    let (email2, identity2) = generate_email_and_hash_identity(128);
    let email_str2 = String::from_utf8_lossy(&email2);    
    println!("   Email2: {}", email_str2);
    println!("   Identity2: {:?}", identity2);
    let usk2 = ibkem.extract(&sk, &identity2);
    let wrong_dec = ibkem.decrypt(&usk2, &identity2, &ct1);
    if let Some(decrypted_key) = wrong_dec {
        if decrypted_key == k1 {
            println!("\nSuccess - Keys match on different identity!");
        } else {
            println!("\nFailed - Wrong identity!");
        }
    } else {
        println!("\nFailed - Decryption returned");
    }   
}

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

fn test_ibkem2() {
    let m_len = 128; 
    let l = 2 * m_len + 1;
    let lambda = 128; 
    let k = 2;
    
    println!("Setting up IBKEM2 with parameters: k={}, l={}, lambda={}", k, l, lambda);
    
    let ibkem2 = IBKEM::new_ibkem2(k, l, 0, lambda); 
    let (pk, sk) = ibkem2.setup2(); 

    println!("IBKEM2 setup: Success");
    println!("Public key has CRS: {}", pk.crs.is_some());

    let (email, identity) = generate_email_and_hash_identity(128);
    let email_str = String::from_utf8_lossy(&email);    
    println!("   Email: {}", email_str);
    println!("   Identity: {:?}", identity);
    
    let usk1 = ibkem2.extract(&sk, &identity);
    
    let (ct, k1) = ibkem2.encrypt2(&pk, &identity);
    println!("IBKEM2 encryption: Success");
    println!("Ciphertext has proof: {}", ct.proof.is_some());
    
    println!("\nDecryption...");
    let k1_dec = ibkem2.decrypt2(&pk, &usk1, &identity, &ct); 

    // Test correctness
    if let Some(decrypted_key) = k1_dec {
        if decrypted_key == k1 {
            println!("Success - Keys match!");
        } else {
            println!("Failed - Keys don't match");
        }
    } else {
        println!("Failed - Decryption returned None");
        return;
    }

    // Testing with wrong identity
    println!("\nTesting with wrong identity...");
    let (email2, identity2) = generate_email_and_hash_identity(128);
    let email_str2 = String::from_utf8_lossy(&email2);    
    println!("   Email2: {}", email_str2);
    println!("   Identity2: {:?}", identity2);

    let usk2 = ibkem2.extract(&sk, &identity2);
    
    let wrong_dec = ibkem2.decrypt2(&pk, &usk2, &identity2, &ct);
    
    if wrong_dec.is_none() {
        println!("Success - Keys don't match!");
    } else {
        println!("Failed - Key match!");
    }
}

fn correctness_ibkem2(){
    for i in 0..3{
        let m_len = 128; 
        let l = 2 * m_len + 1;
        let lambda = 128; 
        let k = 2;
        println!("IBKEM2 Test :{}", i+1);
        let (email, identity) = generate_email_and_hash_identity(128);
        let email_str = String::from_utf8_lossy(&email);    
        println!("   Email: {}", email_str);
        println!("   Identity: {:?}", identity);

        let ts = Instant::now();
        let ibkem2 = IBKEM::new_ibkem2(k, l, 0, lambda); 
        println!("\nSetup...");
        let (pk, sk) = ibkem2.setup2(); 
        println!("Public key has CRS: {}", pk.crs.is_some());
        println!("IBKEM2 setup: Success");

        println!("\nExtract...");
        let usk1 = ibkem2.extract(&sk, &identity);
        println!("IBKEM2 Extract: Success");
        
        println!("\nEncryption...");
        let (ct, k1) = ibkem2.encrypt2(&pk, &identity);
        println!("IBKEM2 encryption: Success");
        
        println!("\nDecryption...");
        let k1_dec = ibkem2.decrypt2(&pk, &usk1, &identity, &ct); 
        assert!(k1_dec.is_some(), "IBKEM2 decryption: Success");

        let tsd = ts.elapsed();
        // Test correctness
        if let Some(decrypted_key) = k1_dec {
            if decrypted_key == k1 {
                println!("Test {}:Success - Keys match!\n", i+1);
                println!("Test {} Runtime: {:.2?}", i+1, tsd);
            } else {
                println!("Test {}:Failed - Keys don't match\n", i+1);
                println!("Test {} Runtime: {:.2?}", i+1, tsd);
            }
        } else {
            println!("Failed - Decryption returned None");
            return;
        }
    }
}

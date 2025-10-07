use ark_bls12_381::G1Projective;
use ibe_schemes::*;

fn main() {
    println!("\nTesting Affine MAC"); 
    test_affine_mac();
    
    println!("\n\nTesting IBKEM1");
    test_ibkem1();
    
    println!("\n\nTesting QANIZK");
    test_qanizk();

    println!("\n\nTesting IBKEM2");
    test_ibkem2();    

    println!("\n\nTesting IBKEM2 correctness");
    correctness_ibkem2();
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
    println!("\n Wrong message verification: {}", if !wrong_verified { "Failed" } else { "Success" });
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

        // Test correctness
        if let Some(decrypted_key) = k1_dec {
            if decrypted_key == k1 {
                println!("Test {}:Success - Keys match!\n", i+1);
            } else {
                println!("Test {}:Failed - Keys don't match\n", i+1);
            }
        } else {
            println!("Failed - Decryption returned None");
            return;
        }
    }
}

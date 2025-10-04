use ark_ec::{PairingEngine, ProjectiveCurve};
use ark_bls12_381::{Bls12_381, Fr, G1Projective, G2Projective};
use ark_ff::{PrimeField, UniformRand, Zero, One, BigInteger256, BigInteger};
use rand::thread_rng;
use ibe_schemes::*;

fn generate_random_message_128() -> Vec<u8> {
    (0..16).map(|_| rand::random::<u8>()).collect()
}

fn main() {
    println!("Testing Affine MAC"); 
    test_affine_mac();
    
    println!("Testing IBKEM1");
    test_ibkem1();

    println!("\nTesting QANIZK");
    test_qanizk();

    println!("Testing IBKEM2");
    test_ibkem2();    

    
}

fn test_affine_mac() {
    let m_len = 128;
    let l = 2 * m_len + 1;
    let mac = AffineMAC::new(2, l, 0);     
    
    let sk = mac.gen_mac();

    let message = generate_random_message_128();
    println!("Random Message: {:?}", &message[0..8]);
    
    let tag = mac.tag(&sk, &message);
    let verified = mac.verify(&sk, &message, &tag);
    
    println!("\nMAC verification: {}", if verified { "Success" } else { "Failed" });
    
    // Test with wrong message
    let wrong_message = generate_random_message_128();
    let wrong_verified = mac.verify(&sk, &wrong_message, &tag);
    println!("\n Wrong message verification: {}", if !wrong_verified { "Success" } else { "Failed" });
}


fn test_ibkem1() {
    let m_len = 128;
    let l = 2 * m_len + 1;
    let ibkem = IBKEM::new(2, l, 0);
    let (pk, sk) = ibkem.setup();
    println!("IBKEM setup: Success");
    let identity = b"test@gmail.com";
    let usk1 = ibkem.extract(&sk, identity);
    let (ct1, k1) = ibkem.encrypt(&pk, identity);
    let k1_dec = ibkem.decrypt(&usk1, identity, &ct1);
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
    let identity2 = b"harshit@gmail.com";
    let usk2 = ibkem.extract(&sk, identity2);
    let wrong_dec = ibkem.decrypt(&usk2, identity2, &ct1);
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

    let identity = b"test@gmail.com";
    
    let usk1 = ibkem2.extract(&sk, identity);
    
    let (ct, k1) = ibkem2.encrypt2(&pk, identity);
    println!("IBKEM2 encryption: Success");
    println!("Ciphertext has proof: {}", ct.proof.is_some());
    
    println!("Decryption...");
    let k1_dec = ibkem2.decrypt2(&pk, &usk1, identity, &ct); 

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
    let identity2 = b"harshit@gmail.com";
    let usk2 = ibkem2.extract(&sk, identity2);
    
    let wrong_dec = ibkem2.decrypt2(&pk, &usk2, identity2, &ct);
    
    if wrong_dec.is_none() {
        println!("Success - Keys don't match!");
    } else {
        println!("Failed - Key match!");
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

// use ark_ec::{PairingEngine, ProjectiveCurve};
// use ark_bls12_381::{Bls12_381, Fr, G1Projective, G2Projective};
// use ark_ff::{PrimeField, UniformRand, Zero, One, BigInteger256, BigInteger};
// use rand::thread_rng;
use ibe_schemes::*;

fn generate_random_message_128() -> Vec<u8> {
    (0..16).map(|_| rand::random::<u8>()).collect()
}

fn main() {
    println!("Testing Affine MAC"); 
    test_affine_mac();
    
    println!("Testing IBKEM");
    test_ibkem();    

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

    // let mac = AffineMAC::new(2, 4);
    // let sk = mac.gen_mac();
    // let message = vec![1u8, 0, 1, 1];
    // let tag = mac.tag(&sk, &message);
    // let verified = mac.verify(&sk, &message, &tag);
    
    // println!("   Affine MAC verification: {}", if verified { "Success" } else { "Failed" });
    
    // // Test with wrong message
    // let wrong_message = vec![0u8, 0, 1, 1];
    // let wrong_verified = mac.verify(&sk, &wrong_message, &tag);
    // println!("   Wrong message verification: {}", if !wrong_verified { "Success" } else { "Failed" });
}


fn test_ibkem() {
    let m_len = 128;
    let l = 2 * m_len + 1;
    let ibkem = IBKEM::new(2, l, 0);
    let (pk, sk) = ibkem.setup();
    println!("IBKEM setup: Success");
    // let idn= &generate_random_message_128();
    // println!("message : {:?}", &idn[0..8]);
    // let identity = idn;
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
    // println!("\nWrong identity rejection: {}", if wrong_dec.is_none() { "Success" } else { "Failed" });

}


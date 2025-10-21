use ibe_schemes::*;

#[test]
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

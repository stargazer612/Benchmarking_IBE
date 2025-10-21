use ibe_schemes::*;
use std::time::Instant;

#[test]
fn test_ibkem2() {
    let m_len = 128;
    let l = 2 * m_len + 1;
    let lambda = 128;
    let k = 2;

    println!(
        "Setting up IBKEM2 with parameters: k={}, l={}, lambda={}",
        k, l, lambda
    );

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

#[test]
fn correctness_ibkem2() {
    for i in 0..3 {
        let m_len = 128;
        let l = 2 * m_len + 1;
        let lambda = 128;
        let k = 2;
        println!("IBKEM2 Test :{}", i + 1);
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
                println!("Test {}:Success - Keys match!\n", i + 1);
                println!("Test {} Runtime: {:.2?}", i + 1, tsd);
            } else {
                println!("Test {}:Failed - Keys don't match\n", i + 1);
                println!("Test {} Runtime: {:.2?}", i + 1, tsd);
            }
        } else {
            println!("Failed - Decryption returned None");
            return;
        }
    }
}

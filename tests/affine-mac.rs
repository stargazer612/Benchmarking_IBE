use ibe_schemes::*;

#[test]
fn test_affine_mac_2() {
    let k = 2usize;
    let m_len = 4usize;
    let l = 2*m_len + 1;
    let l_prime = 0;
    let mac = AffineMAC::new(k, l, l_prime);
    let sk = mac.gen_mac();

    let message = vec![1u8, 0, 1, 1];
    let tag = mac.tag(&sk, &message);
    let check = mac.verify(&sk, &message, &tag);
    assert!(check, "valid tag should verify");

    let new_message = vec![0u8, 0, 1, 1];
    let check2 = mac.verify(&sk, &new_message, &tag);
    assert!(!check2, "tag for different message should not verify");
}

#[test]
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

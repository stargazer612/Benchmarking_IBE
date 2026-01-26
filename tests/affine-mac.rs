use ibe_schemes::{AffineMAC, generate_random_message_128};

#[test]
fn affine_mac_small_ok() {
    let k = 2;
    let m_len = 4;
    let l = 2 * m_len + 1;
    let l_prime = 0;
    let mac = AffineMAC::new(k, l, l_prime);
    let sk = mac.gen_mac();

    let message = vec![1u8, 0, 1, 1];
    let tag = mac.tag(&sk, &message);
    let check = mac.verify(&sk, &message, &tag);
    assert!(check);
}

#[test]
fn affine_mac_small_fail() {
    let k = 2;
    let m_len = 4;
    let l = 2 * m_len + 1;
    let l_prime = 0;
    let mac = AffineMAC::new(k, l, l_prime);
    let sk = mac.gen_mac();

    let message = vec![1u8, 0, 1, 1];
    let tag = mac.tag(&sk, &message);
    let new_message = vec![0u8, 0, 1, 1];
    let check = mac.verify(&sk, &new_message, &tag);
    assert!(!check);
}

#[test]
fn affine_mac_large_ok() {
    let k = 2;
    let l = 128;
    let l_prime = 0;
    let mac = AffineMAC::new(k, l, l_prime);
    let sk = mac.gen_mac();

    let message = generate_random_message_128();
    let tag = mac.tag(&sk, &message);
    let check = mac.verify(&sk, &message, &tag);
    assert!(check);
}

#[test]
fn affine_mac_large_fail() {
    let k = 2;
    let l = 128;
    let l_prime = 0;
    let mac = AffineMAC::new(k, l, l_prime);
    let sk = mac.gen_mac();

    let message = generate_random_message_128();
    let tag = mac.tag(&sk, &message);
    let new_message = generate_random_message_128();
    let check = mac.verify(&sk, &new_message, &tag);
    assert!(!check);
}

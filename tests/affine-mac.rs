use ibe_schemes::{AffineMAC, generate_random_message_128};

#[test]
fn affine_mac_small_ok() {
    let k = 2;
    let msg_len = 8;
    let mac = AffineMAC::new(k, msg_len);
    let sk = mac.gen_mac();

    let message = vec![0b10110011u8];
    let tag = mac.tag(&sk, &message);
    let check = mac.verify(&sk, &message, &tag);
    assert!(check);
}

#[test]
fn affine_mac_small_fail() {
    let k = 2;
    let msg_len = 8;
    let mac = AffineMAC::new(k, msg_len);
    let sk = mac.gen_mac();

    let message = vec![0b11010100u8];
    let tag = mac.tag(&sk, &message);
    let new_message = vec![0b10010001u8];
    let check = mac.verify(&sk, &new_message, &tag);
    assert!(!check);
}

#[test]
fn affine_mac_large_ok() {
    let k = 2;
    let msg_len = 128;
    let mac = AffineMAC::new(k, msg_len);
    let sk = mac.gen_mac();

    let message = generate_random_message_128();
    let tag = mac.tag(&sk, &message);
    let check = mac.verify(&sk, &message, &tag);
    assert!(check);
}

#[test]
fn affine_mac_large_fail() {
    let k = 2;
    let msg_len = 128;
    let mac = AffineMAC::new(k, msg_len);
    let sk = mac.gen_mac();

    let message = generate_random_message_128();
    let tag = mac.tag(&sk, &message);
    let new_message = generate_random_message_128();
    let check = mac.verify(&sk, &new_message, &tag);
    assert!(!check);
}

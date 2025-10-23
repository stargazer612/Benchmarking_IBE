use ibe_schemes::*;

#[test]
fn test_ibkem1_ok() {
    let m_len = 128;
    let l = 2 * m_len + 1;
    let ibkem = IBKEM1::new(2, l, 0);
    let (pk, sk) = ibkem.setup();

    let (_, identity) = generate_email_and_hash_identity(128);

    let usk = ibkem.extract(&sk, &identity);
    let (ct, k) = ibkem.encrypt(&pk, &identity);
    let k_dec = ibkem.decrypt(&usk, &ct);

    assert_eq!(k_dec, k)
}

#[test]
fn test_ibkem1_fail() {
    let m_len = 128;
    let l = 2 * m_len + 1;
    let ibkem = IBKEM1::new(2, l, 0);
    let (pk, sk) = ibkem.setup();

    let (_, identity) = generate_email_and_hash_identity(128);
    let (ct, k) = ibkem.encrypt(&pk, &identity);

    let (_, new_identity) = generate_email_and_hash_identity(128);
    let new_usk = ibkem.extract(&sk, &new_identity);
    let k_dec = ibkem.decrypt(&new_usk, &ct);

    assert_ne!(k_dec, k);
}

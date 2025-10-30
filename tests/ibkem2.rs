use ibe_schemes::*;

#[test]
fn test_ibkem2_ok() {
    let m_len = 128;
    let l = 2 * m_len + 1;
    let lambda = 128;
    let k = 2;

    let ibkem = IBKEM2::new(k, l, 0, lambda);
    let (pk, sk) = ibkem.setup();

    let (_, identity) = generate_email_and_hash_identity(128);

    let usk = ibkem.extract(&sk, &identity);
    let (ct, k) = ibkem.encrypt(&pk, &identity);
    let k_dec = ibkem.decrypt(&pk, &usk, &identity, &ct);

    assert!(k_dec.is_some_and(|k_dec| k_dec == k));
}

#[test]
fn test_ibkem2_fail() {
    let m_len = 128;
    let l = 2 * m_len + 1;
    let lambda = 128;
    let k = 2;

    let ibkem = IBKEM2::new(k, l, 0, lambda);
    let (pk, sk) = ibkem.setup();

    let (_, identity) = generate_email_and_hash_identity(128);
    let (ct, _) = ibkem.encrypt(&pk, &identity);

    let (_, new_identity) = generate_email_and_hash_identity(128);
    let new_usk = ibkem.extract(&sk, &new_identity);
    let k_dec = ibkem.decrypt(&pk, &new_usk, &new_identity, &ct);

    assert!(k_dec.is_none());
}

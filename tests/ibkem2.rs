use ibe_schemes::*;

#[test]
fn test_ibkem2_ok() {
    let m_len = 128;
    let l = 2 * m_len + 1;
    let lambda = 128;
    let k = 2;

    let ibkem2 = IBKEM::new_ibkem2(k, l, 0, lambda);
    let (pk, sk) = ibkem2.setup2();

    let (_, identity) = generate_email_and_hash_identity(128);

    let usk = ibkem2.extract(&sk, &identity);
    let (ct, k) = ibkem2.encrypt2(&pk, &identity);
    let k_dec = ibkem2.decrypt2(&pk, &usk, &identity, &ct);

    assert!(k_dec.is_some_and(|k_dec| k_dec == k));
}

#[test]
fn test_ibkem2_fail() {
    let m_len = 128;
    let l = 2 * m_len + 1;
    let lambda = 128;
    let k = 2;

    let ibkem2 = IBKEM::new_ibkem2(k, l, 0, lambda);
    let (pk, sk) = ibkem2.setup2();

    let (_, identity) = generate_email_and_hash_identity(128);
    let (ct, _) = ibkem2.encrypt2(&pk, &identity);

    let (_, new_identity) = generate_email_and_hash_identity(128);
    let new_usk = ibkem2.extract(&sk, &new_identity);
    let k_dec = ibkem2.decrypt2(&pk, &new_usk, &new_identity, &ct);

    assert!(k_dec.is_none());
}

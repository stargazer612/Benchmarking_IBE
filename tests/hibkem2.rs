use ibe_schemes::*;

#[test]
fn hibkem2_enc_dec_level_1() {
    let k = 2;
    let max_levels = 4;
    let identity_len = 8;
    let hibkem = HIBKEM2::new(k, max_levels, identity_len);
    let (pk, _dk, sk) = hibkem.setup();
    let (_, id) = generate_hierarchical_identity(max_levels, identity_len);

    let id_l1 = id[0..1].to_vec();
    let usk = hibkem.extract(&sk, &id_l1);
    let (k_enc, ct) = hibkem.encrypt(&pk, &id_l1);
    let k_dec = hibkem.decrypt(&usk, &ct);
    assert_eq!(k_enc, k_dec);
}

#[test]
fn hibkem2_enc_dec_level_2() {
    let k = 2;
    let max_levels = 4;
    let identity_len = 8;
    let hibkem = HIBKEM2::new(k, max_levels, identity_len);
    let (pk, _dk, sk) = hibkem.setup();
    let (_, id) = generate_hierarchical_identity(max_levels, identity_len);

    let id_l2 = id[0..2].to_vec();
    let usk = hibkem.extract(&sk, &id_l2);
    let (k_enc, ct) = hibkem.encrypt(&pk, &id_l2);
    let k_dec = hibkem.decrypt(&usk, &ct);
    assert_eq!(k_enc, k_dec);
}

#[test]
fn hibkem2_enc_dec_level_3() {
    let k = 2;
    let max_levels = 4;
    let identity_len = 8;
    let hibkem = HIBKEM2::new(k, max_levels, identity_len);
    let (pk, _dk, sk) = hibkem.setup();
    let (_, id) = generate_hierarchical_identity(max_levels, identity_len);

    let id_l3 = id[0..3].to_vec();
    let usk = hibkem.extract(&sk, &id_l3);
    let (k_enc, ct) = hibkem.encrypt(&pk, &id_l3);
    let k_dec = hibkem.decrypt(&usk, &ct);
    assert_eq!(k_enc, k_dec);
}

#[test]
fn hibkem2_enc_dec_level_4() {
    let k = 2;
    let max_levels = 4;
    let identity_len = 8;
    let hibkem = HIBKEM2::new(k, max_levels, identity_len);
    let (pk, _dk, sk) = hibkem.setup();
    let (_, id) = generate_hierarchical_identity(max_levels, identity_len);

    let id_l = id[0..4].to_vec();
    let usk = hibkem.extract(&sk, &id_l);
    let (k_enc, ct) = hibkem.encrypt(&pk, &id_l);
    let k_dec = hibkem.decrypt(&usk, &ct);
    assert_eq!(k_enc, k_dec);
}

#[test]
fn hibkem2_delegation_l1_to_l2() {
    let k = 2;
    let max_levels = 4;
    let identity_len = 8;
    let hibkem = HIBKEM2::new(k, max_levels, identity_len);
    let (pk, dk, sk) = hibkem.setup();
    let (_, id) = generate_hierarchical_identity(max_levels, identity_len);

    let id_l1 = id[0..1].to_vec();
    let usk1 = hibkem.extract(&sk, &id_l1);
    let usk2 = hibkem.delegate(&dk, &usk1, &id_l1, id[1].clone());

    let id_l2 = id[0..2].to_vec();
    let (k_enc, ct) = hibkem.encrypt(&pk, &id_l2);
    let k_dec = hibkem.decrypt(&usk2, &ct);
    assert_eq!(k_enc, k_dec);
}

#[test]
fn hibkem2_delegation_chained_l1_to_l4() {
    let k = 2;
    let max_levels = 4;
    let identity_len = 8;
    let hibkem = HIBKEM2::new(k, max_levels, identity_len);
    let (pk, dk, sk) = hibkem.setup();
    let (_, id) = generate_hierarchical_identity(max_levels, identity_len);

    let id_l1 = id[0..1].to_vec();
    let usk1 = hibkem.extract(&sk, &id_l1);

    let id_l2 = id[0..2].to_vec();
    let usk2 = hibkem.delegate(&dk, &usk1, &id_l1, id[1].clone());

    let id_l3 = id[0..3].to_vec();
    let usk3 = hibkem.delegate(&dk, &usk2, &id_l2, id[2].clone());

    let usk4 = hibkem.delegate(&dk, &usk3, &id_l3, id[3].clone());

    let id_l4 = id[0..4].to_vec();
    let (k_enc, ct) = hibkem.encrypt(&pk, &id_l4);
    let k_dec = hibkem.decrypt(&usk4, &ct);
    assert_eq!(k_enc, k_dec);
}

#[test]
fn hibkem2_extract_and_delegated_key_both_decrypt() {
    let k = 2;
    let max_levels = 4;
    let identity_len = 8;
    let hibkem = HIBKEM2::new(k, max_levels, identity_len);
    let (pk, dk, sk) = hibkem.setup();
    let (_, id) = generate_hierarchical_identity(max_levels, identity_len);

    let id_l2 = id[0..2].to_vec();

    let usk_direct = hibkem.extract(&sk, &id_l2);

    let id_l1 = id[0..1].to_vec();
    let usk1 = hibkem.extract(&sk, &id_l1);
    let usk_delegated = hibkem.delegate(&dk, &usk1, &id_l1, id[1].clone());

    let (k_enc, ct) = hibkem.encrypt(&pk, &id_l2);
    assert_eq!(k_enc, hibkem.decrypt(&usk_direct, &ct));
    assert_eq!(k_enc, hibkem.decrypt(&usk_delegated, &ct));
}

#[test]
fn hibkem2_wrong_identity_cannot_decrypt() {
    let k = 2;
    let max_levels = 4;
    let identity_len = 8;
    let hibkem = HIBKEM2::new(k, max_levels, identity_len);
    let (pk, _dk, sk) = hibkem.setup();
    let (_, id_a) = generate_hierarchical_identity(max_levels, identity_len);
    let (_, id_b) = generate_hierarchical_identity(max_levels, identity_len);

    let id_l2_a = id_a[0..2].to_vec();
    let usk_a = hibkem.extract(&sk, &id_l2_a);

    let id_wrong = vec![id_a[0].clone(), id_b[1].clone()];
    let (k_enc, ct) = hibkem.encrypt(&pk, &id_wrong);
    let k_dec = hibkem.decrypt(&usk_a, &ct);
    assert_ne!(k_enc, k_dec);
}

#[test]
#[should_panic]
fn hibkem2_parent_cannot_decrypt_child_ciphertext() {
    let k = 2;
    let max_levels = 4;
    let identity_len = 8;

    let hibkem = HIBKEM2::new(k, max_levels, identity_len);
    let (pk, _, sk) = hibkem.setup();

    let (_, id) = generate_hierarchical_identity(max_levels, identity_len);

    let id_l1 = id[0..1].to_vec();
    let id_l2 = id[0..2].to_vec();

    let usk1 = hibkem.extract(&sk, &id_l1);

    let (k_enc, ct) = hibkem.encrypt(&pk, &id_l2);
    let k_dec = hibkem.decrypt(&usk1, &ct);

    assert_ne!(k_enc, k_dec);
}

#[test]
#[should_panic]
fn hibkem2_wrong_depth_decrypt_fail() {
    let k = 2;
    let max_levels = 4;
    let identity_len = 8;

    let hibkem = HIBKEM2::new(k, max_levels, identity_len);
    let (pk, _, sk) = hibkem.setup();

    let (_, id) = generate_hierarchical_identity(max_levels, identity_len);

    let id_l1 = id[0..1].to_vec();
    let id_l2 = id[0..2].to_vec();

    let usk = hibkem.extract(&sk, &id_l1);

    let (k_enc, ct) = hibkem.encrypt(&pk, &id_l2);

    let k_dec = hibkem.decrypt(&usk, &ct);

    assert_ne!(k_enc, k_dec);
}

#[test]
fn hibkem2_encryption_randomness() {
    let k = 2;
    let max_levels = 4;
    let identity_len = 8;

    let hibkem = HIBKEM2::new(k, max_levels, identity_len);
    let (pk, _, _) = hibkem.setup();

    let (_, id) = generate_hierarchical_identity(max_levels, identity_len);

    let id_l = id[0..2].to_vec();

    let (k1, ct1) = hibkem.encrypt(&pk, &id_l);
    let (k2, ct2) = hibkem.encrypt(&pk, &id_l);

    assert_ne!(ct1.c0_g1, ct2.c0_g1);
    assert_ne!(k1, k2);
}

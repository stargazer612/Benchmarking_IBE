use ibe_schemes::*;

#[test]
fn hibkem1_enc_dec_level_1() {
    let k: usize = 2;
    let max_levels: usize = 4;
    let identity_len: usize = 32;
    let hibkem = HIBKEM1::new(k, max_levels, identity_len);
    let (pk, _dk, sk) = hibkem.setup();
    let (_, id) = generate_hierarchical_identity(max_levels, identity_len);
    
    let id_l = id[0..1].to_vec();
    let (usk, _) = hibkem.extract(&sk, &id_l);
    let (k_enc, ct) = hibkem.encrypt(&pk, &id_l);
    let k_dec = hibkem.decrypt(&usk, &ct);
    assert_eq!(k_enc, k_dec);
}

#[test]
fn hibkem1_enc_dec_level_2() {
    let k: usize = 2;
    let max_levels: usize = 4;
    let identity_len: usize = 8;
    let hibkem = HIBKEM1::new(k, max_levels, identity_len);
    let (pk, _dk, sk) = hibkem.setup();
    let (_, id) = generate_hierarchical_identity(max_levels, identity_len);
    
    let id_l = id[0..2].to_vec();
    let (usk, _) = hibkem.extract(&sk, &id_l);
    let (k_enc, ct) = hibkem.encrypt(&pk, &id_l);
    let k_dec = hibkem.decrypt(&usk, &ct);
    assert_eq!(k_enc, k_dec);
}

#[test]
fn hibkem1_enc_dec_level_3() {
    let k: usize = 2;
    let max_levels: usize = 4;
    let identity_len: usize = 8;
    let hibkem = HIBKEM1::new(k, max_levels, identity_len);
    let (pk, _dk, sk) = hibkem.setup();
    let (_, id) = generate_hierarchical_identity(max_levels, identity_len);
    
    let id_l = id[0..3].to_vec();
    let (usk, _) = hibkem.extract(&sk, &id_l);
    let (k_enc, ct) = hibkem.encrypt(&pk, &id_l);
    let k_dec = hibkem.decrypt(&usk, &ct);
    assert_eq!(k_enc, k_dec);
}

#[test]
fn hibkem1_enc_dec_level_4() {
    let k: usize = 2;
    let max_levels: usize = 4;
    let identity_len: usize = 8;
    let hibkem = HIBKEM1::new(k, max_levels, identity_len);
    let (pk, _dk, sk) = hibkem.setup();
    let (_, id) = generate_hierarchical_identity(max_levels, identity_len);
    
    let id_l = id[0..4].to_vec();
    
    let (usk, _) = hibkem.extract(&sk, &id_l);
    let (k_enc, ct) = hibkem.encrypt(&pk, &id_l);
    let k_dec = hibkem.decrypt(&usk, &ct);
    assert_eq!(k_enc, k_dec);
}

#[test]
fn hibkem1_delegation_l1_to_l2() {
    let k: usize = 2;
    let max_levels: usize = 4;
    let identity_len: usize = 8;
    let hibkem = HIBKEM1::new(k, max_levels, identity_len);
    let (pk, dk, sk) = hibkem.setup();
    let (_, id) = generate_hierarchical_identity(max_levels, identity_len);

    let id_l1 = id[0..1].to_vec();
    let (usk1, udk1) = hibkem.extract(&sk, &id_l1);
    let (usk2, _) = hibkem.delegate(&dk, &usk1, &udk1, &id_l1, id[1].clone());

    let id_l2 = id[0..2].to_vec();
    let (k_enc, ct) = hibkem.encrypt(&pk, &id_l2);
    let k_dec = hibkem.decrypt(&usk2, &ct);
    assert_eq!(k_enc, k_dec);
}

#[test]
fn hibkem1_delegation_chained_l1_to_l3() {
    let k: usize = 2;
    let max_levels: usize = 4;
    let identity_len: usize = 8;
    let hibkem = HIBKEM1::new(k, max_levels, identity_len);
    let (pk, dk, sk) = hibkem.setup();
    let (_, id) = generate_hierarchical_identity(max_levels, identity_len);

    let id_l1 = id[0..1].to_vec();
    let (usk1, udk1) = hibkem.extract(&sk, &id_l1);

    let id_l2 = id[0..2].to_vec();
    let (usk2, udk2) = hibkem.delegate(&dk, &usk1, &udk1, &id_l1, id[1].clone());

    let (usk3, _) = hibkem.delegate(&dk, &usk2, &udk2, &id_l2, id[2].clone());

    let id_l3 = id[0..3].to_vec();
    let (k_enc, ct) = hibkem.encrypt(&pk, &id_l3);
    let k_dec = hibkem.decrypt(&usk3, &ct);
    assert_eq!(k_enc, k_dec);
}

#[test]
fn hibkem1_delegation_chained_l1_to_l4() {
    let k: usize = 2;
    let max_levels: usize = 4;
    let identity_len: usize = 8;
    let hibkem = HIBKEM1::new(k, max_levels, identity_len);
    let (pk, dk, sk) = hibkem.setup();
    let (_, id) = generate_hierarchical_identity(max_levels, identity_len);

    let id_l1 = id[0..1].to_vec();
    let (usk1, udk1) = hibkem.extract(&sk, &id_l1);

    let id_l2 = id[0..2].to_vec();
    let (usk2, udk2) = hibkem.delegate(&dk, &usk1, &udk1, &id_l1, id[1].clone());

    let id_l3 = id[0..3].to_vec();
    let (usk3, udk3) = hibkem.delegate(&dk, &usk2, &udk2, &id_l2, id[2].clone());

    let (usk4, _) = hibkem.delegate(&dk, &usk3, &udk3, &id_l3, id[3].clone());

    let id_l4 = id[0..4].to_vec();
    let (k_enc, ct) = hibkem.encrypt(&pk, &id_l4);
    let k_dec = hibkem.decrypt(&usk4, &ct);
    assert_eq!(k_enc, k_dec);
}

#[test]
fn hibkem1_extract_and_delegated_key_both_decrypt() {
    let k: usize = 2;
    let max_levels: usize = 4;
    let identity_len: usize = 8;
    let hibkem = HIBKEM1::new(k, max_levels, identity_len);
    let (pk, dk, sk) = hibkem.setup();
    let (_, id) = generate_hierarchical_identity(max_levels, identity_len);
    
    let id_l2 = id[0..2].to_vec();

    let (usk_direct, _) = hibkem.extract(&sk, &id_l2);

    let id_l1 = id[0..1].to_vec();
    let (usk1, udk1) = hibkem.extract(&sk, &id_l1);
    let (usk_delegated, _) = hibkem.delegate(&dk, &usk1, &udk1, &id_l1, id[1].clone());

    let (k_enc, ct) = hibkem.encrypt(&pk, &id_l2);

    assert_eq!(k_enc, hibkem.decrypt(&usk_direct, &ct));
    assert_eq!(k_enc, hibkem.decrypt(&usk_delegated, &ct));
}

#[test]
fn hibkem1_wrong_identity_cannot_decrypt() {
    let k: usize = 2;
    let max_levels: usize = 4;
    let identity_len: usize = 8;
    let hibkem = HIBKEM1::new(k, max_levels, identity_len);
    let (pk, dk, sk) = hibkem.setup();
    let (_, id_a) = generate_hierarchical_identity(max_levels, identity_len);

    let (_, id_b) = generate_hierarchical_identity(max_levels, identity_len);

    let id_l1 = id_a[0..1].to_vec();
    let (usk1, udk1) = hibkem.extract(&sk, &id_l1);

    let (usk2_a, _) = hibkem.delegate(&dk, &usk1, &udk1, &id_l1, id_a[1].clone());

    let id_wrong = vec![id_a[0].clone(), id_b[1].clone()];
    let (k_enc, ct) = hibkem.encrypt(&pk, &id_wrong);
    let k_dec = hibkem.decrypt(&usk2_a, &ct);

    assert_ne!(k_enc, k_dec, "Security failure: wrong identity decrypted!");
}

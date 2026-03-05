use ibe_schemes::*;

#[test]
fn affine_mac_levels1_single_level_ok() {
    let k = 2;
    let max_levels = 3;
    let identity_len = 8;
    let mac = AffineMacLevels1::new(k, max_levels, identity_len);
    let sk = mac.gen_mac();

    let messages = vec![generate_random_message_bits(identity_len)];
    let tag = mac.tag(&sk, &messages);
    let check = mac.verify(&sk, &messages, &tag);
    assert!(check);
}

#[test]
fn affine_mac_levels1_single_level_fail() {
    let k = 2;
    let max_levels = 3;
    let identity_len = 8;
    let mac = AffineMacLevels1::new(k, max_levels, identity_len);
    let sk = mac.gen_mac();

    let messages = vec![generate_random_message_bits(identity_len)];
    let tag = mac.tag(&sk, &messages);

    let wrong_messages = vec![generate_random_message_bits(identity_len)];
    let check = mac.verify(&sk, &wrong_messages, &tag);
    assert!(!check);
}

#[test]
fn affine_mac_levels1_two_levels_ok() {
    let k = 2;
    let max_levels = 3;
    let identity_len = 8;
    let mac = AffineMacLevels1::new(k, max_levels, identity_len);
    let sk = mac.gen_mac();

    let messages = vec![generate_random_message_bits(identity_len), generate_random_message_bits(identity_len)];
    let tag = mac.tag(&sk, &messages);
    let check = mac.verify(&sk, &messages, &tag);
    assert!(check);
}

#[test]
fn affine_mac_levels1_two_levels_fail() {
    let k = 2;
    let max_levels = 3;
    let identity_len = 8;
    let mac = AffineMacLevels1::new(k, max_levels, identity_len);
    let sk = mac.gen_mac();

    let messages = vec![generate_random_message_bits(identity_len), generate_random_message_bits(identity_len)];
    let tag = mac.tag(&sk, &messages);

    let wrong_messages = vec![generate_random_message_bits(identity_len), generate_random_message_bits(identity_len)];
    let check = mac.verify(&sk, &wrong_messages, &tag);
    assert!(!check);
}

#[test]
fn affine_mac_levels1_three_levels_ok() {
    let k = 2;
    let max_levels = 3;
    let identity_len = 8;
    let mac = AffineMacLevels1::new(k, max_levels, identity_len);
    let sk = mac.gen_mac();

    let messages = vec![
        generate_random_message_bits(identity_len), 
        generate_random_message_bits(identity_len), 
        generate_random_message_bits(identity_len)
    ];
    let tag = mac.tag(&sk, &messages);
    let check = mac.verify(&sk, &messages, &tag);
    assert!(check);
}

#[test]
fn affine_mac_levels1_three_levels_fail() {
    let k = 2;
    let max_levels = 3;
    let identity_len = 8;
    let mac = AffineMacLevels1::new(k, max_levels, identity_len);
    let sk = mac.gen_mac();

    let messages = vec![
        generate_random_message_bits(identity_len), 
        generate_random_message_bits(identity_len), 
        generate_random_message_bits(identity_len)
    ];
    let tag = mac.tag(&sk, &messages);

    let wrong_messages = vec![
        messages[0].clone(), 
        messages[1].clone(), 
        generate_random_message_bits(identity_len)
    ];
    
    let check = mac.verify(&sk, &wrong_messages, &tag);
    assert!(!check);
}

#[test]
fn affine_mac_levels1_hierarchy_mismatch_fail() {
    let k = 2;
    let max_levels = 3;
    let identity_len = 8;
    let mac = AffineMacLevels1::new(k, max_levels, identity_len);
    let sk = mac.gen_mac();

    let messages = vec![generate_random_message_bits(identity_len), generate_random_message_bits(identity_len)];
    let tag = mac.tag(&sk, &messages);

    let wrong_messages = vec![messages[0].clone()];
    let check = mac.verify(&sk, &wrong_messages, &tag);
    assert!(!check);
}

#[test]
fn affine_mac_levels1_longer_identity_ok() {
    let k = 2;
    let max_levels = 2;
    let identity_len = 128;
    let mac = AffineMacLevels1::new(k, max_levels, identity_len);
    let sk = mac.gen_mac();

    let messages = vec![generate_random_message_bits(identity_len)];
    let tag = mac.tag(&sk, &messages);
    let check = mac.verify(&sk, &messages, &tag);
    assert!(check);
}

#[test]
fn affine_mac_levels1_longer_identity_fail() {
    let k = 2;
    let max_levels = 2;
    let identity_len = 128;
    let mac = AffineMacLevels1::new(k, max_levels, identity_len);
    let sk = mac.gen_mac();

    let messages = vec![generate_random_message_bits(identity_len)];
    let tag = mac.tag(&sk, &messages);

    let wrong_messages = vec![generate_random_message_bits(identity_len)];
    let check = mac.verify(&sk, &wrong_messages, &tag);
    assert!(!check);
}

#[test]
fn affine_mac_levels1_prefix_independence_ok() {
    let k = 2;
    let max_levels = 3;
    let identity_len = 8;
    let mac = AffineMacLevels1::new(k, max_levels, identity_len);
    let sk = mac.gen_mac();

    let id1 = generate_random_message_bits(identity_len);
    let id2 = generate_random_message_bits(identity_len);
    let id3 = generate_random_message_bits(identity_len);

    let messages_2 = vec![id1.clone(), id2.clone()];
    let tag_2 = mac.tag(&sk, &messages_2);
    assert!(mac.verify(&sk, &messages_2, &tag_2));

    let messages_3 = vec![id1.clone(), id2.clone(), id3.clone()];
    let tag_3 = mac.tag(&sk, &messages_3);
    assert!(mac.verify(&sk, &messages_3, &tag_3));
}

#[test]
fn affine_mac_levels1_randomness_check() {
    let k = 2;
    let max_levels = 2;
    let identity_len = 8;
    let mac = AffineMacLevels1::new(k, max_levels, identity_len);
    let sk = mac.gen_mac();

    let messages = vec![generate_random_message_bits(identity_len)];
    let tag1 = mac.tag(&sk, &messages);
    let tag2 = mac.tag(&sk, &messages);

    assert!(mac.verify(&sk, &messages, &tag1));
    assert!(mac.verify(&sk, &messages, &tag2));
    assert_ne!(tag1.t_g2[0], tag2.t_g2[0]);
}

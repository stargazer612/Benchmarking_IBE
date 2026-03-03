use ibe_schemes::*;

#[test]
fn affine_mac_levels1_single_level_ok() {
    let k = 2;
    let max_levels = 3;
    let identity_len = 8;
    let mac = AffineMacLevels1::new(k, max_levels, identity_len);
    let sk = mac.gen_mac();

    let messages = vec![vec![0b10101010u8]];
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

    let messages = vec![vec![0b10101010u8]];
    let tag = mac.tag(&sk, &messages);

    let wrong_messages = vec![vec![0b01010101u8]];
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

    let messages = vec![vec![0b11110000u8], vec![0b00001111u8]];
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

    let messages = vec![vec![0b11110000u8], vec![0b00001111u8]];
    let tag = mac.tag(&sk, &messages);

    let wrong_messages = vec![vec![0b11110000u8], vec![0b11110000u8]];
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

    let messages = vec![vec![0xAAu8], vec![0xBBu8], vec![0xCCu8]];
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

    let messages = vec![vec![0xAAu8], vec![0xBBu8], vec![0xCCu8]];
    let tag = mac.tag(&sk, &messages);

    let wrong_messages = vec![vec![0xAAu8], vec![0xBBu8], vec![0xDDu8]];
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

    let messages = vec![vec![0xAAu8], vec![0xBBu8]];
    let tag = mac.tag(&sk, &messages);

    let wrong_messages = vec![vec![0xAAu8]];
    let check = mac.verify(&sk, &wrong_messages, &tag);
    assert!(!check);
}

#[test]
fn affine_mac_levels1_all_zeros_ok() {
    let k = 2;
    let max_levels = 2;
    let identity_len = 8;
    let mac = AffineMacLevels1::new(k, max_levels, identity_len);
    let sk = mac.gen_mac();

    let messages = vec![vec![0x00u8]];
    let tag = mac.tag(&sk, &messages);
    let check = mac.verify(&sk, &messages, &tag);
    assert!(check);
}

#[test]
fn affine_mac_levels1_all_ones_ok() {
    let k = 2;
    let max_levels = 2;
    let identity_len = 8;
    let mac = AffineMacLevels1::new(k, max_levels, identity_len);
    let sk = mac.gen_mac();

    let messages = vec![vec![0xFFu8]];
    let tag = mac.tag(&sk, &messages);
    let check = mac.verify(&sk, &messages, &tag);
    assert!(check);
}

#[test]
fn affine_mac_levels1_longer_identity_ok() {
    let k = 2;
    let max_levels = 2;
    let identity_len = 16;
    let mac = AffineMacLevels1::new(k, max_levels, identity_len);
    let sk = mac.gen_mac();

    let messages = vec![vec![0x12u8, 0x34u8]];
    let tag = mac.tag(&sk, &messages);
    let check = mac.verify(&sk, &messages, &tag);
    assert!(check);
}

#[test]
fn affine_mac_levels1_longer_identity_fail() {
    let k = 2;
    let max_levels = 2;
    let identity_len = 16;
    let mac = AffineMacLevels1::new(k, max_levels, identity_len);
    let sk = mac.gen_mac();

    let messages = vec![vec![0x12u8, 0x34u8]];
    let tag = mac.tag(&sk, &messages);

    let wrong_messages = vec![vec![0x12u8, 0x35u8]];
    let check = mac.verify(&sk, &wrong_messages, &tag);
    assert!(!check);
}

#[test]
fn affine_mac_levels1_different_k_ok() {
    let k = 3;
    let max_levels = 2;
    let identity_len = 8;
    let mac = AffineMacLevels1::new(k, max_levels, identity_len);
    let sk = mac.gen_mac();

    let messages = vec![vec![0x42u8]];
    let tag = mac.tag(&sk, &messages);
    let check = mac.verify(&sk, &messages, &tag);
    assert!(check);
}

#[test]
fn affine_mac_levels1_max_depth_ok() {
    let k = 2;
    let max_levels = 4;
    let identity_len = 8;
    let mac = AffineMacLevels1::new(k, max_levels, identity_len);
    let sk = mac.gen_mac();

    let messages = vec![
        vec![0x11u8],
        vec![0x22u8],
        vec![0x33u8],
        vec![0x44u8],
    ];
    let tag = mac.tag(&sk, &messages);
    let check = mac.verify(&sk, &messages, &tag);
    assert!(check);
}

#[test]
fn affine_mac_levels1_prefix_independence_ok() {
    let k = 2;
    let max_levels = 3;
    let identity_len = 8;
    let mac = AffineMacLevels1::new(k, max_levels, identity_len);
    let sk = mac.gen_mac();

    let messages_2 = vec![vec![0xAAu8], vec![0xBBu8]];
    let tag_2 = mac.tag(&sk, &messages_2);
    let check_2 = mac.verify(&sk, &messages_2, &tag_2);
    assert!(check_2);

    let messages_3 = vec![vec![0xAAu8], vec![0xBBu8], vec![0xCCu8]];
    let tag_3 = mac.tag(&sk, &messages_3);
    let check_3 = mac.verify(&sk, &messages_3, &tag_3);
    assert!(check_3);
}

#[test]
fn affine_mac_levels1_randomness_check() {
    let k = 2;
    let max_levels = 2;
    let identity_len = 8;
    let mac = AffineMacLevels1::new(k, max_levels, identity_len);
    let sk = mac.gen_mac();

    let messages = vec![vec![0x42u8]];
    let tag1 = mac.tag(&sk, &messages);
    let tag2 = mac.tag(&sk, &messages);

    assert!(mac.verify(&sk, &messages, &tag1));
    assert!(mac.verify(&sk, &messages, &tag2));
    assert_ne!(tag1.t_g2[0], tag2.t_g2[0]);
}

#[test]
fn affine_mac_levels1_tag_structure_check() {
    let k = 2;
    let max_levels = 2;
    let identity_len = 8;
    let mac = AffineMacLevels1::new(k, max_levels, identity_len);
    let sk = mac.gen_mac();

    let messages = vec![vec![0x42u8]];
    let tag = mac.tag(&sk, &messages);

    assert_eq!(tag.t_g2.len(), 3 * k, "t should have length 3k");
    assert_eq!(tag.u_g2.len(), k, "u should have length k");
    assert_eq!(tag.t_field.len(), 3 * k, "t_field should have length 3k");
}

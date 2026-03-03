use ibe_schemes::*;

fn main() {
    println!("Hello, IBE benchmarking :)\n");

    // hibkem1_identity_generation_level1();
    // hibkem1_identity_generation_level3();
    hibkem1_identity_full_workflow();
    hibkem1_delegation_workflow();
}


fn bytes_to_hex(block: &[u8]) -> String {
        let mut hex = String::new();
        for &byte in block {
            hex.push_str(&format!("{:02x}", byte));
        }
        hex
    }

fn hibkem1_identity_generation_level1() {
    let bits_per_level = 128;
    let (_emails, identity_levels) = generate_hierarchical_identity(1, bits_per_level);

    println!("=== HIBKEM1 Level 1 Identity ===");
    println!("Emails: {:?}", _emails);
    println!("identity_levels.len(): {}", identity_levels.len());  // 1
    println!("Each block bits: {}", bits_per_level);
    println!("Each block bytes: {}", identity_levels[0].len());  // 16

    let identity_hex = bytes_to_hex(&identity_levels[0]);
    println!("Final identity[0]: {}", identity_hex);
    println!("Ready for Hibkem1::ext(&identity_levels)");
}

fn hibkem1_identity_generation_level3() {
    let bits_per_level = 128;
    let (emails, identity_levels) = generate_hierarchical_identity(3, bits_per_level);

    println!("=== HIBKEM1 Level 3 Hierarchical Identity ===");
    println!("Emails:");
    for (i, email) in emails.iter().enumerate() {
        println!("  Level {}: {}", i + 1, String::from_utf8_lossy(email));
    }
    println!("identity_levels.len(): {}", identity_levels.len());  // 3

    for (level, block) in identity_levels.iter().enumerate() {
        let hex_str = bytes_to_hex(block);
        println!("Level {} block ({} bytes): {}", 
                    level + 1, block.len(), hex_str);
    }
    println!("Final Vec<Vec<u8>> ready for hibkem.ext(&identity_levels)");
}

fn hibkem1_identity_full_workflow() {
    let k = 2;
    let max_levels = 2;
    let bits_per_level = 32;
    println!("new");
    let hibkem = HIBKEM1::new(k, max_levels, bits_per_level);
    println!("setup");
    let (pk, _dk, sk) = hibkem.setup();
    
    println!("email and id's");
    let (emails, identity_levels) = generate_hierarchical_identity(max_levels, bits_per_level);

    println!("=== Full HIBKEM1 Workflow (Level 2) ===");
    println!("Generated emails:");
    for (i, email) in emails.iter().enumerate() {
        println!("  Level {}: {}", i + 1, String::from_utf8_lossy(email));
    }

    println!("identity_levels:");
    for (level, block) in identity_levels.iter().enumerate() {
        println!("  Level {}: {}", level + 1, bytes_to_hex(block));
    }

    let id = identity_levels.clone();
    println!("extract");
    let (usk, _udk) = hibkem.extract(&sk, &id);
    println!("encrypt");
    let (k_enc, ct) = hibkem.encrypt(&pk, &id);
    println!("k_enc : {}", k_enc);
    println!("decrypt");
    let k_dec = hibkem.decrypt(&usk, &ct);
    println!("k_dec : {}", k_dec);
    assert_eq!(k_dec, k_enc);

    println!("Crypto works!");
    println!("Used Vec<Vec<u8>>:");
    for (i, block) in id.iter().enumerate() {
        println!("  Level {}: {}", i + 1, bytes_to_hex(block));
    }
}

fn hibkem1_delegation_workflow() {
    let k = 2;
    let max_levels = 3;
    let bits_per_level = 32;

    println!("=== HIBKEM1 Delegation Workflow ===");

    println!("new");
    let hibkem = HIBKEM1::new(k, max_levels, bits_per_level);

    println!("setup");
    let (pk, dk, sk) = hibkem.setup();

    // Generate identities for all levels
    let (emails, identity_levels) = generate_hierarchical_identity(max_levels, bits_per_level);

    println!("Emails:");
    for (i, email) in emails.iter().enumerate() {
        println!("  Level {}: {}", i + 1, String::from_utf8_lossy(email));
    }

    // Level-1 identity prefix (parent)
    let id_level1 = identity_levels[0..1].to_vec();

    // Extract user secret key and delegation key at level 1
    println!("ext (level 1)");
    let (usk1, udk1) = hibkem.extract(&sk, &id_level1);

    // Delegate from level 1 → level 2 using the delegation key
    let id_next = identity_levels[1].clone(); // level-2 identity component
    println!("del (level 1 → level 2)");
    let (usk2, udk2) = hibkem.delegate(&dk, &usk1, &udk1, &id_level1, id_next);

    // Full level-2 identity (prefix + new component)
    let id_level2 = identity_levels[0..2].to_vec();

    // Encrypt to the level-2 identity
    println!("enc (level 2)");
    let (k_enc, ct) = hibkem.encrypt(&pk, &id_level2);
    println!("k_enc: {}", k_enc);

    // Decrypt with the delegated key
    println!("dec with delegated usk2");
    let k_dec = hibkem.decrypt(&usk2, &ct);
    println!("k_dec: {}", k_dec);

    assert_eq!(k_dec, k_enc, "Delegation: decryption failed!");
    println!("Delegation works! k_enc == k_dec ✓");

    // --- Optional: test a second delegation level 2 → level 3 ---
    let id_next2 = identity_levels[2].clone();
    println!("del (level 2 → level 3)");
    let (usk3, _udk3) = hibkem.delegate(&dk, &usk2, &udk2, &id_level2, id_next2);

    let id_level3 = identity_levels[0..3].to_vec();
    println!("enc (level 3)");
    let (k_enc3, ct3) = hibkem.encrypt(&pk, &id_level3);

    println!("dec with delegated usk3");
    let k_dec3 = hibkem.decrypt(&usk3, &ct3);
    assert_eq!(k_dec3, k_enc3, "Level-3 delegation: decryption failed!");
    println!("Level-3 delegation works! k_enc == k_dec ✓");
}

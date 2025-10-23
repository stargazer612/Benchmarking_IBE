use blake3;
use rand::Rng;

pub fn blake3_hash_to_bits(input: &[u8], num_bits: usize) -> Vec<usize> {
    let hash = blake3::hash(input);
    let hash_bytes = hash.as_bytes();
    let mut bits = Vec::with_capacity(num_bits);

    for i in 0..num_bits {
        let byte_idx = i / 8;
        let bit_idx = i % 8;

        if byte_idx < hash_bytes.len() {
            let bit = (hash_bytes[byte_idx] >> bit_idx) & 1;
            bits.push(bit as usize);
        } else {
            bits.push(0);
        }
    }

    bits
}

pub fn blake3_hash_bytes(input: &[u8]) -> Vec<u8> {
    let hash = blake3::hash(input);
    hash.as_bytes().to_vec()
}

pub fn generate_random_message_128() -> Vec<u8> {
    (0..16).map(|_| rand::random::<u8>()).collect()
}

pub fn generate_random_email() -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let chars = b"abcdefghijklmnopqrstuvwxyz0123456789";

    let name_len = rng.gen_range(6..12);
    let domain_len = rng.gen_range(5..10);

    let name: String = (0..name_len)
        .map(|_| chars[rng.gen_range(0..chars.len())] as char)
        .collect();

    let domain: String = (0..domain_len)
        .map(|_| chars[rng.gen_range(0..chars.len())] as char)
        .collect();

    let tld_chars = b"abcdefghijklmnopqrstuvwxyz";
    let tld_len = rng.gen_range(2..4);
    let tld: String = (0..tld_len)
        .map(|_| tld_chars[rng.gen_range(0..tld_chars.len())] as char)
        .collect();

    let email = format!("{}@{}.{}", name, domain, tld);
    email.into_bytes()
}

pub fn generate_email_and_hash_identity(bits: usize) -> (Vec<u8>, Vec<u8>) {
    let email = generate_random_email();
    let hash_bits = blake3_hash_to_bits(&email, bits);

    let mut identity = Vec::new();
    for chunk in hash_bits.chunks(8) {
        let mut byte = 0u8;
        for (i, &bit) in chunk.iter().enumerate() {
            if bit == 1 {
                byte |= 1 << i;
            }
        }
        identity.push(byte);
    }

    (email, identity)
}

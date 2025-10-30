use bit_vec::BitVec;
use blake3;
use rand::Rng;

pub fn blake3_hash_to_bits(input: &[u8], num_bits: usize) -> BitVec {
    assert!(num_bits <= 256);
    let hash = blake3::hash(input);
    let hash_bytes = hash.as_bytes();
    let mut bits = BitVec::from_bytes(hash_bytes);
    bits.truncate(num_bits);
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
    let identity = hash_bits.to_bytes();
    (email, identity)
}

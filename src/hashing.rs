use ark_bls12_381::g1::Config as G1Config;
use ark_bls12_381::{Fr, G1Affine};
use ark_ec::hashing::HashToCurve;
use ark_ec::hashing::curve_maps::wb::WBMap;
use ark_ec::hashing::map_to_curve_hasher::MapToCurveBasedHasher;
use ark_ec::short_weierstrass::Projective;
use ark_ff::fields::field_hashers::{DefaultFieldHasher, HashToField};

use bit_vec::BitVec;
use rand::Rng;

use crate::blake3::Blake3;

pub fn blake3_hash_to_bits(input: &[u8], num_bits: usize) -> BitVec {
    assert!(num_bits <= 256);
    let hash_bytes = Blake3::default().hash(input);
    let mut bits = BitVec::from_bytes(&hash_bytes);
    bits.truncate(num_bits);
    bits
}

pub fn blake3_hash_bytes(input: &[u8]) -> Vec<u8> {
    Blake3::default().hash(input).to_vec()
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

const IDENT_DOMAIN: &str = "IDENTITY";
const DEFAULT_FIELD_HASHER_SEC_PARAM: usize = 128;

pub fn hash_to_fr(id: &str) -> Fr {
    let domain = IDENT_DOMAIN.as_bytes();
    let hasher = <DefaultFieldHasher<Blake3> as HashToField<Fr>>::new(domain);
    hasher.hash_to_field::<1>(id.as_bytes())[0]
}

pub fn hash_to_g1(id: &str) -> G1Affine {
    let domain = IDENT_DOMAIN.as_bytes();
    let g_mapper = MapToCurveBasedHasher::<
        Projective<G1Config>,
        DefaultFieldHasher<Blake3, DEFAULT_FIELD_HASHER_SEC_PARAM>,
        WBMap<G1Config>,
    >::new(domain)
    .unwrap();
    let mut input = Vec::new();
    input.extend_from_slice(&blake3_hash_bytes(id.as_bytes()));
    g_mapper.hash(input.as_slice()).unwrap()
}

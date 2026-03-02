use ark_bls12_381::Fq12 as Gt;
use ark_ff::UniformRand;

use ibe_schemes::pes::{HIBEScheme, IBEScheme};

use rand::thread_rng;

fn run_ibe_scheme<T: IBEScheme>(
    scheme: T,
    user_identity: &str,
    ct_identity: &str,
) -> (Gt, Option<Gt>) {
    let mut rng = thread_rng();

    let (msk, mpk) = scheme.setup(&mut rng);

    let usk = scheme.keygen(&mut rng, &msk, String::from(user_identity));

    let k = Gt::rand(&mut rng);
    let ct = scheme.encrypt(&mut rng, &k, &mpk, String::from(ct_identity));

    let dec = scheme.decrypt(&usk, &ct);
    return (k, dec);
}

pub fn test_ibe_decrypt_ok<T: IBEScheme>(scheme: T, user_identity: &str, ct_identity: &str) {
    let (k, dec) = run_ibe_scheme(scheme, user_identity, ct_identity);
    assert!(dec.is_some_and(|k_dec| k_dec == k));
}

pub fn test_ibe_decrypt_fail<T: IBEScheme>(scheme: T, user_identity: &str, ct_identity: &str) {
    let (_, dec) = run_ibe_scheme(scheme, user_identity, ct_identity);
    assert!(dec.is_none());
}

fn parse_identity(id: &str) -> Vec<String> {
    id.split(".").map(|s| String::from(s)).collect()
}

fn run_hibe_scheme<T: HIBEScheme>(
    scheme: T,
    user_identity: &str,
    ct_identity: &str,
    identity_extension: Option<&str>,
) -> (Gt, Option<Gt>) {
    let mut rng = thread_rng();

    let (msk, mpk) = scheme.setup(&mut rng);

    let k = Gt::rand(&mut rng);
    let ct_identity = parse_identity(ct_identity);
    let ct = scheme.encrypt(&mut rng, &k, &mpk, ct_identity);

    let user_identity = parse_identity(user_identity);
    let usk = scheme.keygen(&mut rng, &msk, user_identity.clone());
    let usk = match identity_extension {
        None => usk,
        Some(id) => scheme.delegate(&mut rng, &mpk, &usk, String::from(id)),
    };

    let dec = scheme.decrypt(&usk, &ct);
    return (k, dec);
}

pub fn test_hibe_decrypt_ok<T: HIBEScheme>(
    scheme: T,
    user_identity: &str,
    ct_identity: &str,
    identity_extension: Option<&str>,
) {
    let (k, dec) = run_hibe_scheme(scheme, user_identity, ct_identity, identity_extension);
    assert!(dec.is_some_and(|k_dec| k_dec == k));
}

pub fn test_hibe_decrypt_fail<T: HIBEScheme>(
    scheme: T,
    user_identity: &str,
    ct_identity: &str,
    identity_extension: Option<&str>,
) {
    let (_, dec) = run_hibe_scheme(scheme, user_identity, ct_identity, identity_extension);
    assert!(dec.is_none());
}

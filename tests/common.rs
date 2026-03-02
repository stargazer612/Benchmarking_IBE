use ark_bls12_381::Fq12 as Gt;
use ark_ff::UniformRand;

use ibe_schemes::pes::{HIBEScheme, IBEScheme};

use rand::thread_rng;

fn run_ibe_scheme<T: IBEScheme>(
    scheme: T,
    msg_in: Gt,
    user_identity: &str,
    ct_identity: &str,
) -> Option<Gt> {
    let mut rng = thread_rng();

    let (msk, mpk) = scheme.setup(&mut rng);
    let usk = scheme.keygen(&mut rng, &msk, String::from(user_identity));
    let ct = scheme.encrypt(&mut rng, &msg_in, &mpk, String::from(ct_identity));
    let msg_out = scheme.decrypt(&usk, &ct);

    return msg_out;
}

pub fn test_ibe_decrypt_ok<T: IBEScheme>(scheme: T, user_identity: &str, ct_identity: &str) {
    let mut rng = thread_rng();
    let msg_in = Gt::rand(&mut rng);

    let msg_out = run_ibe_scheme(scheme, msg_in, user_identity, ct_identity);
    assert!(msg_out.is_some_and(|msg| msg == msg_in));
}

pub fn test_ibe_decrypt_fail<T: IBEScheme>(scheme: T, user_identity: &str, ct_identity: &str) {
    let mut rng = thread_rng();
    let msg_in = Gt::rand(&mut rng);

    let msg_out = run_ibe_scheme(scheme, msg_in, user_identity, ct_identity);
    assert!(msg_out.is_none());
}

fn parse_identity(id: &str) -> Vec<String> {
    id.split(".").map(|s| String::from(s)).collect()
}

fn run_hibe_scheme<T: HIBEScheme>(
    scheme: T,
    msg_in: Gt,
    user_identity: &str,
    ct_identity: &str,
    identity_extension: Option<&str>,
) -> Option<Gt> {
    let mut rng = thread_rng();

    let ct_identity = parse_identity(ct_identity);
    let user_identity = parse_identity(user_identity);

    let (msk, mpk) = scheme.setup(&mut rng);
    let ct = scheme.encrypt(&mut rng, &msg_in, &mpk, ct_identity);
    let usk = scheme.keygen(&mut rng, &msk, user_identity.clone());
    let usk = match identity_extension {
        None => usk,
        Some(id) => scheme.delegate(&mut rng, &mpk, &usk, String::from(id)),
    };

    let msg_out = scheme.decrypt(&usk, &ct);
    return msg_out;
}

pub fn test_hibe_decrypt_ok<T: HIBEScheme>(
    scheme: T,
    user_identity: &str,
    ct_identity: &str,
    identity_extension: Option<&str>,
) {
    let mut rng = thread_rng();
    let msg_in = Gt::rand(&mut rng);

    let msg_out = run_hibe_scheme(
        scheme,
        msg_in,
        user_identity,
        ct_identity,
        identity_extension,
    );
    assert!(msg_out.is_some_and(|msg| msg == msg_in));
}

pub fn test_hibe_decrypt_fail<T: HIBEScheme>(
    scheme: T,
    user_identity: &str,
    ct_identity: &str,
    identity_extension: Option<&str>,
) {
    let mut rng = thread_rng();
    let msg_in = Gt::rand(&mut rng);

    let msg_out = run_hibe_scheme(
        scheme,
        msg_in,
        user_identity,
        ct_identity,
        identity_extension,
    );
    assert!(msg_out.is_none());
}

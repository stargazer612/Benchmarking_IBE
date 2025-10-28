use ark_bls12_381::Fq12 as Gt;
use ark_ff::UniformRand;

use ibe_schemes::*;

use rand::thread_rng;

#[test]
fn lw_decrypt_ok() {
    let mut rng = thread_rng();

    let lw = LW::new();
    let (msk, mpk) = lw.setup(&mut rng);

    let mut identity = Vec::new();
    identity.push(String::from("A"));
    identity.push(String::from("B"));
    identity.push(String::from("C"));
    identity.push(String::from("D"));

    let k = Gt::rand(&mut rng);
    let usk = lw.keygen(&mut rng, &msk, identity.clone());
    let ct = lw.encrypt(&mut rng, &k, &mpk, identity.clone());
    let dec = lw.decrypt(&usk, &ct);

    assert!(dec.is_some_and(|k_dec| k_dec == k));
}

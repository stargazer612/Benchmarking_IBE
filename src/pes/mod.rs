use ark_bls12_381::Fq12 as Gt;
use rand::Rng;

pub trait IBEScheme {
    type MPK;
    type MSK;
    type USK;
    type CT;

    fn name(&self) -> String;

    fn setup(&self, rng: impl Rng) -> (Self::MSK, Self::MPK);

    fn keygen(&self, rng: impl Rng, msk: &Self::MSK, identity: String) -> Self::USK;

    fn encrypt(&self, rng: impl Rng, msg: &Gt, mpk: &Self::MPK, identity: String) -> Self::CT;

    fn decrypt(&self, usk: &Self::USK, ct: &Self::CT) -> Option<Gt>;
}

pub trait HIBEScheme {
    type MPK;
    type MSK;
    type USK;
    type CT;

    fn setup(&self, rng: impl Rng) -> (Self::MSK, Self::MPK);

    fn keygen(&self, rng: impl Rng, msk: &Self::MSK, identity: Vec<String>) -> Self::USK;

    fn encrypt(&self, rng: impl Rng, msg: &Gt, mpk: &Self::MPK, identity: Vec<String>) -> Self::CT;

    fn decrypt(&self, usk: &Self::USK, ct: &Self::CT) -> Option<Gt>;

    fn delegate(
        &self,
        rng: impl Rng,
        mpk: &Self::MPK,
        usk: &Self::USK,
        identity_extension: String,
    ) -> Self::USK;
}

pub mod bb;
pub mod bf;
pub mod hiberla_dec;
pub mod hiberla_enc;
pub mod lw;

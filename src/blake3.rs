use blake3;

use digest::{FixedOutput, FixedOutputReset, Output, OutputSizeUser, Reset, Update, typenum};

pub struct Blake3(blake3::Hasher);

impl Blake3 {
    pub fn hash(&self, input: &[u8]) -> [u8; 32] {
        blake3::hash(input).as_bytes().clone()
    }
}

impl Default for Blake3 {
    fn default() -> Self {
        Self {
            0: blake3::Hasher::default(),
        }
    }
}

impl Clone for Blake3 {
    fn clone(&self) -> Self {
        Self { 0: self.0.clone() }
    }
}

impl Update for Blake3 {
    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
}

impl FixedOutput for Blake3 {
    fn finalize_into(self, out: &mut Output<Self>) {
        let hash = self.0.finalize().as_bytes().clone();
        for i in 0..32 {
            out[i] = hash[i];
        }
    }
}

impl OutputSizeUser for Blake3 {
    type OutputSize = typenum::U32;
}

impl Reset for Blake3 {
    fn reset(&mut self) {
        self.0.reset();
    }
}

impl FixedOutputReset for Blake3 {
    fn finalize_into_reset(&mut self, out: &mut Output<Self>) {
        self.clone().finalize_into(out);
        self.reset();
    }
}

use bit_vec::BitVec;

pub fn bit_at(i: usize, m: &[u8]) -> usize {
    let msg_bits = BitVec::from_bytes(m);
    if msg_bits[i] { 1 } else { 0 }
}

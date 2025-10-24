use bit_vec::BitVec;

pub fn f_i(i: usize, l: usize, message: &[u8]) -> u8 {
    if i < 2 {
        return 0;
    }

    let bit_index = (i - 2) / 2;
    let bit_value = (i - 2) % 2;

    if bit_index >= l || bit_index >= message.len() * 8 {
        return 0;
    }

    let msg = BitVec::from_bytes(message);
    // Original code accesses bits of each byte from LSB to MSB
    // BitVec access bits of each byte from MSB to LSB
    // This idx maps between both to keep original behavior
    let idx = (bit_index / 8) * 8 + (7 - bit_index % 8);
    let message_bit = msg[idx] as usize;

    if message_bit == bit_value { 1 } else { 0 }
}

pub fn f_prime_i(i: usize) -> u8 {
    if i == 0 { 1 } else { 0 }
}

pub fn f_i(i: usize, l: usize, message: &[u8]) -> u8 {
    match i {
        0 | 1 => 0,
        _ => {
            let bit_index = (i - 2) / 2;
            let bit_value = (i - 2) % 2;

            if bit_index < l && bit_index < message.len() * 8 {
                let byte_index = bit_index / 8;
                let bit_position = bit_index % 8;

                if byte_index < message.len() {
                    let message_bit = ((message[byte_index] >> bit_position) & 1) as usize;

                    if message_bit == bit_value { 1 } else { 0 }
                } else {
                    0
                }
            } else {
                0
            }
        }
    }
}

pub fn f_prime_i(i: usize) -> u8 {
    if i == 0 { 1 } else { 0 }
}

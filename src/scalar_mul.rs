use ark_bls12_381::{Fq12 as Gt, G1Projective as G1, G2Projective as G2};
use ark_ec::AdditiveGroup;
use ark_ff::{BigInt, BigInteger, Field};

pub fn k_ary_g1(x: G1, s: BigInt<4>) -> G1 {
    let bytes = s.to_bytes_be();
    let mut nibbles = Vec::with_capacity(64);
    for b in bytes {
        nibbles.push((b >> 4) & 0xF);
        nibbles.push(b & 0xF);
    }

    // Precompute
    let mut lut = Vec::with_capacity(16);
    lut.push(G1::ZERO);
    lut.push(x);
    for i in 2..16 {
        lut.push(lut[i - 1] + x);
    }

    // Exponentiation
    let mut res: G1 = lut[nibbles[0] as usize];
    for n in nibbles[1..64].iter() {
        res.double_in_place()
            .double_in_place()
            .double_in_place()
            .double_in_place();
        res += lut[*n as usize];
    }
    res
}

pub fn k_ary_g2(x: G2, s: BigInt<4>) -> G2 {
    let bytes = s.to_bytes_be();
    let mut nibbles = Vec::with_capacity(64);
    for b in bytes {
        nibbles.push((b >> 4) & 0xF);
        nibbles.push(b & 0xF);
    }

    // Precompute
    let mut lut = Vec::with_capacity(16);
    lut.push(G2::ZERO);
    lut.push(x);
    for i in 2..16 {
        lut.push(lut[i - 1] + x);
    }

    // Exponentiation
    let mut res: G2 = lut[nibbles[0] as usize];
    for n in nibbles[1..64].iter() {
        res.double_in_place()
            .double_in_place()
            .double_in_place()
            .double_in_place();
        res += lut[*n as usize];
    }
    res
}

pub fn k_ary_gt(x: Gt, s: BigInt<4>) -> Gt {
    let bytes = s.to_bytes_be();
    let mut nibbles = Vec::with_capacity(64);
    for b in bytes {
        nibbles.push((b >> 4) & 0xF);
        nibbles.push(b & 0xF);
    }

    // Precompute
    let mut lut = Vec::with_capacity(16);
    lut.push(Gt::ONE);
    lut.push(x);
    for i in 2..16 {
        lut.push(lut[i - 1] * x);
    }

    // Exponentiation
    let mut res: Gt = lut[nibbles[0] as usize];
    for n in nibbles[1..64].iter() {
        res.square_in_place()
            .square_in_place()
            .square_in_place()
            .square_in_place();
        res *= lut[*n as usize];
    }
    res
}

pub fn naf_g1(x: G1, s: BigInt<4>) -> G1 {
    let w = 2;
    let es = s.find_wnaf(w).unwrap();

    // TODO: can we "reverse" faster?
    let mut res = G1::ZERO;
    for &e in es.iter().rev() {
        res.double_in_place();
        if e == 1 {
            res += x;
        } else if e == -1 {
            res -= x;
        }
    }
    res
}

pub fn naf_g2(x: G2, s: BigInt<4>) -> G2 {
    let w = 2;
    let es = s.find_wnaf(w).unwrap();

    // TODO: can we "reverse" faster?
    let mut res = G2::ZERO;
    for &e in es.iter().rev() {
        res.double_in_place();
        if e == 1 {
            res += x;
        } else if e == -1 {
            res -= x;
        }
    }
    res
}

// TODO: this does not make sense for Gt, only for G1 and G2 as division is too expensive
pub fn naf_gt(x: Gt, s: BigInt<4>) -> Gt {
    let w = 2;
    let es = s.find_wnaf(w).unwrap();
    let x_inv = x.inverse().unwrap();

    // TODO: can we "reverse" faster?
    let mut res = Gt::ONE;
    for &e in es.iter().rev() {
        res.square_in_place();
        if e == 1 {
            res *= x;
        } else if e == -1 {
            res *= x_inv;
        }
    }
    res
}

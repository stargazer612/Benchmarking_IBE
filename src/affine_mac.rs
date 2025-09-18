use crate::common::*;
use ark_bls12_381::G2Projective;
use ark_ff::{Zero, One, PrimeField};
use ark_ec::ProjectiveCurve; 

pub struct SecretKey {
    pub b: Matrix,
    pub x_matrices: Vec<Matrix>,
    pub x_prime: Vec<Vector>,
}

pub struct Tag {
    pub t_g2: Vec<G2Projective>,
    pub u_g2: Vec<G2Projective>,
    pub t_field: Vector,
}

pub struct AffineMAC {
    pub k: usize,
    pub l: usize,
    pub l_prime: usize,
    pub group: GroupCtx,
}

impl AffineMAC {
    pub fn new(k: usize, l: usize, l_prime: usize) -> Self {
        Self {
            k, l, l_prime,
            group: GroupCtx::bls12_381(),
        }
    }

    pub fn gen_mac(&self) -> SecretKey {
        let b = <()>::random_matrix(self.k, self.k);
        // let ell = 2 * self.l + 1;
        let mut x_matrices = Vec::with_capacity(self.l + 1);
        println!("l = {}", self.l);
        for _ in 0..=self.l {
            x_matrices.push(<()>::random_matrix(2 * self.k, self.k));
        }
        println!("x matrices length = {}", x_matrices.len());
        //l_prime = 0
        println!("l' = {}",self.l_prime);
        let mut x_prime = Vec::with_capacity(self.l_prime + 1);
        for _ in 0..=self.l_prime {
            x_prime.push(<()>::random_vector(2 * self.k));
        }
        // let x_prime = <()>::random_vector(2 * self.k);
        SecretKey { b, x_matrices, x_prime }
    }

    pub fn f_i(&self, i: usize, message: &[u8]) -> FieldElement {
        match i {
            0 | 1 => FieldElement::zero(),
            _ => {
                let bit_index = (i - 2) / 2;           
                let bit_value = (i - 2) % 2;           
                
                if bit_index < self.l && bit_index < message.len() * 8 {
                    let byte_index = bit_index / 8;     
                    let bit_position = bit_index % 8;   
                    
                    if byte_index < message.len() {
                        let message_bit = ((message[byte_index] >> bit_position) & 1) as usize;
                        
                        if message_bit == bit_value {
                            FieldElement::one()
                        } else {
                            FieldElement::zero()
                        }
                    } else {
                        FieldElement::zero()
                    }
                } else {
                    FieldElement::zero()
                }
            }
        }   
    }

    pub fn f_prime_i(&self, i: usize, _message: &[u8]) -> FieldElement {
        if i == 0 { FieldElement::one() } else { FieldElement::zero() }
    }

    pub fn tag(&self, sk: &SecretKey, message: &[u8]) -> Tag {
        let s = <()>::random_vector(self.k);
        let t_field = <()>::matrix_vector_mul(&sk.b, &s);
        // let ell = 2 * self.l + 1;
        let mut u_field: Vector = vec![FieldElement::zero(); 2 * self.k];

        // print!("\nf_i = ");
        for i in 0..=self.l {
            let fi = self.f_i(i, message);
            if !fi.is_zero() {
                // print!("{} ", i);
                let xi_t = <()>::matrix_vector_mul(&sk.x_matrices[i], &t_field);
                let scaled = <()>::scalar_vector_mul(fi, &xi_t);
                u_field = <()>::vector_add(&u_field, &scaled);
            }
        }

        let f0 = self.f_prime_i(0, message);
        // print!("\nf_i' = ");
        for i in 0..=self.l_prime {
            let fi_prime = self.f_prime_i(i, message);
            if !fi_prime.is_zero() {
                // print!("{} ", i);
                let scaled_xprime = <()>::scalar_vector_mul(f0, &sk.x_prime[i]);
                u_field = <()>::vector_add(&u_field, &scaled_xprime);
            }
        }
        // let scaled_xprime = <()>::scalar_vector_mul(f0, &sk.x_prime);
        // u_field = <()>::vector_add(&u_field, &scaled_xprime);

        let t_g2: Vec<G2Projective> = t_field.clone().into_iter()
            .map(|c| self.group.scalar_mul_p2(c))
            .collect();
        let u_g2: Vec<G2Projective> = u_field.into_iter()
            .map(|c| self.group.scalar_mul_p2(c))
            .collect();

        Tag { t_g2, u_g2, t_field }
    }

    pub fn verify(&self, sk: &SecretKey, message: &[u8], tag: &Tag) -> bool {
        let mut expected: Vec<G2Projective> = vec![G2Projective::zero(); 2 * self.k];
        // let ell = 2 * self.l + 1;

        // print!("\nf_i = ");
        for i in 0..=self.l {
            let fi = self.f_i(i, message);
            if !fi.is_zero() {
                // print!("{} ", i);
                let xi = &sk.x_matrices[i];
                for r in 0..(2 * self.k) {
                    let mut accum = G2Projective::zero();
                    for j in 0..self.k {
                        let scalar = xi[r][j] * fi;
                        if !scalar.is_zero() {
                            accum += tag.t_g2[j].mul(scalar.into_repr());
                        }
                    }
                    expected[r] += accum;
                }
            }
        }

        for i in 0..=self.l_prime {
            let fi_prime = self.f_prime_i(i, message);
            if !fi_prime.is_zero() {
                let row_vec = &sk.x_prime[i]; // length 2k
                if row_vec.len() != 2 * self.k {
                    return false;
                }
                for r in 0..(2 * self.k) {
                    let coeff = fi_prime * row_vec[r];
                    if !coeff.is_zero() {
                        expected[r] += self.group.scalar_mul_p2(coeff);
                    }
                }
            }
        }

        // for r in 0..(2 * self.k) {
        //     expected[r] += self.group.scalar_mul_p2(sk.x_prime[r]);
        // }

        if expected.len() != tag.u_g2.len() { 
            return false; 
        }

        for (e, u) in expected.iter().zip(tag.u_g2.iter()) {
            if e != u {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_affine_mac() {
        let k = 2usize;
        let m_len = 4usize;
        let l = 2*m_len + 1;
        let l_prime = 0;
        let mac = AffineMAC::new(k, l, l_prime);
        let sk = mac.gen_mac();

        let message = vec![1u8, 0, 1, 1];
        let tag = mac.tag(&sk, &message);
        let check = mac.verify(&sk, &message, &tag);
        assert!(check, "valid tag should verify");

        let new_message = vec![0u8, 0, 1, 1];
        let check2 = mac.verify(&sk, &new_message, &tag);
        assert!(!check2, "tag for different message should not verify");
    }
}

    
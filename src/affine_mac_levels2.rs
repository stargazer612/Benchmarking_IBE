use crate::bit_utils::bit_at;
use crate::field_utils::*;
use crate::types::*;
use ark_bls12_381::G2Projective as G2;

pub struct AffineMacLevels2SecretKey {
    pub b: Matrix<FieldElement>,
    pub x_matrices: Vec<Vec<Vec<Matrix<FieldElement>>>>,
    pub x_prime: Vector,
}

pub struct AffineMacLevels2Tag {
    pub t_g2: Vec<Vec<G2>>,
    pub u_g2: Vec<G2>,
    pub t_fields: Vec<Vector>,
}

pub struct AffineMacLevels2 {
    pub k: usize,
    pub max_levels: usize,
    pub identity_len: usize,
}

impl AffineMacLevels2 {
    pub fn new(k: usize, max_levels: usize, identity_len: usize) -> Self {
        assert!(k > 0, "k must be positive");
        assert!(max_levels > 0, "max_levels must be positive");
        assert!(
            identity_len > 0 && identity_len % 8 == 0,
            "identity_len must be positive and divisible by 8"
        );
        Self {
            k,
            max_levels,
            identity_len,
        }
    }

    pub fn gen_mac(&self) -> AffineMacLevels2SecretKey {
        let b = random_matrix(3 * self.k, self.k);
        let mut x_matrices = Vec::with_capacity(self.max_levels);
        for i in 1..=self.max_levels {
            let num_j = i * self.identity_len;
            let mut i_matrices = Vec::with_capacity(num_j);
            for _j in 0..num_j {
                let mut b_matrices = Vec::with_capacity(2);
                for _b in 0..2 {
                    let x_matrix = random_matrix(self.k, 3 * self.k);
                    b_matrices.push(x_matrix);
                }

                i_matrices.push(b_matrices);
            }

            x_matrices.push(i_matrices);
        }

        let x_prime = random_vector(self.k);

        AffineMacLevels2SecretKey {
            b,
            x_matrices,
            x_prime,
        }
    }

    pub fn tag(&self, sk_mac: &AffineMacLevels2SecretKey, m: &[Vec<u8>]) -> AffineMacLevels2Tag {
        let p = m.len();
        assert!(p > 0 && p <= self.max_levels, "Invalid depth p");

        let mut t_fields: Vec<Vector> = Vec::with_capacity(p);
        let mut t_g2: Vec<Vec<G2>> = Vec::with_capacity(p);
        for _i in 0..p {
            let s_i = random_vector(self.k);
            let t_i = matrix_vector_mul(&sk_mac.b, &s_i);
            t_g2.push(vector_lift_g2(&t_i));
            t_fields.push(t_i);
        }

        let mut u = sk_mac.x_prime.clone();

        for i in 1..=p {
            for j in 1..=(i * self.identity_len) {
                let msg_idx = (j - 1) / self.identity_len;
                let bit_in_msg = (j - 1) % self.identity_len;
                let b = bit_at(bit_in_msg, &m[msg_idx]);

                let x_i_j_b = &sk_mac.x_matrices[i - 1][j - 1][b];

                let x_t = matrix_vector_mul(x_i_j_b, &t_fields[i-1]);

                u = vector_add(&u, &x_t);
            }
        }

        let u_g2 = vector_lift_g2(&u);

        AffineMacLevels2Tag {
            t_g2,
            u_g2,
            t_fields,
        }
    }

    pub fn verify(
        &self,
        sk_mac: &AffineMacLevels2SecretKey,
        m: &[Vec<u8>],
        tag: &AffineMacLevels2Tag,
    ) -> bool {
        let p = m.len();

        if p == 0 || p > self.max_levels {
            return false;
        }

        if tag.t_g2.len() != p {
            return false;
        }
        for t_i in tag.t_g2.iter() {
            if t_i.len() != 3 * self.k {
                return false;
            }
        }

        if tag.u_g2.len() != self.k {
            return false;
        }

        let mut u_expected = sk_mac.x_prime.clone();

        for i in 1..=p {
            for j in 1..=(i * self.identity_len) {
                let msg_idx = (j - 1) / self.identity_len;
                let bit_in_msg = (j - 1) % self.identity_len;
                let b = bit_at(bit_in_msg, &m[msg_idx]);

                let x_i_j_b = &sk_mac.x_matrices[i - 1][j - 1][b];
                let x_t = matrix_vector_mul(x_i_j_b, &tag.t_fields[i-1]);
                u_expected = vector_add(&u_expected, &x_t);
            }
        }

        let u_expected_g2 = vector_lift_g2(&u_expected);

        u_expected_g2
            .iter()
            .zip(tag.u_g2.iter())
            .all(|(e, u)| e == u)
    }
}

use crate::common::*;
use ark_bls12_381::{G1Projective, G2Projective};
use ark_ff::{Field, PrimeField, Zero, One, BigInteger};
use ark_ec::ProjectiveCurve;
use blake3;

pub struct CRS {
    pub a_g2: Vec<Vec<G2Projective>>,
    pub ka_g2: Vec<Vec<G2Projective>>,
    pub b_g1: Vec<Vec<G1Projective>>,
    pub mk_g1: Vec<Vec<G1Projective>>,
    pub kjb_a_g2: Vec<Vec<Vec<Vec<G2Projective>>>>,
    pub b_kjb_g1: Vec<Vec<Vec<Vec<G1Projective>>>>,
}

pub struct Trapdoor {
    pub k_matrix: Matrix,
}

pub struct QANIZKProof {
    pub t1_g1: Vec<G1Projective>,
    pub u1_g1: Vec<G1Projective>,
}

pub struct QANIZK {
    pub k: usize,
    pub lamda: usize,
    pub group: GroupCtx,
}

impl QANIZK {
    pub fn new(k: usize, lamda: usize) -> Self {
        Self {
            k,
            lamda,
            group: GroupCtx::bls12_381(),
        }
    }
    
    pub fn gen_crs(&self, m1_matrix: &Vec<Vec<G1Projective>>) -> (CRS, Trapdoor) {
        let a_matrix = <()>::random_matrix(self.k + 1, self.k);
        let b_matrix = <()>::random_matrix(self.k, self.k);
        let k_matrix = <()>::random_matrix(m1_matrix.len(), self.k + 1);
         
        let a_g2: Vec<Vec<G2Projective>> = a_matrix.iter()
            .map(|row| row.iter()
                .map(|&element| self.group.scalar_mul_p2(element))
                .collect())
            .collect();

        let ka_matrix = ().matrix_multiply(&k_matrix, &a_matrix);
        
        let ka_g2: Vec<Vec<G2Projective>> = ka_matrix.iter()
            .map(|row| row.iter()
                .map(|&element| self.group.scalar_mul_p2(element))
                .collect())
            .collect();
        
        let b_g1: Vec<Vec<G1Projective>> = b_matrix.iter()
            .map(|row| row.iter()
                .map(|&element| self.group.scalar_mul_p1(element))
                .collect())
            .collect();
        
        let m_transpose_matrix = ().transpose_g1_matrix(&m1_matrix);

        let mk_g1 = ().g1_matrix_field_multiply(&m_transpose_matrix, &k_matrix);
        
        let mut kjb_a_g2 = Vec::new();
        let mut b_kjb_g1 = Vec::new();
        
        for _j in 0..self.lamda {
            let mut kjb_row_a = Vec::new();
            let mut b_kjb_row = Vec::new();
            
            for _b in 0..2 {
                let kjb_matrix = <()>::random_matrix(self.k, self.k + 1);
                let kjb_a = ().matrix_multiply(&kjb_matrix, &a_matrix);
                
                let kjb_row_a_g2: Vec<Vec<G2Projective>> = kjb_a.iter()
                    .map(|row| row.iter()
                        .map(|&element| self.group.scalar_mul_p2(element))
                        .collect())
                    .collect();
                        
                kjb_row_a.push(kjb_row_a_g2);

                let b_kjb = ().matrix_multiply(&b_matrix, &kjb_matrix);
                
                let b_kjb_row_g1: Vec<Vec<G1Projective>> = b_kjb.iter()
                    .map(|row| row.iter()
                        .map(|&element| self.group.scalar_mul_p1(element))
                        .collect())
                    .collect();

                b_kjb_row.push(b_kjb_row_g1);
            }
            
            kjb_a_g2.push(kjb_row_a);
            b_kjb_g1.push(b_kjb_row);
        }
        
        let crs = CRS { a_g2,
                             ka_g2,
                             b_g1 , 
                             mk_g1, 
                             kjb_a_g2, 
                             b_kjb_g1, 
                            };
        let trapdoor = Trapdoor { k_matrix };
        
        (crs, trapdoor)
    }

    pub fn compute_b_k_tau_from_crs(&self, b_kjb_g1: &Vec<Vec<Vec<Vec<G1Projective>>>>,tau: &Vec<usize>) -> Vec<Vec<G1Projective>> {
        let lambda = tau.len();
        assert_eq!(b_kjb_g1.len(), lambda, "b_kjb_g1 length must match tau length");
        
        if lambda == 0 {
            return vec![vec![G1Projective::zero()]];
        }
        
        let rows = b_kjb_g1[0][0].len();
        let cols = b_kjb_g1[0][0][0].len();
        
        let mut b_k_tau = vec![vec![G1Projective::zero(); cols]; rows];
        
        for j in 0..lambda {
            let tau_j = tau[j];
            assert!(tau_j <= 1, "tau values must be 0 or 1");
            
            let b_kj_tauj = &b_kjb_g1[j][tau_j];
            
            for row in 0..rows {
                for col in 0..cols {
                    b_k_tau[row][col] = b_k_tau[row][col] + b_kj_tauj[row][col];
                }
            }
        }
        
        b_k_tau
    }
    
    pub fn compute_s_times_b_k_tau(&self, s: &Vector, b_kjb_g1: &Vec<Vec<Vec<Vec<G1Projective>>>>,tau: &Vec<usize>) -> Vec<G1Projective> {
        
        let b_k_tau = self.compute_b_k_tau_from_crs(b_kjb_g1, tau);
        
        ().vector_g1_matrix_multiply(s, &b_k_tau)
    }
    
    
    pub fn prove(&self, crs: &CRS, tag: &[u8], c0_g1: &Vec<G1Projective>, r: &Vector) -> QANIZKProof {
        let s = <()>::random_vector(self.k);
        println!("\n1");
        let t1_g1 = <()>::group_matrix_vector_mul_msm(&crs.b_g1, &s);
        println!("2");
        let hash_input = self.hash_tag_c0_t1(tag, c0_g1, &t1_g1);
        println!("3");
        let tau = self.blake3_hash_to_bits(&hash_input);
        println!("4");
        let mk_transpose = ().transpose_g1_matrix(&crs.mk_g1); 
        println!("5");
        let r_mk = ().vector_g1_matrix_multiply(r, &mk_transpose);
        println!("6");
        let s_b_k_tau = self.compute_s_times_b_k_tau(&s, &crs.b_kjb_g1, &tau);
        println!("7");
        let u1_g1: Vec<G1Projective> = r_mk.iter().zip(s_b_k_tau.iter())
            .map(|(a, b)| *a + *b)
            .collect();
        println!("7\n");    
        QANIZKProof { t1_g1, u1_g1 }
    }
    
    pub fn verify(&self, crs: &CRS, tag: &[u8], c0_g1: &Vec<G1Projective>, pie: &QANIZKProof) -> bool {
        let t1_g1 = &pie.t1_g1;
        let u1_g1 = &pie.u1_g1;
        
        let hash_input = self.hash_tag_c0_t1(tag, c0_g1, t1_g1);
        let tau = self.blake3_hash_to_bits(&hash_input);
        
        let k_tau_a = self.compute_k_tau_a_from_crs(&crs.kjb_a_g2, &tau);
        
        let mut lhs_pairings = Vec::new();  
        let mut rhs1_pairings = Vec::new();   
        let mut rhs2_pairings = Vec::new(); 
        
        for (i, &u1_elem) in u1_g1.iter().enumerate() {
            if i < crs.a_g2.len() {
                for (j, &a_elem) in crs.a_g2[i].iter().enumerate() {
                    lhs_pairings.push((u1_elem, a_elem));
                }
            }
        }
        
        for (i, &c0_elem) in c0_g1.iter().enumerate() {
            if i < crs.ka_g2.len() {
                for (j, &ka_elem) in crs.ka_g2[i].iter().enumerate() {
                    rhs1_pairings.push((c0_elem, ka_elem));
                }
            }
        }
        
        for (i, &t1_elem) in t1_g1.iter().enumerate() {
            if i < k_tau_a.len() {
                for (j, &ktau_elem) in k_tau_a[i].iter().enumerate() {
                    rhs2_pairings.push((t1_elem, ktau_elem));
                }
            }
        }
        
        let lhs = self.group.multi_pairing(&lhs_pairings);
        let rhs1 = self.group.multi_pairing(&rhs1_pairings);
        let rhs2 = self.group.multi_pairing(&rhs2_pairings);
        
        let rhs = rhs1 * rhs2;
        lhs == rhs
    }
    
    
    fn compute_k_tau_a_from_crs(&self, kjb_a_g2: &[Vec<Vec<Vec<G2Projective>>>], tau: &[usize]) -> Vec<Vec<G2Projective>> {
        let lambda = tau.len();
        assert_eq!(kjb_a_g2.len(), lambda, "kjb_a_g2 length must match tau length");
        
        if lambda == 0 {
            return vec![vec![G2Projective::zero()]];
        }
        
        let rows = kjb_a_g2[0][0].len();
        let cols = kjb_a_g2[0][0][0].len();
        
        let mut k_tau_a = vec![vec![G2Projective::zero(); cols]; rows];
        
        for j in 0..lambda {
            let tau_j = tau[j];
            assert!(tau_j <= 1, "tau values must be 0 or 1");
            
            let kj_tauj_a = &kjb_a_g2[j][tau_j];
            
            for row in 0..rows {
                for col in 0..cols {
                    k_tau_a[row][col] = k_tau_a[row][col] + kj_tauj_a[row][col];
                }
            }
        }
        
        k_tau_a
    }
    
    fn blake3_hash_to_bits(&self, input: &[u8]) -> Vec<usize> {
        let hash = blake3::hash(input);
        let hash_bytes = hash.as_bytes();
        
        let mut bits = Vec::new();
        for i in 0..self.lamda {
            let byte_idx = i / 8;
            let bit_idx = i % 8;
            if byte_idx < hash_bytes.len() {
                let bit = (hash_bytes[byte_idx] >> bit_idx) & 1;
                bits.push(bit as usize);
            } else {
                bits.push(0);
            }
        }
        bits
    }
    
    fn hash_tag_c0_t1(&self, tag: &[u8], c0_g1: &[G1Projective], t1: &[G1Projective]) -> Vec<u8> {
        let mut input = Vec::new();
        
        input.extend_from_slice(tag);
        
        for point in c0_g1 {
            input.extend_from_slice(&point.into_affine().x.into_repr().to_bytes_le());
            input.extend_from_slice(&point.into_affine().y.into_repr().to_bytes_le());
        }
        
        for point in t1 {
            input.extend_from_slice(&point.into_affine().x.into_repr().to_bytes_le());
            input.extend_from_slice(&point.into_affine().y.into_repr().to_bytes_le());
        }
        
        input
    }
}


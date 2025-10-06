use crate::common::*;
use crate::affine_mac::{AffineMAC, SecretKey as MACSecretKey};
use crate::qanizk::{QANIZK, CRS, QANIZKProof as Proof};
use ark_bls12_381::{G1Projective, G2Projective};
use ark_ff::{Field, PrimeField, Zero, One, BigInteger};
use ark_ec::ProjectiveCurve;

pub struct IBKEMPublicKey {
    pub m_matrix: Vec<Vec<G1Projective>>,   
    pub z_matrices: Vec<Vec<Vec<G1Projective>>>, 
    pub z_prime_vectors: Vec<Vec<G1Projective>>,  
    pub crs: Option<CRS>, // only for IBKEM2
}

pub struct IBKEMSecretKey {
    pub mac_sk: MACSecretKey,
    pub y_matrices: Vec<Matrix>,
    pub y_prime_vectors: Vec<Vector>,
}

pub struct IBKEMUserSecretKey {
    pub t_g2: Vec<G2Projective>,
    pub u_g2: Vec<G2Projective>,
    pub v_g2: Vec<G2Projective>,
}

pub struct IBKEMCiphertext {
    pub c0_g1: Vec<G1Projective>,
    pub c1_g1: Vec<G1Projective>,
    pub proof: Option<Proof>, // only for IBKEM2
}

pub struct IBKEM {
    pub k: usize,      
    pub eta: usize,   //eta = 2*k
    pub l: usize,     //2*len + 1
    pub l_prime: usize,
    pub mac: AffineMAC,
    pub qanizk: Option<QANIZK>, // only for IBKEM2
    pub group: GroupCtx,
}

impl IBKEM {
    pub fn new(k: usize, l: usize, l_prime: usize) -> Self {
        Self::new_ibkem1(k, l, l_prime)
    }

    pub fn new_ibkem1(k: usize, l: usize, l_prime: usize) -> Self {
        let eta = 2*k;
        Self {
            k, eta, l, l_prime,
            mac: AffineMAC::new(k, l, l_prime),
            qanizk: None, // no QANIZK for IBKEM1
            group: GroupCtx::bls12_381(),
        }
    }

    pub fn new_ibkem2(k: usize, l: usize, l_prime: usize, lambda: usize) -> Self {
        let eta = 2*k;
        Self {
            k, eta, l, l_prime,
            mac: AffineMAC::new(k, l, l_prime),
            qanizk: Some(QANIZK::new(k, lambda)), 
            group: GroupCtx::bls12_381(),
        }
    }

    pub fn setup(&self) -> (IBKEMPublicKey, IBKEMSecretKey) {
        println!("  k = {}", self.k);
        println!("  eta (2*k) = {}", self.eta);
        println!("  l  = {}", self.l);
        print!(" l' = {}", self.l_prime);
        
        let m_matrix = <()>::random_matrix(self.k + self.eta, self.k);
        println!("  M matrix dimensions: {} × {}", m_matrix.len(), m_matrix[0].len());
        
        let mac_sk = self.mac.gen_mac();
       
        println!("x_matrices length = {}", mac_sk.x_matrices.len());

        assert_eq!(mac_sk.x_matrices.len(), self.l + 1, "Wrong x_matrices count");

        let mut y_matrices = Vec::new();
        let mut z_matrices = Vec::new();
        
        for i in 0..=self.l {    
            //n=k and eta=2*k
            let y_i = <()>::random_matrix(self.k, self.k); // k * n; 
            
            let y_i_transposed = ().transpose_matrix(&y_i);
            let x_i_transposed = ().transpose_matrix(&mac_sk.x_matrices[i]);
            // let x_i_transposed = &mac_sk.x_matrices[i];
            
            // println!("i={}, k={}, eta={}", i, self.k, self.eta);
            // println!("y_i dimensions: {} rows × {} cols", y_i.len(), y_i[0].len());
            // println!("y_i_transposed dimensions: {} rows × {} cols", y_i_transposed.len(), y_i_transposed[0].len());
            // println!("x_i dimensions: {} rows × {} cols", mac_sk.x_matrices[i].len(), mac_sk.x_matrices[i][0].len());
            // println!("x_i_transposed dimensions: {} rows × {} cols", x_i_transposed.len(), x_i_transposed[0].len());

            let combined = ().concatenate_matrices(&y_i_transposed, &x_i_transposed);
            let z_i = ().matrix_multiply(&combined,&m_matrix);    
            
            
            y_matrices.push(y_i);
            z_matrices.push(z_i);
        }

        let mut y_prime_vectors = Vec::new();
        let mut z_prime_vectors = Vec::new();
        
        
        for i in 0..=self.l_prime {
            let y_prime_i = <()>::random_vector(self.k);
            
            // println!("y_prime_i.len() = {}", y_prime_i.len());
            // println!("x_prime.len() = {}", mac_sk.x_prime.len());
            // println!("m_matrix: row = {} and col = {} ", m_matrix.len(), m_matrix[0].len());        
            
            let combined = ().concatenate_vectors(&y_prime_i, &mac_sk.x_prime[i]);

            // println!("combined length of vectors = {}", combined.len());

            assert_eq!(combined.len(), m_matrix.len(), "error :dimension mismatch");

            let mut z_prime_i = vec![FieldElement::zero(); self.k];
            for j in 0..self.k {
                for k in 0..combined.len() {
                    z_prime_i[j] += combined[k]*m_matrix[k][j];
                }
            }
            
            y_prime_vectors.push(y_prime_i);
            z_prime_vectors.push(z_prime_i);
        }

        let m_g1: Vec<Vec<G1Projective>> = m_matrix.iter()
            .map(|row| row.iter()
                .map(|&element| self.group.scalar_mul_p1(element))
                .collect())
            .collect();

        
        let z_matrices_g1: Vec<Vec<Vec<G1Projective>>> = z_matrices.iter()
            .map(|matrix| matrix.iter()
                .map(|row| row.iter()
                    .map(|&element| self.group.scalar_mul_p1(element))
                    .collect())
                .collect())
            .collect();
        
        let z_prime_vectors_g1: Vec<Vec<G1Projective>> = z_prime_vectors.iter()
            .map(|vector| vector.iter()
                .map(|&element| self.group.scalar_mul_p1(element))
                .collect())
            .collect();

        let pk = IBKEMPublicKey {
            m_matrix: m_g1,
            z_matrices: z_matrices_g1,
            z_prime_vectors: z_prime_vectors_g1,
            crs : None, 
        };

        let sk = IBKEMSecretKey {
            mac_sk,
            y_matrices,
            y_prime_vectors,
        };

        (pk, sk)
    }

    // IBKEM2 setup
    pub fn setup2(&self) -> (IBKEMPublicKey, IBKEMSecretKey) {
        println!("IBKEM2 Setup:");
        
        let (mut pk, sk) = self.setup();
        
        if let Some(qanizk) = &self.qanizk {
            println!("Generating CRS for IBKEM2...");
            let (crs, _trapdoor) = qanizk.gen_crs(&pk.m_matrix);
            pk.crs = Some(crs);
            println!("CRS generation completed.");
        } else {
            println!(" CRS Not generated! ");
        }
        
        (pk, sk)
    }

    pub fn extract(&self, sk: &IBKEMSecretKey, identity: &[u8]) -> IBKEMUserSecretKey {
        let tag = self.mac.tag(&sk.mac_sk, identity);

        let mut v_field: Vector = vec![FieldElement::zero(); self.k];

        // print!("\nExt f_i = ");
        for i in 0..=self.l {
            let fi = self.mac.f_i(i, identity);
            if !fi.is_zero() {
                // print!("{} ",i);
                let yi_t = <()>::matrix_vector_mul(&sk.y_matrices[i], &tag.t_field);
                let scaled = <()>::scalar_vector_mul(fi, &yi_t);
                v_field = <()>::vector_add(&v_field, &scaled);
            }
        }

        for i in 0..=self.l_prime {
            let fi_prime = self.mac.f_prime_i(i, identity);
            if !fi_prime.is_zero() {
                let scaled_y_prime = <()>::scalar_vector_mul(fi_prime, &sk.y_prime_vectors[i]);
                v_field = <()>::vector_add(&v_field, &scaled_y_prime);
            }
        }

        let v_g2 = v_field.iter()
                .map(|&element| self.group.scalar_mul_p2(element))
                .collect(); 

        IBKEMUserSecretKey {
            t_g2: tag.t_g2,
            u_g2: tag.u_g2,
            v_g2,
        }
    }

    pub fn encrypt(&self, pk: &IBKEMPublicKey, identity: &[u8]) -> (IBKEMCiphertext, GTElement) {
        let r = <()>::random_vector(self.k);
        
        let c0_g1 = <()>::group_matrix_vector_mul_msm(&pk.m_matrix, &r);
 
        let n = pk.z_matrices[0].len();  
        let mut z_i_sum = vec![vec![G1Projective::zero(); self.k]; n];
        
        for i in 0..=self.l {
            let fi = self.mac.f_i(i, identity);
            if !fi.is_zero() {
                for row in 0..n {
                    for col in 0..self.k {
                        z_i_sum[row][col] += pk.z_matrices[i][row][col].mul(fi.into_repr());
                    }
                }
            }
        }
        
        let c1_g1 = <()>::group_matrix_vector_mul_msm(&z_i_sum, &r);
        
        let mut pairing_pairs = Vec::new();

        for i in 0..=self.l_prime {
            let fi_prime = self.mac.f_prime_i(i, identity);
            if !fi_prime.is_zero() {
                
                let mut zi_prime_dot_r = G1Projective::zero();
                for (g1_elem, &r_elem) in pk.z_prime_vectors[i].iter().zip(r.iter()){
                    zi_prime_dot_r += g1_elem.mul(r_elem.into_repr());
                }
                
                // fi * (zi_prime*r)
                let scaling = zi_prime_dot_r.mul(fi_prime.into_repr()); 
                pairing_pairs.push((scaling,self.group.p2.clone()));
            }
        }
        
        // let k_gt = self.group.scalar_expo_gt(k_field);
        let k_gt= if pairing_pairs.is_empty() { 
            GTElement::one()
        } else {
            self.group.multi_pairing(&pairing_pairs)
        };

        let ciphertext = IBKEMCiphertext { 
            c0_g1, 
            c1_g1, 
            proof: None,     // no proof for IBKEM1
        };
        (ciphertext, k_gt)
    }

    // IBKEM2 encryption
    pub fn encrypt2(&self, pk: &IBKEMPublicKey, identity: &[u8]) -> (IBKEMCiphertext, GTElement) {
        println!("IBKEM2 Encrypt for identity: {:?}", identity);
        
        let r = <()>::random_vector(self.k);
        
        let c0_g1 = <()>::group_matrix_vector_mul_msm(&pk.m_matrix, &r);
        
        let n = pk.z_matrices[0].len();
        let mut z_i_sum = vec![vec![G1Projective::zero(); self.k]; n];

        for i in 0..=self.l {
            let fi = self.mac.f_i(i, identity);
            if !fi.is_zero() {
                for row in 0..n {
                    for col in 0..self.k {
                        z_i_sum[row][col] += pk.z_matrices[i][row][col].mul(fi.into_repr());
                    }
                }
            }
        }

        let c1_g1 = <()>::group_matrix_vector_mul_msm(&z_i_sum, &r);

        let mut pairing_pairs = Vec::new();
        for i in 0..=self.l_prime {
            let fi_prime = self.mac.f_prime_i(i, identity);
            if !fi_prime.is_zero() {
                let mut zi_prime_dot_r = G1Projective::zero();
                for (g1_elem, &r_elem) in pk.z_prime_vectors[i].iter().zip(r.iter()) {
                    zi_prime_dot_r += g1_elem.mul(r_elem.into_repr());
                }
                // fi' * (z_i' * r)
                let scaling = zi_prime_dot_r.mul(fi_prime.into_repr());
                pairing_pairs.push((scaling, self.group.p2.clone()));
            }
        }

        let k_gt = if pairing_pairs.is_empty() {
            GTElement::one()
        } else {
            self.group.multi_pairing(&pairing_pairs)
        };

        let mut ciphertext = IBKEMCiphertext { 
            c0_g1, 
            c1_g1, 
            proof: None 
        };

        if let (Some(qanizk), Some(crs)) = (&self.qanizk, &pk.crs) {
            println!("Generating QANIZK proof...");
            
            // tag (identity || c0)
            let mut tag = Vec::new();
            tag.extend_from_slice(identity);
            for point in &ciphertext.c0_g1 {
                let affine = point.into_affine();
                tag.extend_from_slice(&affine.x.into_repr().to_bytes_le());
                tag.extend_from_slice(&affine.y.into_repr().to_bytes_le());
            }
            
            let proof = qanizk.prove(crs, &tag, &ciphertext.c0_g1, &r);
            ciphertext.proof = Some(proof);
            
            println!("QANIZK proof generated successfully.");
        }

        (ciphertext, k_gt)
    }


    pub fn decrypt(&self, usk: &IBKEMUserSecretKey, _identity: &[u8], ciphertext: &IBKEMCiphertext) -> Option<GTElement> {
        
        let mut w_g2 = usk.v_g2.clone();
        w_g2.extend_from_slice(&usk.u_g2);

        let c0_g1_len = ciphertext.c0_g1.len();
        let c1_g1_len= ciphertext.c1_g1.len();

        if c0_g1_len == 0 || c1_g1_len == 0 {
            return None;
        }

        let first_term: Vec<_> = (0..c0_g1_len)
            .map(|i| (ciphertext.c0_g1[i].clone(), w_g2[i].clone()))
            .collect();

        let second_term: Vec<_> = (0..c1_g1_len)
            .map(|i| (ciphertext.c1_g1[i].clone(), usk.t_g2[i].clone()))
            .collect();

        let result1 = self.group.multi_pairing(&first_term);
        let result2 = self.group.multi_pairing(&second_term);

        // K = first_term - second_term = result1 * result2^(-1)
        
        let inverse_exist = result2.inverse();
        if let Some(neg_inv) = inverse_exist {
            Some(result1*neg_inv)
        }
        else{
            None
        }
    }

    // IBKEM2 decrypt
    pub fn decrypt2(&self, pk: &IBKEMPublicKey, usk: &IBKEMUserSecretKey, identity: &[u8], ciphertext: &IBKEMCiphertext) -> Option<GTElement> {
        println!("IBKEM2 Decrypt for identity: {:?}", identity);
        
        if let (Some(qanizk), Some(crs), Some(proof)) = (&self.qanizk, &pk.crs, &ciphertext.proof) {
            println!("Verifying QANIZK proof...");
            
            // tag (identity || c0)
            let mut tag = Vec::new();
            tag.extend_from_slice(identity);
            for point in &ciphertext.c0_g1 {
                let affine = point.into_affine();
                tag.extend_from_slice(&affine.x.into_repr().to_bytes_le());
                tag.extend_from_slice(&affine.y.into_repr().to_bytes_le());
            }
            
            if !qanizk.verify(crs, &tag, &ciphertext.c0_g1, proof) {
                println!("QANIZK proof verification failed!");
                return None; 
            }
            
            println!("QANIZK proof verification succeeded!");
        }
        
        let mut w_g2 = usk.v_g2.clone();
        w_g2.extend_from_slice(&usk.u_g2);

        let c0_g1_len = ciphertext.c0_g1.len();
        let c1_g1_len = ciphertext.c1_g1.len();

        if c0_g1_len == 0 || c1_g1_len == 0 {
            return None;
        }

        let first_term: Vec<_> = (0..c0_g1_len)
            .map(|i| (ciphertext.c0_g1[i].clone(), w_g2[i].clone()))
            .collect();

        let second_term: Vec<_> = (0..c1_g1_len)
            .map(|i| (ciphertext.c1_g1[i].clone(), usk.t_g2[i].clone()))
            .collect();

        let result1 = self.group.multi_pairing(&first_term);
        let result2 = self.group.multi_pairing(&second_term);

        // K = result1 * result2^(-1)
        let inverse_exist = result2.inverse();
        if let Some(neg_inv) = inverse_exist {
            Some(result1 * neg_inv)
        } else {
            None
        }
    }

}


// #[cfg(test)]
// mod tests {
//     use super::*;

//     #[test]
//     fn test_ibkem_basic() {
//         let m_len = 128;
//         let l = 2*m_len + 1;
//         let ibkem = IBKEM::new(2, l, 0);
//         let (pk, sk) = ibkem.setup();
//         let identity = b"bob@yahoo.com";
//         let usk1 = ibkem.extract(&sk, identity);
//         let (ct1, _k1) = ibkem.encrypt(&pk, identity);
//         let k1_dec = ibkem.decrypt(&usk1, identity, &ct1);
//         assert!(k1_dec.is_some(), "IBKEM1 decryption should succeed");
//     }

// }
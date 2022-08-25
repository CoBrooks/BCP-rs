use num_bigint::{RandBigInt, BigUint};
use num_traits::{Pow, FromPrimitive, ToPrimitive};
use num_modular::ModularUnaryOps;
use num_primes::Generator;
use rand::thread_rng;

fn to_num_biguint(primes_biguint: num_primes::BigUint) -> BigUint {
    let bytes = primes_biguint.to_bytes_be();

    BigUint::from_bytes_be(&bytes)
}

#[derive(Debug)]
pub enum Error {
    Unimplemented
}

#[derive(Clone, Debug)]
pub struct PublicKey { 
    pub n: BigUint,
    pub h: BigUint,
    pub g: BigUint,
}

#[derive(Clone, Debug)]
pub struct PrivateKey {
    pub a: BigUint
}

#[derive(Clone, Debug)]
pub struct KeyPair {
    pub public: BigUint,
    pub private: BigUint
}

pub type Ciphertext = (BigUint, BigUint);

#[derive(Clone, Debug)]
pub struct Bcp {
    pub bitsize: usize,

    pub n: BigUint,
    pub k: BigUint,
    pub g: BigUint,
    
    pub mk: BigUint,
    
    pub p: BigUint,
    pub q: BigUint,
    pub n2: BigUint,
}

impl Bcp {
    pub fn new(bitsize: usize) -> Result<Self, Error> {
        let p: BigUint = to_num_biguint(Generator::safe_prime(bitsize));
        let q: BigUint = to_num_biguint(Generator::safe_prime(bitsize));
        
        let pp: BigUint = (p.clone() - 1u32) / 2u32;
        let qq: BigUint = (q.clone() - 1u32) / 2u32;

        let n = p.clone() * q.clone();
        let n2 = n.clone().pow(2u32);

        let g = Self::get_g(&p, &pp, &q, &qq, &n2);
        let k = g.modpow(&(&pp * &qq), &n2) / n.clone();
        
        let mk = pp * qq;
        
        let bcp = Self { 
            bitsize,
            n, k, g,
            mk,
            p, q, n2
        };

        Ok(bcp)
    }

    fn get_g(p: &BigUint, pp: &BigUint, qq: &BigUint, q: &BigUint, n2: &BigUint) -> BigUint {
        let one: BigUint = BigUint::from_u32(1).unwrap();

        let mut g: BigUint;
        loop {
            g = thread_rng().gen_biguint_below(n2);
            g = (g - 1u32).modpow(&2u32.into(), n2);

            if g == one { continue; }

            let tmp = g.clone().modpow(p, n2);
            if tmp == one { continue; }

            let tmp = g.clone().modpow(pp, n2);
            if tmp == one { continue; }

            let tmp = g.clone().modpow(q, n2);
            if tmp == one { continue; }
            
            let tmp = g.clone().modpow(qq, n2);
            if tmp == one { continue; }
            
            let tmp = g.clone().modpow(&(p * pp), n2);
            if tmp == one { continue; }
            
            let tmp = g.clone().modpow(&(p * q), n2);
            if tmp == one { continue; }
            
            let tmp = g.clone().modpow(&(p * qq), n2);
            if tmp == one { continue; }
            
            let tmp = g.clone().modpow(&(pp * q), n2);
            if tmp == one { continue; }
            
            let tmp = g.clone().modpow(&(pp * qq), n2);
            if tmp == one { continue; }
            
            let tmp = g.clone().modpow(&(q * qq), n2);
            if tmp == one { continue; }

            let p_pp: BigUint = p * pp;
            let q_qq: BigUint = q * qq;
            
            let tmp = g.clone().modpow(&(p_pp * qq), n2);
            if tmp == one { continue; }
            
            let tmp = g.clone().modpow(&(p * &q_qq), n2);
            if tmp == one { continue; }
            
            let tmp = g.clone().modpow(&(pp * q_qq), n2);
            if tmp == one { continue; }

            break g;
        }
    }

    pub fn gen_key(&self) -> KeyPair {
        let a_range: BigUint = &self.n2 / 2u32;
        let a: BigUint = thread_rng().gen_biguint_below(&a_range);

        let h = self.g.modpow(&a, &self.n2);

        KeyPair {
            public: h,
            private: a
        }
    }

    pub fn encrypt(&self, plaintext: u32, pk: &BigUint) -> Ciphertext {
        let m: BigUint = plaintext.into();
        let r: BigUint = thread_rng().gen_biguint_below(&self.n2);

        let a = self.g.modpow(&r, &self.n2);
        
        let b1 = (&self.n * m + 1u32) % &self.n2;
        let b2 = pk.clone().modpow(&r, &self.n2);
        let b = (b1 * b2) % &self.n2;
        
        (a, b)
    }

    pub fn decrypt(&self, ciphertext: Ciphertext, sk: &BigUint) -> u32 {
        let (a, b) = ciphertext;

        let inv_a = a.invm(&self.n2).unwrap();

        let t1: BigUint = (b * inv_a.modpow(sk, &self.n2) - 1u32) % &self.n2;
        let m: BigUint = t1 / &self.n;

        // TODO: error on overflow; better error handling
        m.to_u32().unwrap()
    }

    pub fn decrypt_mk(&self, ciphertext: Ciphertext, pk: &BigUint) -> u32 {
        let inv_mk = &self.mk.clone().invm(&self.n).unwrap();
        let kk = &self.k.clone().invm(&self.n).unwrap();

        let tmp1 = (pk.clone().modpow(&self.mk, &self.n2) - 1u32) % &self.n2;
        let a = (tmp1 / &self.n * kk) % &self.n;
        
        let tmp2 = (ciphertext.0.modpow(&self.mk, &self.n2) - 1u32) % &self.n2;
        let r = (tmp2 / &self.n * kk) % &self.n;

        let gamma = (a * r) % &self.n;

        let mut tmp3 = self.g.clone().invm(&self.n2).unwrap()
            .modpow(&gamma, &self.n2);

        tmp3 *= ciphertext.1;
        tmp3 = tmp3.modpow(&self.mk, &self.n2);
        tmp3 -= 1u32;
        tmp3 /= &self.n;
        tmp3 *= inv_mk;

        let m = tmp3 % &self.n;

        // TODO: error on overflow; better error handling
        m.to_u32().unwrap()
    }
}


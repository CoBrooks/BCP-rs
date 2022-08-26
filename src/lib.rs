use num_bigint::{RandBigInt, BigUint};
use num_integer::Integer;
use num_traits::Pow;
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
pub struct PublicKey(BigUint);

#[derive(Clone, Debug)]
pub struct PrivateKey(BigUint);

#[derive(Clone, Debug)]
pub struct KeyPair {
    pub public: PublicKey,
    pub private: PrivateKey
}

#[derive(Clone, Debug)]
pub struct Ciphertext(BigUint, BigUint);

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
    pub fn new(bitsize: usize) -> Self {
        let p: BigUint = to_num_biguint(Generator::safe_prime(bitsize));
        let q: BigUint = to_num_biguint(Generator::safe_prime(bitsize));
        
        let pp: BigUint = (p.clone() - 1u32) / 2u32;
        let qq: BigUint = (q.clone() - 1u32) / 2u32;

        let n = p.clone() * q.clone();
        let n2 = n.clone().pow(2u32);

        let mut alpha = thread_rng().gen_biguint_below(&n2);
        // Only happens if alpha divides by n
        while alpha.gcd(&n2) != 1u32.into() {
            alpha = thread_rng().gen_biguint_below(&n2);
        }

        let g = alpha.modpow(&2u32.into(), &n2);

        let k = g.modpow(&(&pp * &qq), &n2) / n.clone();
        
        let mk = pp * qq;
        
        Self { 
            bitsize,
            n, k, g,
            mk,
            p, q, n2
        }
    }

    pub fn gen_key(&self) -> KeyPair {
        let a_range: BigUint = &self.n2 / 2u32;
        let a: BigUint = thread_rng().gen_biguint_below(&a_range);

        let h = self.g.modpow(&a, &self.n2);

        KeyPair {
            public: PublicKey(h),
            private: PrivateKey(a)
        }
    }

    pub fn encrypt(&self, m: BigUint, public_key: &PublicKey) -> Ciphertext {
        assert!(m < self.n);

        let PublicKey(pk) = public_key;

        let r: BigUint = thread_rng().gen_biguint_below(&self.n2);

        let a = self.g.modpow(&r, &self.n2);
        
        let b1 = (&self.n * m + 1u32) % &self.n2;
        let b2 = pk.clone().modpow(&r, &self.n2);
        let b = (b1 * b2) % &self.n2;
        
        Ciphertext(a, b)
    }

    pub fn decrypt(&self, ciphertext: Ciphertext, private_key: &PrivateKey) -> BigUint {
        let Ciphertext(a, b) = ciphertext;
        let PrivateKey(sk) = private_key;

        let inv_a = a.invm(&self.n2).unwrap();

        let t1: BigUint = (b * inv_a.modpow(sk, &self.n2) - 1u32) % &self.n2;
        let m: BigUint = t1 / &self.n;

        m
    }

    pub fn decrypt_mk(&self, ciphertext: Ciphertext, public_key: &PublicKey) -> BigUint {
        let PublicKey(pk) = public_key;

        let inv_mk = &self.mk.clone().invm(&self.n).unwrap();
        let kk = &self.k.clone().invm(&self.n).unwrap();

        let tmp1 = (pk.clone().modpow(&self.mk, &self.n2) - 1u32) % &self.n2;
        let a = (tmp1 / &self.n * kk) % &self.n;
        
        let tmp2 = (ciphertext.0.modpow(&self.mk, &self.n2) - 1u32) % &self.n2;
        let r = (tmp2 / &self.n * kk) % &self.n;

        let gamma = (a * r) % &self.n;

        let inv_g_pow_gamma = self.g.clone().invm(&self.n2).unwrap()
            .modpow(&gamma, &self.n2);

        let numerator = (ciphertext.1 * inv_g_pow_gamma).modpow(&self.mk, &self.n2) - 1u32;

        (numerator / &self.n * inv_mk) % &self.n
    }

    pub fn encrypt_str(&self, plaintext: &str, public_key: &PublicKey) -> String {
        let chunk_size = self.bitsize / 8;
        let chunks = plaintext.as_bytes().chunks(chunk_size);

        let mut ciphertexts: Vec<Ciphertext> = Vec::new();

        // Generate ciphertexts for each block
        for chunk in chunks {
            let num = BigUint::from_bytes_be(chunk);
            let ciphertext = self.encrypt(num, public_key);

            ciphertexts.push(ciphertext);
        }

        let mut c: String = String::new();

        // Concat into a single string
        for ciphertext in ciphertexts {
            let Ciphertext(a, b) = ciphertext;

            // Convert to base 92 (ascii " to ~)
            let a = a.to_radix_be(92);
            for digit in a {
                let ch = digit + b'"';
                c.push(ch.into());
            }

            // ! separates A from B
            c.push('!');

            let b = b.to_radix_be(92);
            for digit in b {
                let ch = digit + b'"';
                c.push(ch.into());
            }

            // ' ' separates ciphertexts
            c.push(' ');
        }
        c.pop();

        c
    }

    pub fn decrypt_str(&self, ciphertext: &str, private_key: &PrivateKey) -> String {
        let chunks: Vec<&str> = ciphertext.split(' ').collect();

        let mut s: String = String::new();

        for chunk in chunks {
            if let Some((a, b)) = chunk.split_once('!') {
                let a_bytes: Vec<u8> = a.as_bytes().iter().map(|b| b - b'"').collect();
                let b_bytes: Vec<u8> = b.as_bytes().iter().map(|b| b - b'"').collect();

                let a = BigUint::from_radix_be(&a_bytes, 92).unwrap();
                let b = BigUint::from_radix_be(&b_bytes, 92).unwrap();

                let num = self.decrypt(Ciphertext(a, b), private_key);
                let chars = num.to_bytes_be();

                for c in chars {
                    s.push(c.into());
                }
            } else {
                unreachable!()
            }
        }

        s
    }
    
    pub fn decrypt_str_mk(&self, ciphertext: &str, public_key: &PublicKey) -> String {
        let chunks: Vec<&str> = ciphertext.split(' ').collect();

        let mut s: String = String::new();

        for chunk in chunks {
            if let Some((a, b)) = chunk.split_once('!') {
                let a_bytes: Vec<u8> = a.as_bytes().iter().map(|b| b - b'"').collect();
                let b_bytes: Vec<u8> = b.as_bytes().iter().map(|b| b - b'"').collect();

                let a = BigUint::from_radix_be(&a_bytes, 92).unwrap();
                let b = BigUint::from_radix_be(&b_bytes, 92).unwrap();

                let num = self.decrypt_mk(Ciphertext(a, b), public_key);
                let chars = num.to_bytes_be();

                for c in chars {
                    s.push(c.into());
                }
            } else {
                unreachable!()
            }
        }

        s
    }
}


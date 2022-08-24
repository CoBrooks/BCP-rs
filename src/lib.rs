use rug::Integer;
use rug::integer::IsPrime;
use rug::ops::Pow;
use rug::rand::RandState;

#[derive(Debug)]
pub enum Error {
    Unimplemented
}

#[derive(Clone, Debug)]
pub struct PublicKey { 
    pub n: Integer,
    pub h: Integer,
    pub g: Integer,
}

#[derive(Clone, Debug)]
pub struct PrivateKey {
    pub a: Integer
}

#[derive(Clone, Debug)]
pub struct KeyPair {
    pub public: Integer,
    pub private: Integer
}

pub type Ciphertext = (Integer, Integer);

#[derive(Clone, Debug)]
pub struct Bcp {
    pub bitsize: u32,

    pub n: Integer,
    pub k: Integer,
    pub g: Integer,
    
    pub mk: Integer,
    
    pub p: Integer,
    pub q: Integer,
    pub n2: Integer,
}

fn rand_safe_prime(bitsize: u32, rng: &mut RandState) -> Integer {
        let mut pp: Integer = Integer::random_bits(bitsize, rng).into();
        pp.next_prime_mut();

        let mut p: Integer = (2 * pp.clone()) + 1;
        loop {
            match p.is_probably_prime(30) {
                IsPrime::Yes => return p,
                _ => {
                    pp.next_prime_mut();
                    p = (2 * pp.clone()) + 1;
                }
            }
        }

}

impl Bcp {
    pub fn new(bitsize: u32, rng: &mut RandState) -> Result<Self, Error> {
        let p = rand_safe_prime(bitsize, rng);
        let q = rand_safe_prime(bitsize, rng);
        
        let pp: Integer = (p.clone() - 1) / 2;
        let qq: Integer = (q.clone() - 1) / 2;

        let n = p.clone() * q.clone();
        let n2 = n.clone().pow(2u32);

        let g = Self::get_g(&p, &pp, &q, &qq, &n2, rng);
        let k = g.clone().pow_mod(&(&pp * &qq).into(), &n2).unwrap() / n.clone();
        
        let mk = pp * qq;
        
        let bcp = Self { 
            bitsize,
            n, k, g,
            mk,
            p, q, n2
        };

        Ok(bcp)
    }

    fn get_g(p: &Integer, pp: &Integer, qq: &Integer, q: &Integer, n2: &Integer, rng: &mut RandState) -> Integer {
        let mut g: Integer;
        loop {
            g = n2.clone().random_below(rng);
            g = (g - Integer::from(1i32)).pow_mod(&2.into(), n2).unwrap();

            if g == 1 { continue; }

            let tmp = g.clone().pow_mod(p, n2).unwrap();
            if tmp == 1 { continue; }

            let tmp = g.clone().pow_mod(pp, n2).unwrap();
            if tmp == 1 { continue; }

            let tmp = g.clone().pow_mod(q, n2).unwrap();
            if tmp == 1 { continue; }
            
            let tmp = g.clone().pow_mod(qq, n2).unwrap();
            if tmp == 1 { continue; }
            
            let tmp = g.clone().pow_mod(&(p * pp).into(), n2).unwrap();
            if tmp == 1 { continue; }
            
            let tmp = g.clone().pow_mod(&(p * q).into(), n2).unwrap();
            if tmp == 1 { continue; }
            
            let tmp = g.clone().pow_mod(&(p * qq).into(), n2).unwrap();
            if tmp == 1 { continue; }
            
            let tmp = g.clone().pow_mod(&(pp * q).into(), n2).unwrap();
            if tmp == 1 { continue; }
            
            let tmp = g.clone().pow_mod(&(pp * qq).into(), n2).unwrap();
            if tmp == 1 { continue; }
            
            let tmp = g.clone().pow_mod(&(q * qq).into(), n2).unwrap();
            if tmp == 1 { continue; }

            let p_pp: Integer = (p * pp).into();
            let q_qq: Integer = (q * qq).into();
            
            let tmp = g.clone().pow_mod(&(&p_pp * qq).into(), n2).unwrap();
            if tmp == 1 { continue; }
            
            let tmp = g.clone().pow_mod(&(p * &q_qq).into(), n2).unwrap();
            if tmp == 1 { continue; }
            
            let tmp = g.clone().pow_mod(&(pp * &q_qq).into(), n2).unwrap();
            if tmp == 1 { continue; }

            break g;
        }
    }

    pub fn gen_key(&self, rng: &mut RandState) -> KeyPair {
        let a_range: Integer = (&self.n2 / 2i32).into();
        let a = a_range.random_below(rng);

        let h = self.g.clone().pow_mod(&a, &self.n2).unwrap();

        KeyPair {
            public: h,
            private: a
        }
    }

    pub fn encrypt(&self, plaintext: u32, pk: &Integer, rng: &mut RandState) -> Ciphertext {
        let m: Integer = plaintext.into();
        let r = self.n2.clone().random_below(rng);

        let a = self.g.clone().pow_mod(&r, &self.n2).unwrap();
        
        let b1 = (&self.n * m + 1) % &self.n2;
        let b2 = pk.clone().pow_mod(&r, &self.n2).unwrap();
        let b = (b1 * b2) % &self.n2;
        
        (a, b)
    }

    pub fn decrypt(&self, ciphertext: Ciphertext, sk: &Integer) -> u32 {
        let (a, b) = ciphertext;

        let inv_a = a.invert(&self.n2).unwrap();

        let t1: Integer = (b * inv_a.pow_mod(sk, &self.n2).unwrap() - 1) % &self.n2;
        let m: Integer = t1 / &self.n;

        // TODO: error on overflow; better error handling
        m.to_u32_wrapping()
    }

    pub fn decrypt_mk(&self, ciphertext: Ciphertext, pk: &Integer) -> u32 {
        let inv_mk = &self.mk.clone().invert(&self.n).unwrap();
        let kk = &self.k.clone().invert(&self.n).unwrap();

        let tmp1 = (pk.clone().pow_mod(&self.mk, &self.n2).unwrap() - 1i32) % &self.n2;
        let a = (tmp1 / &self.n * kk) % &self.n;
        
        let tmp2 = (ciphertext.0.pow_mod(&self.mk, &self.n2).unwrap() - 1i32) % &self.n2;
        let r = (tmp2 / &self.n * kk) % &self.n;

        let gamma = (a * r) % &self.n;

        let mut tmp3 = self.g.clone().invert(&self.n2).unwrap()
            .pow_mod(&gamma, &self.n2).unwrap();

        tmp3 *= ciphertext.1;
        tmp3.pow_mod_mut(&self.mk, &self.n2).unwrap();
        tmp3 -= 1;
        tmp3 /= &self.n;
        tmp3 *= inv_mk;

        let m = tmp3 % &self.n;

        // TODO: error on overflow; better error handling
        m.to_u32_wrapping()
    }
}


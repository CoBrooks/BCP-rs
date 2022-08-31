#![allow(non_upper_case_globals)]

use num_bigint::BigUint;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct KeyPair {
    public: String,
    private: String,
}

#[wasm_bindgen]
impl KeyPair {
    #[wasm_bindgen(getter)]
    pub fn public(&self) -> String {
        self.public.clone()
    }
    
    #[wasm_bindgen(getter)]
    pub fn private(&self) -> String {
        self.private.clone()
    }
}

#[wasm_bindgen]
pub struct Bcp(crate::Bcp);

#[wasm_bindgen]
impl Bcp {
    #[wasm_bindgen(constructor)]
    pub fn new(bitsize: usize) -> Self {
        let bcp = crate::Bcp::new(bitsize);

        Self(bcp)
    }

    #[wasm_bindgen]
    pub fn gen_keypair(&self) -> KeyPair {
        let super::KeyPair { public, private } = self.0.gen_key();
        let super::PublicKey(pk) = public;
        let super::PrivateKey(sk) = private;

        let public = base64::encode(pk.to_bytes_be());
        let private = base64::encode(sk.to_bytes_be());

        KeyPair { public, private }
 
    }
    
    #[wasm_bindgen]
    pub fn encrypt(&self, plaintext: &str, pk: &str) -> String {
        let pk = BigUint::from_bytes_be(&base64::decode(pk).unwrap());

        self.0.encrypt_str(plaintext, &crate::PublicKey(pk))
    }
    
    #[wasm_bindgen]
    pub fn decrypt(&self, ciphertext: &str, sk: &str) -> String {
        let sk = BigUint::from_bytes_be(&base64::decode(sk).unwrap());

        self.0.decrypt_str(ciphertext, &crate::PrivateKey(sk))
    }
    
    #[wasm_bindgen]
    pub fn decrypt_mk(&self, ciphertext: &str, pk: &str) -> String {
        let pk = BigUint::from_bytes_be(&base64::decode(pk).unwrap());

        self.0.decrypt_str_mk(ciphertext, &crate::PublicKey(pk))
    }
}

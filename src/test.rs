use num_bigint::BigUint;
use wright::*;

fn main() {
    describe("Bcp", || {
        use bcp_rs::{ Bcp, KeyPair };

        describe("::new(bitsize)", || {
            let bcp = Bcp::new(16);

            // TODO: Validate initial values
            it("should initialize a new Bcp", || {
                true
            });

            let key1 = bcp.gen_key();
            let key2 = bcp.gen_key();

            // TODO: actually test key generation
            describe(".gen_key()", || {
                it("should return a public-private key pair", || {
                    let KeyPair { public: _pk, private: _sk } = key1.clone();

                    true
                });

                it("should not generate duplicate key pairs", || {
                    let KeyPair { public: _pk1, private: _sk1 } = key1.clone();
                    let KeyPair { public: _pk2, private: _sk2 } = key2.clone();

                    true
                });
            });

            let data: BigUint = 100u32.into();

            let ciphertext = bcp.encrypt(data.clone(), &key1.public);

            describe(".encrypt(plaintext, pk)", || {
                it("should return encrypted plaintext", || {
                    // TODO: validate encryption
                    
                    true
                });
            });


            describe(".decrypt(ciphertext, pk)", || {
                it("should decrypt ciphertext encrypted with pk", || {
                    let decrypted = bcp.decrypt(ciphertext.clone(), &key1.private);

                    expect(&decrypted).to().equal(data.clone())
                });
                
                it("should fail to decrypt ciphertext encrypted with sk", || {
                    let decrypted = bcp.decrypt(ciphertext.clone(), &key2.private);

                    !expect(&decrypted).to().equal(data.clone())
                });
            });

            describe(".decrypt_with_mk(ciphertext, public_key)", || {
                it("should decrypt ciphertext encrypted with pk", || {
                    let ciphertext = bcp.encrypt(data.clone(), &key1.public);
                    let decrypted = bcp.decrypt_mk(ciphertext, &key1.public);

                    expect(&decrypted).to().equal(data.clone())
                });
                
                it("should decrypt ciphertext encrypted with sk", || {
                    let ciphertext = bcp.encrypt(data.clone(), &key2.public);
                    let decrypted = bcp.decrypt_mk(ciphertext, &key2.public);

                    expect(&decrypted).to().equal(data.clone())
                });
            });

            let data: String = "Hello, World!".to_string();
            let ciphertext = bcp.encrypt_str(&data, &key1.public);

            let d = data.len();
            let c = ciphertext.len();
            let eff = d as f32 / c as f32;
            let recip = eff.recip();

            println!("Efficiency = {:.2}% [{d} / {c}]", eff * 100.0);
            println!("Encrypted text is {recip:.2}x bigger than the plaintext");

            // TODO: validate encryption
            describe(".encrypt_str(string, public_key)", || {
                it("should return an encrypted string", || {
                    !expect(&ciphertext).to().equal(data.clone())
                });
            });

            describe(".decrypt_str(string, private_key)", || {
                it("should decrypt the encrypted string", || {
                    let decrypted = bcp.decrypt_str(&ciphertext, &key1.private);
                    
                    expect(&decrypted).to().equal(data.clone())
                });
            });


            describe(".decrypt_str_mk(string, public_key)", || {
                it("should decrypt the encrypted string", || {
                    let decrypted = bcp.decrypt_str_mk(&ciphertext, &key1.public);

                    expect(&decrypted).to().equal(data.clone())
                });
            });
        });
    });
}

use wright::*;

fn main() {
    describe("Bcp", || {
        use bcp_rs::{ Bcp, KeyPair };
        use rug::rand::RandState;

        describe("::new(bitsize)", || {
            let mut rng = RandState::new();

            let bcp = Bcp::new(16, &mut rng);

            it("should initialize a new Bcp", || {
                expect(&bcp).to().be().ok()
            });

            let bcp = bcp.unwrap();

            let key1 = bcp.gen_key(&mut rng);
            let key2 = bcp.gen_key(&mut rng);

            describe(".gen_key()", || {
                it("should return a public-private key pair", || {
                    let KeyPair { public, private } = key1.clone();

                    !expect(&public).to().equal(0)
                        && !expect(&private).to().equal(0)
                });

                it("should not generate duplicate key pairs", || {
                    let KeyPair { public: pk1, private: sk1 } = key1.clone();
                    let KeyPair { public: pk2, private: sk2 } = key2.clone();

                    !expect(&pk1).to().equal(pk2)
                        && !expect(&sk1).to().equal(sk2)

                });
            });

            const DATA: u32 = 100;

            let ciphertext = bcp.encrypt(DATA, &key1.public, &mut rng);

            describe(".encrypt(plaintext, pk)", || {
                it("should return encrypted plaintext", || {
                    let (a, b) = ciphertext.clone();

                    a > 0 && b > 0
                });
            });


            describe(".decrypt(ciphertext, pk)", || {
                it("should decrypt ciphertext encrypted with pk", || {
                    let decrypted = bcp.decrypt(ciphertext.clone(), &key1.private);

                    expect(&decrypted).to().equal(DATA)
                });
                
                it("should fail to decrypt ciphertext encrypted with sk", || {
                    let decrypted = bcp.decrypt(ciphertext.clone(), &key2.private);

                    !expect(&decrypted).to().equal(DATA)
                });
            });

            describe(".decrypt_with_mk(ciphertext)", || {
                it("should decrypt ciphertext encrypted with pk", || {
                    let ciphertext = bcp.encrypt(DATA, &key1.public, &mut rng.clone());
                    let decrypted = bcp.decrypt_mk(ciphertext, &key1.public);

                    expect(&decrypted).to().equal(DATA)
                });
                
                it("should decrypt ciphertext encrypted with sk", || {
                    let ciphertext = bcp.encrypt(DATA, &key2.public, &mut rng.clone());
                    let decrypted = bcp.decrypt_mk(ciphertext, &key2.public);

                    expect(&decrypted).to().equal(DATA)
                });
            });
        });
    });
}

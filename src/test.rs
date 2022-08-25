use num_bigint::BigUint;
use num_traits::FromPrimitive;
use wright::*;

fn main() {
    describe("Bcp", || {
        use bcp_rs::{ Bcp, KeyPair };

        describe("::new(bitsize)", || {
            let bcp = Bcp::new(16);

            it("should initialize a new Bcp", || {
                expect(&bcp).to().be().ok()
            });

            let bcp = bcp.unwrap();

            let key1 = bcp.gen_key();
            let key2 = bcp.gen_key();

            describe(".gen_key()", || {
                it("should return a public-private key pair", || {
                    let KeyPair { public, private } = key1.clone();

                    let zero = BigUint::from_u8(0).unwrap();

                    !expect(&public).to().equal(zero.clone())
                        && !expect(&private).to().equal(zero)
                });

                it("should not generate duplicate key pairs", || {
                    let KeyPair { public: pk1, private: sk1 } = key1.clone();
                    let KeyPair { public: pk2, private: sk2 } = key2.clone();

                    !expect(&pk1).to().equal(pk2)
                        && !expect(&sk1).to().equal(sk2)

                });
            });

            const DATA: u32 = 100;

            let ciphertext = bcp.encrypt(DATA, &key1.public);

            describe(".encrypt(plaintext, pk)", || {
                it("should return encrypted plaintext", || {
                    let (a, b) = ciphertext.clone();

                    a > 0u32.into() && b > 0u32.into()
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

            describe(".decrypt_with_mk(ciphertext, public_key)", || {
                it("should decrypt ciphertext encrypted with pk", || {
                    let ciphertext = bcp.encrypt(DATA, &key1.public);
                    let decrypted = bcp.decrypt_mk(ciphertext, &key1.public);

                    expect(&decrypted).to().equal(DATA)
                });
                
                it("should decrypt ciphertext encrypted with sk", || {
                    let ciphertext = bcp.encrypt(DATA, &key2.public);
                    let decrypted = bcp.decrypt_mk(ciphertext, &key2.public);

                    expect(&decrypted).to().equal(DATA)
                });
            });
        });
    });
}

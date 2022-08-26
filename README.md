# BCP-rs

An implementation of the cryptographic algorithm described in 
*A Simple Public-Key Cryptosystem with a Double Trapdoor Decryption 
Mechanism and its Applications* 
([Bresson, Catalano, and Pointcheval](https://iacr.org/archive/asiacrypt2003/01_Session01/03_106/28940037.pdf))
and further described by *Efficiently Outsourcing Multiparty 
Computation under Multiple Keys*
([Peter, Tews, and Katzenbeisser, pg. 5](https://eprint.iacr.org/2013/013.pdf#page=5)).

## Testing

```bash
$ git clone https://github.com/CoBrooks/BCP-rs.git
$ cd BCP-rs
$ cargo test -q wright
```

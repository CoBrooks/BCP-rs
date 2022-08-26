# BCP-rs

An implementation of the cryptographic algorithm described in 
*A Simple Public-Key Cryptosystem with a Double Trapdoor Decryption 
Mechanism and its Applications* 
([Bresson, Catalano, and Pointcheval](https://iacr.org/archive/asiacrypt2003/01_Session01/03_106/28940037.pdf))
and further described by *Efficiently Outsourcing Multiparty 
Computation under Multiple Keys*
([Peter, Tews, and Katzenbeisser, pg. 5](https://eprint.iacr.org/2013/013.pdf#page=5)).

## Note

Due to an innefficient implementation of safe prime generation, 
higher bitsizes (128+) start slowing down the initial key generation
algorithm considerably.

From some very quick-and-dirty benchmarks on a 2014 Mac Air with an i7-4650U:
```
BITSIZE | TIME TO COMPLETE TESTS
     16 | 1.20s
     32 | 1.69s
     64 | 10.50s
    128 | 169.03s
```

## Testing

Uses my BDD testing library - [Wright](https://github.com/CoBrooks/wright).

```bash
$ git clone https://github.com/CoBrooks/BCP-rs.git
$ cd BCP-rs
$ cargo test -q wright
```

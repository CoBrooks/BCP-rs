# BCP-rs

An implementation of the cryptographic algorithm described in 
*A Simple Public-Key Cryptosystem with a Double Trapdoor Decryption 
Mechanism and its Applications* 
([Bresson, Catalano, and Pointcheval](https://iacr.org/archive/asiacrypt2003/01_Session01/03_106/28940037.pdf))
and further described by *Efficiently Outsourcing Multiparty 
Computation under Multiple Keys*
([Peter, Tews, and Katzenbeisser, pg. 5](https://eprint.iacr.org/2013/013.pdf#page=5)).

## Testing

Uses my BDD testing library - [Wright](https://github.com/CoBrooks/wright).

```bash
$ cargo test -q wright
```

## Benchmarks

```bash
$ cargo bench
```

## WASM

See [the WASM example](./WASM-example).

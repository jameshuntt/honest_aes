# honest_aes

AES built on the [`honest`](https://crates.io/crates/honest) field, with no
lookup tables.

Every textbook AES keeps a 256-byte S-box in memory and indexes it with
secret bytes; that is where cache-timing attacks get their signal. Here the
S-box is computed for each byte as the field inverse followed by the affine
map, MixColumns is multiplication in GF(2^8), and the round constants are
made by doubling. All of that arithmetic comes from `honest`, where it is
written with masks and shifts and never branches on a value.

The price is speed: a block costs a few thousand field operations instead
of a few dozen table lookups. This crate is for the sizes that matter to
key handling, wrapping a data key, sealing a token, tagging a message, not
for streaming gigabytes.

```rust
use honest_aes::{gcm, Aes};

let key = Aes::aes256(&[0x42; 32]);
let nonce = [7u8; 12];               // never reused under one key

// AES-256-GCM: ciphertext followed by a 16-byte tag over the header and the data
let sealed = gcm::encrypt(&key, &nonce, b"header", b"wrap this data key").unwrap();
let opened = gcm::decrypt(&key, &nonce, b"header", &sealed).unwrap();
assert_eq!(opened, b"wrap this data key");

// a changed header or a flipped bit is refused, and nothing is returned
assert!(gcm::decrypt(&key, &nonce, b"other", &sealed).is_err());
```

## What is here

| module | mode | note |
|---|---|---|
| `Aes` | the block cipher, 128/192/256-bit keys | round keys zeroized on drop |
| `gcm` | AES-GCM, 16-byte tag, any nonce length | `seal`/`open` in place, `encrypt`/`decrypt` with vectors |
| `ctr` | counter mode | 128-bit big-endian counter, one shot |
| `cbc` | cipher block chaining | with PKCS#7 (`encrypt`/`decrypt`) or whole blocks only |
| `cmac` | CMAC | `tag` and constant-time `verify` |

CBC is confidentiality only; a wrong key or a tampered ciphertext yields
garbage or a padding error, and that error is an oracle if an attacker can
observe it. Use GCM on a wire. CBC is here for formats that require it.

## Proof

- FIPS 197 Appendix C (all three key sizes), Appendix A key schedules.
- SP 800-38A Appendix F: ECB, CBC and CTR vectors for AES-128 and AES-256.
- RFC 4493: the four CMAC examples.
- The GCM specification's test cases 1 to 5, including the 64-bit nonce.
- Every mode against the RustCrypto crates on random inputs, all key sizes,
  message lengths around the block boundary, tampering at random positions.

## Not here

Other modes, key derivation, and any container for the key bytes. The
`classified_aes` crate adds the containers.

`no_std` with `alloc` when the `std` feature is off.

## License

MIT OR Apache-2.0.

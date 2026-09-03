//! AES on the [`honest`] field, with no lookup tables.
//!
//! Every textbook AES keeps a 256-byte S-box in memory and indexes it with
//! secret bytes, which is where cache-timing attacks get their signal. This
//! implementation keeps nothing in memory: the S-box is computed for each
//! byte as the field inverse followed by the affine map, MixColumns is
//! multiplication in GF(2^8), and the round constants are made by doubling.
//! All of that arithmetic comes from [`honest`], where it is written with
//! masks and shifts and never branches on a value. The only data-dependent
//! work left in the cipher is arithmetic.
//!
//! The price is speed: a block costs a few thousand field operations
//! instead of a few dozen table lookups. This crate is for the sizes that
//! matter to key handling, wrapping a data key, sealing a token, tagging a
//! message, not for streaming gigabytes.
//!
//! ```
//! use honest_aes::{gcm, Aes};
//!
//! let key = Aes::aes256(&[0x42; 32]);
//! let nonce = [7u8; 12];
//!
//! let mut data = *b"wrap this data key";
//! let tag = gcm::seal(&key, &nonce, b"header", &mut data).unwrap();
//!
//! gcm::open(&key, &nonce, b"header", &mut data, &tag).unwrap();
//! assert_eq!(&data, b"wrap this data key");
//! ```
//!
//! What is here: the block cipher for all three key sizes ([`Aes`]),
//! counter mode ([`ctr`]), cipher block chaining with PKCS#7 ([`cbc`]),
//! CMAC ([`cmac`]) and Galois/Counter Mode ([`gcm`]). What is not: any
//! other mode, key derivation, or a container for the key bytes; the
//! `classified_aes` crate adds the containers.
//!
//! Correctness is proven against the FIPS 197 and SP 800-38A/B/D vectors
//! and, for every mode, against the RustCrypto implementations on random
//! inputs (see the tests). `no_std` with `alloc`.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

extern crate alloc;

mod block;
pub mod cbc;
pub mod cmac;
pub mod ctr;
mod error;
pub mod gcm;
mod ghash;
mod key_schedule;
mod round;
mod sbox;

pub use block::{Aes, BLOCK};
pub use error::AesError;

#[cfg(doctest)]
#[doc = include_str!("../README.md")]
mod readme_doctests {}

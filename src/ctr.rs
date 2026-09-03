//! Counter mode (SP 800-38A §6.5): the cipher makes a keystream from a
//! counter, and the data is XORed with it. Encryption and decryption are
//! the same operation.
//!
//! The counter is the whole 16-byte block as a big-endian integer,
//! incremented by one per block. Never reuse a counter block under one
//! key: two messages under the same keystream reveal their XOR.

use crate::{Aes, BLOCK};

/// XOR `data` with the keystream that starts at `counter`, in place.
///
/// ```
/// use honest_aes::{ctr, Aes};
///
/// let aes = Aes::aes128(&[1; 16]);
/// let start = [0u8; 16];
/// let mut msg = *b"stream me";
/// ctr::apply(&aes, &start, &mut msg);
/// assert_ne!(&msg, b"stream me");
/// ctr::apply(&aes, &start, &mut msg);
/// assert_eq!(&msg, b"stream me");
/// ```
pub fn apply(aes: &Aes, counter: &[u8; BLOCK], data: &mut [u8]) {
    let mut counter = u128::from_be_bytes(*counter);
    for chunk in data.chunks_mut(BLOCK) {
        let mut keystream = counter.to_be_bytes();
        aes.encrypt_block(&mut keystream);
        for (d, k) in chunk.iter_mut().zip(keystream.iter()) {
            *d ^= k;
        }
        counter = counter.wrapping_add(1);
    }
}

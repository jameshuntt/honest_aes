//! CMAC (SP 800-38B, RFC 4493): a 16-byte message authentication code
//! from the block cipher alone.

use subtle::ConstantTimeEq;

use crate::{Aes, BLOCK};

/// The tag of `message` under `aes`.
///
/// ```
/// use honest_aes::{cmac, Aes};
///
/// let aes = Aes::aes128(&[0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c]);
/// // RFC 4493 example 1: the empty message
/// assert_eq!(cmac::tag(&aes, b"")[..4], [0xbb, 0x1d, 0x69, 0x29]);
/// ```
pub fn tag(aes: &Aes, message: &[u8]) -> [u8; BLOCK] {
    let (k1, k2) = subkeys(aes);
    let mut x = [0u8; BLOCK];

    let full_blocks = message.len() / BLOCK;
    let remainder = message.len() % BLOCK;
    // the last block is "complete" only when the message is non-empty and block-aligned
    let last_is_complete = remainder == 0 && !message.is_empty();
    let whole = if last_is_complete { full_blocks - 1 } else { full_blocks };

    for chunk in message[..whole * BLOCK].chunks_exact(BLOCK) {
        for (x, m) in x.iter_mut().zip(chunk) {
            *x ^= m;
        }
        aes.encrypt_block(&mut x);
    }

    let mut last = [0u8; BLOCK];
    let tail = &message[whole * BLOCK..];
    last[..tail.len()].copy_from_slice(tail);
    let key = if last_is_complete {
        k1
    } else {
        last[tail.len()] = 0x80;
        k2
    };
    for i in 0..BLOCK {
        x[i] ^= last[i] ^ key[i];
    }
    aes.encrypt_block(&mut x);
    x
}

/// Whether `tag` is the tag of `message`, compared in constant time.
pub fn verify(aes: &Aes, message: &[u8], tag: &[u8; BLOCK]) -> bool {
    bool::from(self::tag(aes, message).ct_eq(tag))
}

/// K1 and K2: the cipher of the zero block, doubled once and twice in
/// GF(2^128) with the CMAC polynomial, without branching on the carry.
fn subkeys(aes: &Aes) -> ([u8; BLOCK], [u8; BLOCK]) {
    let mut l = [0u8; BLOCK];
    aes.encrypt_block(&mut l);
    let k1 = double(&l);
    let k2 = double(&k1);
    (k1, k2)
}

fn double(block: &[u8; BLOCK]) -> [u8; BLOCK] {
    let v = u128::from_be_bytes(*block);
    let carry = (v >> 127) as u8;
    let shifted = v << 1;
    // subtract from zero turns the carry bit into an all-ones or all-zeros mask
    let mask = 0u8.wrapping_sub(carry);
    (shifted ^ u128::from(0x87 & mask)).to_be_bytes()
}

//! Galois/Counter Mode (SP 800-38D): counter-mode encryption plus a
//! 16-byte tag over the associated data and the ciphertext.
//!
//! A nonce must never repeat under one key. The 96-bit nonce is the
//! recommended size and the fast path; other lengths are hashed into the
//! initial counter as the spec describes. Decryption checks the tag before
//! returning anything: on a mismatch the buffer is zeroized and the error
//! is the only output.

use alloc::vec::Vec;

use subtle::ConstantTimeEq;

use crate::ghash::Ghash;
use crate::{ctr, Aes, AesError, BLOCK};

/// The tag size in bytes.
pub const TAG: usize = 16;

/// The most plaintext one call may carry: 2^36 − 32 bytes, from the 32-bit
/// block counter.
const MAX_MESSAGE: u64 = (1 << 36) - 32;

/// Encrypt `data` in place and return the tag over `aad` and the result.
///
/// ```
/// use honest_aes::{gcm, Aes};
///
/// let aes = Aes::aes128(&[0; 16]);
/// let mut data = [0u8; 16];
/// let tag = gcm::seal(&aes, &[0; 12], b"", &mut data).unwrap();
/// // the GCM spec's test case 2
/// assert_eq!(data[..4], [0x03, 0x88, 0xda, 0xce]);
/// assert_eq!(tag[..4], [0xab, 0x6e, 0x47, 0xd4]);
/// ```
pub fn seal(aes: &Aes, nonce: &[u8], aad: &[u8], data: &mut [u8]) -> Result<[u8; TAG], AesError> {
    let (h, j0) = setup(aes, nonce, data.len())?;
    ctr::apply(aes, &inc32(&j0), data);
    Ok(tag(aes, &h, &j0, aad, data))
}

/// Check `tag` and decrypt `data` in place. On a mismatch `data` is
/// zeroized and [`AesError::TagMismatch`] returned.
pub fn open(aes: &Aes, nonce: &[u8], aad: &[u8], data: &mut [u8], tag: &[u8; TAG]) -> Result<(), AesError> {
    let (h, j0) = setup(aes, nonce, data.len())?;
    let expected = self::tag(aes, &h, &j0, aad, data);
    if !bool::from(expected.ct_eq(tag)) {
        data.iter_mut().for_each(|b| *b = 0);
        return Err(AesError::TagMismatch);
    }
    ctr::apply(aes, &inc32(&j0), data);
    Ok(())
}

/// [`seal`] into a new vector: the ciphertext followed by the tag.
pub fn encrypt(aes: &Aes, nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, AesError> {
    let mut out = Vec::with_capacity(plaintext.len() + TAG);
    out.extend_from_slice(plaintext);
    let tag = seal(aes, nonce, aad, &mut out)?;
    out.extend_from_slice(&tag);
    Ok(out)
}

/// [`open`] from a ciphertext-then-tag vector, returning the plaintext.
pub fn decrypt(aes: &Aes, nonce: &[u8], aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, AesError> {
    if sealed.len() < TAG {
        return Err(AesError::TagMismatch);
    }
    let (body, tag) = sealed.split_at(sealed.len() - TAG);
    let tag: &[u8; TAG] = tag.try_into().expect("split at TAG bytes");
    let mut out = body.to_vec();
    open(aes, nonce, aad, &mut out, tag)?;
    Ok(out)
}

/// The hash subkey and the pre-counter block J0 (SP 800-38D §7.1 steps 1–2).
fn setup(aes: &Aes, nonce: &[u8], data_len: usize) -> Result<([u8; BLOCK], [u8; BLOCK]), AesError> {
    if nonce.is_empty() {
        return Err(AesError::InvalidNonceLength(0));
    }
    if data_len as u64 > MAX_MESSAGE {
        return Err(AesError::TooLong);
    }
    let mut h = [0u8; BLOCK];
    aes.encrypt_block(&mut h);

    let j0 = if nonce.len() == 12 {
        let mut j0 = [0u8; BLOCK];
        j0[..12].copy_from_slice(nonce);
        j0[15] = 1;
        j0
    } else {
        let mut g = Ghash::new(&h);
        g.update(nonce);
        // the length block for a nonce is 0^64 || len(nonce) in bits
        g.lengths(0, nonce.len());
        g.finish()
    };
    Ok((h, j0))
}

/// `GHASH(H, A, C)` XOR `E_K(J0)`.
fn tag(aes: &Aes, h: &[u8; BLOCK], j0: &[u8; BLOCK], aad: &[u8], ciphertext: &[u8]) -> [u8; TAG] {
    let mut g = Ghash::new(h);
    g.update(aad);
    g.update(ciphertext);
    g.lengths(aad.len(), ciphertext.len());
    let mut tag = g.finish();
    let mut mask = *j0;
    aes.encrypt_block(&mut mask);
    for (t, m) in tag.iter_mut().zip(mask.iter()) {
        *t ^= m;
    }
    tag
}

/// Increment the low 32 bits of a counter block, modulo 2^32 (SP 800-38D §6.2).
fn inc32(block: &[u8; BLOCK]) -> [u8; BLOCK] {
    let mut out = *block;
    let low = u32::from_be_bytes([out[12], out[13], out[14], out[15]]).wrapping_add(1);
    out[12..].copy_from_slice(&low.to_be_bytes());
    out
}

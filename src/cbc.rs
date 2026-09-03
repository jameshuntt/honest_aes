//! Cipher block chaining (SP 800-38A §6.2), with and without PKCS#7 padding.
//!
//! CBC gives confidentiality and nothing else: a modified ciphertext
//! decrypts to garbage without any error, and the padding check on
//! decryption is exactly the signal a padding-oracle attack needs if an
//! attacker can submit ciphertexts and observe the outcome. Use [`gcm`](crate::gcm)
//! for anything on a wire; CBC is here for formats that require it.

use alloc::vec::Vec;

use subtle::ConstantTimeEq;

use crate::{Aes, AesError, BLOCK};

/// Encrypt whole blocks in place, no padding. Refused unless `data` is a
/// multiple of 16 bytes.
pub fn encrypt_blocks(aes: &Aes, iv: &[u8; BLOCK], data: &mut [u8]) -> Result<(), AesError> {
    if data.len() % BLOCK != 0 {
        return Err(AesError::NotBlockAligned(data.len()));
    }
    let mut previous = *iv;
    for chunk in data.chunks_exact_mut(BLOCK) {
        let block: &mut [u8; BLOCK] = chunk.try_into().expect("chunks_exact yields full blocks");
        for (b, p) in block.iter_mut().zip(previous.iter()) {
            *b ^= p;
        }
        aes.encrypt_block(block);
        previous = *block;
    }
    Ok(())
}

/// Decrypt whole blocks in place, no padding. Refused unless `data` is a
/// multiple of 16 bytes.
pub fn decrypt_blocks(aes: &Aes, iv: &[u8; BLOCK], data: &mut [u8]) -> Result<(), AesError> {
    if data.len() % BLOCK != 0 {
        return Err(AesError::NotBlockAligned(data.len()));
    }
    let mut previous = *iv;
    for chunk in data.chunks_exact_mut(BLOCK) {
        let block: &mut [u8; BLOCK] = chunk.try_into().expect("chunks_exact yields full blocks");
        let ciphertext = *block;
        aes.decrypt_block(block);
        for (b, p) in block.iter_mut().zip(previous.iter()) {
            *b ^= p;
        }
        previous = ciphertext;
    }
    Ok(())
}

/// Pad `plaintext` with PKCS#7 and encrypt. The output is always a whole
/// number of blocks and at least one block longer than... no: at least one
/// byte of padding is always added, so the output is `plaintext.len()`
/// rounded up to the next multiple of 16.
///
/// ```
/// use honest_aes::{cbc, Aes};
///
/// let aes = Aes::aes256(&[9; 32]);
/// let iv = [3u8; 16];
/// let ct = cbc::encrypt(&aes, &iv, b"seventeen bytes!!");
/// assert_eq!(ct.len(), 32);
/// assert_eq!(cbc::decrypt(&aes, &iv, &ct).unwrap(), b"seventeen bytes!!");
/// ```
pub fn encrypt(aes: &Aes, iv: &[u8; BLOCK], plaintext: &[u8]) -> Vec<u8> {
    let pad = BLOCK - plaintext.len() % BLOCK;
    let mut data = Vec::with_capacity(plaintext.len() + pad);
    data.extend_from_slice(plaintext);
    data.resize(plaintext.len() + pad, pad as u8);
    encrypt_blocks(aes, iv, &mut data).expect("padded to a whole number of blocks");
    data
}

/// Decrypt and strip PKCS#7 padding. The padding is checked in constant
/// time over the last block, but see the module note: the error itself is
/// an oracle if an attacker can observe it.
pub fn decrypt(aes: &Aes, iv: &[u8; BLOCK], ciphertext: &[u8]) -> Result<Vec<u8>, AesError> {
    if ciphertext.is_empty() || ciphertext.len() % BLOCK != 0 {
        return Err(AesError::NotBlockAligned(ciphertext.len()));
    }
    let mut data = ciphertext.to_vec();
    decrypt_blocks(aes, iv, &mut data)?;
    let len = data.len();
    let pad = data[len - 1];
    // valid iff 1 <= pad <= 16 and the last `pad` bytes all equal `pad`;
    // every byte of the last block is inspected regardless of `pad`
    let in_range = (pad >= 1) as u8 & (pad as usize <= BLOCK) as u8;
    let mut all_match = 1u8;
    for (i, &b) in data[len - BLOCK..].iter().enumerate() {
        // position i (0..16) is part of the padding iff i >= 16 - pad
        let is_padding = ((i as isize) >= BLOCK as isize - pad as isize) as u8;
        let matches = b.ct_eq(&pad).unwrap_u8();
        all_match &= !is_padding | matches;
    }
    if in_range & all_match != 1 {
        data.iter_mut().for_each(|b| *b = 0);
        return Err(AesError::InvalidPadding);
    }
    data.truncate(len - pad as usize);
    Ok(data)
}

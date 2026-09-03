use core::fmt;

use zeroize::Zeroize;

use crate::key_schedule::{expand, MAX_ROUND_KEYS};
use crate::round::{add_round_key, inv_mix_columns, inv_shift_rows, mix_columns, shift_rows};
use crate::sbox::{inv_sub_bytes, sub_bytes};
use crate::AesError;

/// The block size in bytes.
pub const BLOCK: usize = 16;

/// An expanded AES key: the round keys for one of the three key sizes.
///
/// Building it runs the key schedule once; encrypting and decrypting
/// blocks then reuse the round keys. The round keys are zeroized on drop
/// and `Debug` shows only the key size.
///
/// ```
/// use honest_aes::Aes;
///
/// let aes = Aes::aes128(&[0; 16]);
/// let mut block = [0u8; 16];
/// aes.encrypt_block(&mut block);
/// assert_eq!(block[..4], [0x66, 0xe9, 0x4b, 0xd4]);
/// aes.decrypt_block(&mut block);
/// assert_eq!(block, [0; 16]);
/// ```
pub struct Aes {
    round_keys: [[u8; BLOCK]; MAX_ROUND_KEYS],
    rounds: usize,
}

impl Aes {
    /// Expand a key of 16, 24 or 32 bytes.
    pub fn new(key: &[u8]) -> Result<Self, AesError> {
        if !matches!(key.len(), 16 | 24 | 32) {
            return Err(AesError::InvalidKeyLength(key.len()));
        }
        let mut round_keys = [[0u8; BLOCK]; MAX_ROUND_KEYS];
        let rounds = expand(key, &mut round_keys);
        Ok(Self { round_keys, rounds })
    }

    /// AES-128.
    pub fn aes128(key: &[u8; 16]) -> Self {
        Self::new(key).expect("16 bytes is a valid key length")
    }

    /// AES-192.
    pub fn aes192(key: &[u8; 24]) -> Self {
        Self::new(key).expect("24 bytes is a valid key length")
    }

    /// AES-256.
    pub fn aes256(key: &[u8; 32]) -> Self {
        Self::new(key).expect("32 bytes is a valid key length")
    }

    /// The key size in bits: 128, 192 or 256.
    pub fn key_bits(&self) -> usize {
        (self.rounds - 6) * 32
    }

    /// The number of rounds: 10, 12 or 14.
    pub fn rounds(&self) -> usize {
        self.rounds
    }

    /// Encrypt one block in place (FIPS 197 §5.1).
    pub fn encrypt_block(&self, block: &mut [u8; BLOCK]) {
        add_round_key(block, &self.round_keys[0]);
        for round in 1..self.rounds {
            sub_bytes(block);
            shift_rows(block);
            mix_columns(block);
            add_round_key(block, &self.round_keys[round]);
        }
        sub_bytes(block);
        shift_rows(block);
        add_round_key(block, &self.round_keys[self.rounds]);
    }

    /// Decrypt one block in place (FIPS 197 §5.3, the straightforward inverse).
    pub fn decrypt_block(&self, block: &mut [u8; BLOCK]) {
        add_round_key(block, &self.round_keys[self.rounds]);
        for round in (1..self.rounds).rev() {
            inv_shift_rows(block);
            inv_sub_bytes(block);
            add_round_key(block, &self.round_keys[round]);
            inv_mix_columns(block);
        }
        inv_shift_rows(block);
        inv_sub_bytes(block);
        add_round_key(block, &self.round_keys[0]);
    }
}

impl fmt::Debug for Aes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Aes-{}([REDACTED])", self.key_bits())
    }
}

impl Drop for Aes {
    fn drop(&mut self) {
        self.round_keys.zeroize();
        self.rounds = 0;
    }
}

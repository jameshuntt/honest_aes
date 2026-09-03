//! GHASH (SP 800-38D §6.4): a polynomial hash in GF(2^128) with GCM's
//! bit ordering, multiplied bit by bit with masks so no bit of the hash
//! key or the data selects a branch or an address.

use crate::BLOCK;

/// The reduction polynomial `x^128 + x^7 + x^2 + x + 1` in GCM's reflected
/// representation: the low-order coefficients sit in the top byte.
const R: u128 = 0xE1 << 120;

/// The running hash.
pub struct Ghash {
    h: u128,
    y: u128,
}

impl Ghash {
    /// Start a hash under the hash subkey `h` (the cipher of the zero block).
    pub fn new(h: &[u8; BLOCK]) -> Self {
        Self { h: u128::from_be_bytes(*h), y: 0 }
    }

    /// Absorb whole blocks; a final partial block is zero-padded.
    pub fn update(&mut self, data: &[u8]) {
        for chunk in data.chunks(BLOCK) {
            let mut block = [0u8; BLOCK];
            block[..chunk.len()].copy_from_slice(chunk);
            self.y = mul(self.y ^ u128::from_be_bytes(block), self.h);
        }
    }

    /// Absorb the bit lengths of the associated data and the ciphertext.
    pub fn lengths(&mut self, aad_bytes: usize, ct_bytes: usize) {
        let block = ((aad_bytes as u128 * 8) << 64) | (ct_bytes as u128 * 8);
        self.y = mul(self.y ^ block, self.h);
    }

    /// The hash so far.
    pub fn finish(&self) -> [u8; BLOCK] {
        self.y.to_be_bytes()
    }
}

/// `x · y` in GF(2^128), SP 800-38D Algorithm 1, with the conditional
/// steps turned into masks.
fn mul(x: u128, y: u128) -> u128 {
    let mut z = 0u128;
    let mut v = y;
    for i in 0..128 {
        // bit i of x, counting from the most significant (GCM's bit 0)
        let bit = (x >> (127 - i)) & 1;
        z ^= v & 0u128.wrapping_sub(bit);
        let lsb = v & 1;
        v = (v >> 1) ^ (R & 0u128.wrapping_sub(lsb));
    }
    z
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_is_the_identity_and_multiplication_commutes() {
        // GCM's "1" is the block 80 00 .. 00
        let one = 1u128 << 127;
        let a = 0x66e9_4bd4_ef8a_2c3b_884c_fa59_ca34_2b2e_u128;
        let b = 0x0388_dace_60b6_a392_f328_c2b9_71b2_fe78_u128;
        assert_eq!(mul(a, one), a);
        assert_eq!(mul(one, b), b);
        assert_eq!(mul(a, b), mul(b, a));
        assert_eq!(mul(a, 0), 0);
    }

    #[test]
    fn the_spec_test_case_2_hash() {
        // SP 800-38D / the GCM spec test case 2: H = E_K(0) for K = 0,
        // C = 0388dace60b6a392f328c2b971b2fe78, no AAD:
        // GHASH(H, {}, C) = f38cbb1ad69223dcc3457ae5b6b0f885
        let h = [0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b, 0x2e];
        let c = [0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92, 0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78];
        let mut g = Ghash::new(&h);
        g.update(&c);
        g.lengths(0, 16);
        assert_eq!(g.finish(), [0xf3, 0x8c, 0xbb, 0x1a, 0xd6, 0x92, 0x23, 0xdc, 0xc3, 0x45, 0x7a, 0xe5, 0xb6, 0xb0, 0xf8, 0x85]);
    }
}

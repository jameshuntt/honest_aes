//! Key expansion (FIPS 197 §5.2) for 4, 6 and 8-word keys, with the round
//! constants produced by doubling in the field rather than read from a table.

use honest::Gf256;

use crate::sbox::sub_byte;

/// The most round keys any key size needs: 15 for AES-256.
pub const MAX_ROUND_KEYS: usize = 15;

/// Expand `key` (16, 24 or 32 bytes) into `rounds + 1` round keys. Returns
/// the number of rounds; unused slots are left zero.
pub fn expand(key: &[u8], out: &mut [[u8; 16]; MAX_ROUND_KEYS]) -> usize {
    let nk = key.len() / 4; // words in the key: 4, 6 or 8
    let rounds = nk + 6;
    let total_words = 4 * (rounds + 1);

    // the schedule as words, filled left to right
    let mut w = [[0u8; 4]; 4 * MAX_ROUND_KEYS];
    for (i, word) in w.iter_mut().take(nk).enumerate() {
        word.copy_from_slice(&key[4 * i..4 * i + 4]);
    }

    let mut rcon = Gf256::ONE;
    for i in nk..total_words {
        let mut temp = w[i - 1];
        if i % nk == 0 {
            temp.rotate_left(1);
            for b in temp.iter_mut() {
                *b = sub_byte(*b);
            }
            temp[0] ^= rcon.0;
            rcon = rcon.mul(Gf256(2));
        } else if nk > 6 && i % nk == 4 {
            for b in temp.iter_mut() {
                *b = sub_byte(*b);
            }
        }
        for (k, b) in temp.iter().enumerate() {
            w[i][k] = w[i - nk][k] ^ b;
        }
    }

    for (r, round_key) in out.iter_mut().enumerate().take(rounds + 1) {
        for c in 0..4 {
            round_key[4 * c..4 * c + 4].copy_from_slice(&w[4 * r + c]);
        }
    }
    rounds
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_round_constants_are_the_fips_197_ones() {
        let mut rcon = Gf256::ONE;
        let mut seen = [0u8; 10];
        for slot in seen.iter_mut() {
            *slot = rcon.0;
            rcon = rcon.mul(Gf256(2));
        }
        assert_eq!(seen, [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]);
    }

    #[test]
    fn aes_128_expansion_matches_fips_197_appendix_a1() {
        let key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
        let mut rk = [[0u8; 16]; MAX_ROUND_KEYS];
        assert_eq!(expand(&key, &mut rk), 10);
        assert_eq!(rk[0], key);
        // w[4..8] from the worked example
        assert_eq!(&rk[1][..4], &[0xa0, 0xfa, 0xfe, 0x17]);
        // the last round key, w[40..44]
        assert_eq!(rk[10], [0xd0, 0x14, 0xf9, 0xa8, 0xc9, 0xee, 0x25, 0x89, 0xe1, 0x3f, 0x0c, 0xc8, 0xb6, 0x63, 0x0c, 0xa6]);
    }

    #[test]
    fn aes_256_expansion_matches_fips_197_appendix_a3() {
        let key: [u8; 32] = [
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c,
            0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
        ];
        let mut rk = [[0u8; 16]; MAX_ROUND_KEYS];
        assert_eq!(expand(&key, &mut rk), 14);
        // w[8] = 9ba35411
        assert_eq!(&rk[2][..4], &[0x9b, 0xa3, 0x54, 0x11]);
        // w[59] = 706c631e, the last word of the schedule
        assert_eq!(&rk[14][12..], &[0x70, 0x6c, 0x63, 0x1e]);
    }
}

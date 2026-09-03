//! The round transformations on a 16-byte state in column-major order:
//! byte `4·c + r` is row `r` of column `c`, as in FIPS 197 §3.4.

use honest::Gf256;

/// Rotate row `r` left by `r` positions (FIPS 197 §5.1.2).
pub fn shift_rows(s: &mut [u8; 16]) {
    let t = *s;
    // row 1
    s[1] = t[5];
    s[5] = t[9];
    s[9] = t[13];
    s[13] = t[1];
    // row 2
    s[2] = t[10];
    s[6] = t[14];
    s[10] = t[2];
    s[14] = t[6];
    // row 3
    s[3] = t[15];
    s[7] = t[3];
    s[11] = t[7];
    s[15] = t[11];
}

/// Rotate row `r` right by `r` positions (FIPS 197 §5.3.1).
pub fn inv_shift_rows(s: &mut [u8; 16]) {
    let t = *s;
    s[1] = t[13];
    s[5] = t[1];
    s[9] = t[5];
    s[13] = t[9];
    s[2] = t[10];
    s[6] = t[14];
    s[10] = t[2];
    s[14] = t[6];
    s[3] = t[7];
    s[7] = t[11];
    s[11] = t[15];
    s[15] = t[3];
}

/// Multiply each column by the fixed polynomial `{03}x³ + {01}x² + {01}x + {02}`
/// (FIPS 197 §5.1.3), as four field multiplications per byte.
pub fn mix_columns(s: &mut [u8; 16]) {
    for c in 0..4 {
        let col = [Gf256(s[4 * c]), Gf256(s[4 * c + 1]), Gf256(s[4 * c + 2]), Gf256(s[4 * c + 3])];
        let out = mix_column(col, [Gf256(2), Gf256(3), Gf256(1), Gf256(1)]);
        write_column(s, c, out);
    }
}

/// Multiply each column by the inverse polynomial `{0b}x³ + {0d}x² + {09}x + {0e}`
/// (FIPS 197 §5.3.3).
pub fn inv_mix_columns(s: &mut [u8; 16]) {
    for c in 0..4 {
        let col = [Gf256(s[4 * c]), Gf256(s[4 * c + 1]), Gf256(s[4 * c + 2]), Gf256(s[4 * c + 3])];
        let out = mix_column(col, [Gf256(0x0e), Gf256(0x0b), Gf256(0x0d), Gf256(0x09)]);
        write_column(s, c, out);
    }
}

/// One column times the circulant matrix whose first row is `m`.
fn mix_column(col: [Gf256; 4], m: [Gf256; 4]) -> [Gf256; 4] {
    let mut out = [Gf256::ZERO; 4];
    for (r, slot) in out.iter_mut().enumerate() {
        let mut acc = Gf256::ZERO;
        for (k, &x) in col.iter().enumerate() {
            // row r of the circulant matrix is m rotated right by r
            acc = acc.add(m[(k + 4 - r) % 4].mul(x));
        }
        *slot = acc;
    }
    out
}

fn write_column(s: &mut [u8; 16], c: usize, col: [Gf256; 4]) {
    for (r, v) in col.iter().enumerate() {
        s[4 * c + r] = v.0;
    }
}

/// XOR the round key into the state (FIPS 197 §5.1.4).
pub fn add_round_key(s: &mut [u8; 16], k: &[u8; 16]) {
    for (b, k) in s.iter_mut().zip(k) {
        *b ^= k;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mix_columns_matches_the_fips_197_example() {
        // FIPS 197 §5.1.3 gives the column [db 13 53 45] -> [8e 4d a1 bc]
        let mut s = [0u8; 16];
        s[..4].copy_from_slice(&[0xdb, 0x13, 0x53, 0x45]);
        mix_columns(&mut s);
        assert_eq!(&s[..4], &[0x8e, 0x4d, 0xa1, 0xbc]);
        inv_mix_columns(&mut s);
        assert_eq!(&s[..4], &[0xdb, 0x13, 0x53, 0x45]);
    }

    #[test]
    fn shift_rows_round_trips_and_moves_the_right_bytes() {
        let mut s: [u8; 16] = core::array::from_fn(|i| i as u8);
        shift_rows(&mut s);
        // column 0 after ShiftRows holds bytes 0, 5, 10, 15 of the original
        assert_eq!(&s[..4], &[0, 5, 10, 15]);
        inv_shift_rows(&mut s);
        assert_eq!(s, core::array::from_fn(|i| i as u8));
    }
}

//! The S-box, computed rather than stored.
//!
//! FIPS 197 §5.1.1 defines SubBytes as the multiplicative inverse in
//! GF(2^8) (with 0 mapping to 0) followed by an affine transformation over
//! GF(2). `honest` gives the inverse without branching, and the affine map
//! is four rotations and a constant, so no byte ever indexes memory.

use honest::Gf256;

/// `SubBytes` for one byte.
pub const fn sub_byte(x: u8) -> u8 {
    let b = Gf256(x).inv_or_zero().0;
    b ^ b.rotate_left(1) ^ b.rotate_left(2) ^ b.rotate_left(3) ^ b.rotate_left(4) ^ 0x63
}

/// `InvSubBytes` for one byte: the inverse affine map, then the field inverse.
pub const fn inv_sub_byte(x: u8) -> u8 {
    let b = x.rotate_left(1) ^ x.rotate_left(3) ^ x.rotate_left(6) ^ 0x05;
    Gf256(b).inv_or_zero().0
}

/// `SubBytes` over a whole state.
pub fn sub_bytes(state: &mut [u8; 16]) {
    for byte in state.iter_mut() {
        *byte = sub_byte(*byte);
    }
}

/// `InvSubBytes` over a whole state.
pub fn inv_sub_bytes(state: &mut [u8; 16]) {
    for byte in state.iter_mut() {
        *byte = inv_sub_byte(*byte);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fips_197_figure_7_corners() {
        // the four corners of the S-box table in FIPS 197 Figure 7
        assert_eq!(sub_byte(0x00), 0x63);
        assert_eq!(sub_byte(0x0f), 0x76);
        assert_eq!(sub_byte(0xf0), 0x8c);
        assert_eq!(sub_byte(0xff), 0x16);
        // and the worked example in §5.1.1
        assert_eq!(sub_byte(0x53), 0xed);
    }

    #[test]
    fn every_byte_round_trips() {
        for x in 0..=255u8 {
            assert_eq!(inv_sub_byte(sub_byte(x)), x, "{x:#04x}");
        }
    }

    #[test]
    fn the_sbox_is_a_permutation_with_no_fixed_points() {
        let mut seen = [false; 256];
        for x in 0..=255u8 {
            let y = sub_byte(x);
            assert_ne!(x, y, "AES has no fixed points");
            assert!(!seen[y as usize], "duplicate output {y:#04x}");
            seen[y as usize] = true;
        }
    }
}

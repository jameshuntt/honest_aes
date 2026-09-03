use core::fmt;

/// Why an operation was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AesError {
    /// A key must be 16, 24 or 32 bytes.
    InvalidKeyLength(usize),
    /// A GCM nonce must have at least one byte.
    InvalidNonceLength(usize),
    /// CBC without padding and CTR-less block work need whole blocks.
    NotBlockAligned(usize),
    /// PKCS#7 padding did not check out. In CBC that means the ciphertext,
    /// the IV or the key is wrong; without a MAC the mode cannot say which.
    InvalidPadding,
    /// The GCM tag did not match; the data was not returned.
    TagMismatch,
    /// More data than GCM's counter can cover (2^36 − 32 bytes) or than
    /// its length field can describe.
    TooLong,
}

impl fmt::Display for AesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKeyLength(n) => write!(f, "AES keys are 16, 24 or 32 bytes, not {n}"),
            Self::InvalidNonceLength(n) => write!(f, "GCM nonce must have at least one byte, not {n}"),
            Self::NotBlockAligned(n) => write!(f, "{n} bytes is not a multiple of the 16-byte block"),
            Self::InvalidPadding => write!(f, "PKCS#7 padding is invalid"),
            Self::TagMismatch => write!(f, "GCM tag mismatch"),
            Self::TooLong => write!(f, "message too long for GCM"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for AesError {}

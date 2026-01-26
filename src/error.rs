//! error types.

use core::fmt;

/// signature verification or key parsing error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// signature verification failed.
    ///
    /// intentionally does not reveal which component (ed25519 or falcon) failed.
    VerificationFailed,
    /// invalid ed25519 key bytes.
    InvalidEd25519Key,
    /// invalid falcon key bytes.
    InvalidFalconKey,
    /// invalid signature bytes.
    InvalidSignature,
    /// invalid key length.
    InvalidLength,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::VerificationFailed => write!(f, "signature verification failed"),
            Error::InvalidEd25519Key => write!(f, "invalid ed25519 key"),
            Error::InvalidFalconKey => write!(f, "invalid falcon key"),
            Error::InvalidSignature => write!(f, "invalid signature"),
            Error::InvalidLength => write!(f, "invalid length"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

//! signature implementation.

use crate::error::Error;
use crate::{ED25519_SIGNATURE_SIZE, FALCON_SIGNATURE_SIZE, SIGNATURE_SIZE};

use ed25519_dalek::Signature as Ed25519Signature;
use subtle::ConstantTimeEq;

/// hybrid signature: ed25519 + falcon-512.
///
/// contains both signatures over the same message.
/// both must verify for the combined signature to be valid.
#[derive(Clone)]
pub struct Signature {
    ed25519: Ed25519Signature,
    falcon: [u8; FALCON_SIGNATURE_SIZE],
}

impl Signature {
    /// construct a signature from its component parts.
    pub(crate) fn from_parts(
        ed25519: Ed25519Signature,
        falcon: [u8; FALCON_SIGNATURE_SIZE],
    ) -> Self {
        Self { ed25519, falcon }
    }

    /// serialize the signature to bytes.
    ///
    /// format: `ed25519_sig (64) || falcon_sig`
    pub fn to_bytes(&self) -> [u8; SIGNATURE_SIZE] {
        let mut out = [0u8; SIGNATURE_SIZE];

        out[..ED25519_SIGNATURE_SIZE].copy_from_slice(&self.ed25519.to_bytes());
        out[ED25519_SIGNATURE_SIZE..].copy_from_slice(&self.falcon);

        out
    }

    /// deserialize a signature from bytes.
    pub fn from_bytes(bytes: &[u8; SIGNATURE_SIZE]) -> Result<Self, Error> {
        let ed_bytes: [u8; ED25519_SIGNATURE_SIZE] = bytes[..ED25519_SIGNATURE_SIZE]
            .try_into()
            .map_err(|_| Error::InvalidLength)?;

        let ed25519 = Ed25519Signature::from_bytes(&ed_bytes);

        let mut falcon = [0u8; FALCON_SIGNATURE_SIZE];
        falcon.copy_from_slice(&bytes[ED25519_SIGNATURE_SIZE..]);

        Ok(Self { ed25519, falcon })
    }

    /// access the inner ed25519 signature.
    pub fn ed25519(&self) -> &Ed25519Signature {
        &self.ed25519
    }

    /// access the inner falcon signature bytes.
    pub fn falcon(&self) -> &[u8; FALCON_SIGNATURE_SIZE] {
        &self.falcon
    }
}

impl core::fmt::Debug for Signature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Signature")
            .field("ed25519", &hex_preview(&self.ed25519.to_bytes()))
            .field("falcon", &hex_preview(&self.falcon[..32]))
            .finish()
    }
}

impl TryFrom<&[u8]> for Signature {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != SIGNATURE_SIZE {
            return Err(Error::InvalidLength);
        }
        let arr: &[u8; SIGNATURE_SIZE] = bytes.try_into().map_err(|_| Error::InvalidLength)?;
        Self::from_bytes(arr)
    }
}

impl PartialEq for Signature {
    fn eq(&self, other: &Self) -> bool {
        self.to_bytes().ct_eq(&other.to_bytes()).into()
    }
}

impl Eq for Signature {}

/// hex preview for debug output
fn hex_preview(bytes: &[u8]) -> alloc::string::String {
    use alloc::format;
    if bytes.len() <= 8 {
        hex_encode(bytes)
    } else {
        format!(
            "{}..{}",
            hex_encode(&bytes[..4]),
            hex_encode(&bytes[bytes.len() - 4..])
        )
    }
}

fn hex_encode(bytes: &[u8]) -> alloc::string::String {
    use alloc::string::String;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use core::fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    s
}

#[cfg(feature = "serde")]
impl serde::Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.to_bytes())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct SignatureVisitor;

        impl<'de> serde::de::Visitor<'de> for SignatureVisitor {
            type Value = Signature;

            fn expecting(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                write!(f, "{} bytes", SIGNATURE_SIZE)
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Signature::try_from(v).map_err(E::custom)
            }
        }

        deserializer.deserialize_bytes(SignatureVisitor)
    }
}

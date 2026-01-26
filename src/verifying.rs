//! verifying key implementation.

use crate::error::Error;
use crate::signature::Signature;
use crate::{ED25519_PUBLIC_KEY_SIZE, FALCON_PUBLIC_KEY_SIZE, VERIFYING_KEY_SIZE};

use ed25519_dalek::VerifyingKey as Ed25519VerifyingKey;
use fn_dsa::{VerifyingKey as FnDsaVerifyingKey, VerifyingKey512, DOMAIN_NONE, HASH_ID_RAW};
use subtle::ConstantTimeEq;

/// hybrid verifying key: ed25519 + falcon-512.
///
/// use this to verify signatures created by the corresponding [`crate::SigningKey`].
#[derive(Clone)]
pub struct VerifyingKey {
    ed25519: Ed25519VerifyingKey,
    falcon_pk: [u8; FALCON_PUBLIC_KEY_SIZE],
}

impl core::fmt::Debug for VerifyingKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VerifyingKey")
            .field("ed25519", &self.ed25519)
            .field("falcon_pk", &"[..]")
            .finish()
    }
}

impl VerifyingKey {
    /// construct a verifying key from its component parts.
    pub(crate) fn from_parts(
        ed25519: Ed25519VerifyingKey,
        falcon_pk: [u8; FALCON_PUBLIC_KEY_SIZE],
    ) -> Self {
        Self { ed25519, falcon_pk }
    }

    /// verify a signature over a message.
    ///
    /// checks ed25519 first. if it fails, returns early without checking falcon.
    /// this is faster and leaks nothing—verification is a public operation.
    ///
    /// if you want constant-time verification (both always checked), use
    /// [`verify_strict`](Self::verify_strict).
    pub fn verify(&self, msg: &[u8], sig: &Signature) -> Result<(), Error> {
        use ed25519_dalek::Verifier;

        // ed25519 first - fast path
        self.ed25519
            .verify(msg, sig.ed25519())
            .map_err(|_| Error::Ed25519Verification)?;

        // then falcon
        let falcon_vk: VerifyingKey512 = FnDsaVerifyingKey::decode(&self.falcon_pk)
            .ok_or(Error::InvalidFalconKey)?;

        if !falcon_vk.verify(sig.falcon(), &DOMAIN_NONE, &HASH_ID_RAW, msg) {
            return Err(Error::FalconVerification);
        }

        Ok(())
    }

    /// verify a signature in constant time.
    ///
    /// both ed25519 and falcon signatures are always verified, regardless of
    /// whether either fails. use this if you need to avoid timing side channels
    /// on verification failure (unusual but sometimes wanted).
    pub fn verify_strict(&self, msg: &[u8], sig: &Signature) -> Result<(), Error> {
        use ed25519_dalek::Verifier;

        let ed_result = self.ed25519.verify(msg, sig.ed25519());

        let falcon_result = FnDsaVerifyingKey::decode(&self.falcon_pk)
            .map(|vk: VerifyingKey512| vk.verify(sig.falcon(), &DOMAIN_NONE, &HASH_ID_RAW, msg))
            .unwrap_or(false);

        // check both, return first error
        match (ed_result, falcon_result) {
            (Err(_), _) => Err(Error::Ed25519Verification),
            (_, false) => Err(Error::FalconVerification),
            (Ok(()), true) => Ok(()),
        }
    }

    /// serialize the verifying key to bytes.
    ///
    /// format: `ed25519_pk (32) || falcon_pk`
    pub fn to_bytes(&self) -> [u8; VERIFYING_KEY_SIZE] {
        let mut out = [0u8; VERIFYING_KEY_SIZE];

        out[..ED25519_PUBLIC_KEY_SIZE].copy_from_slice(self.ed25519.as_bytes());
        out[ED25519_PUBLIC_KEY_SIZE..].copy_from_slice(&self.falcon_pk);

        out
    }

    /// deserialize a verifying key from bytes.
    pub fn from_bytes(bytes: &[u8; VERIFYING_KEY_SIZE]) -> Result<Self, Error> {
        let ed_bytes: [u8; ED25519_PUBLIC_KEY_SIZE] = bytes[..ED25519_PUBLIC_KEY_SIZE]
            .try_into()
            .map_err(|_| Error::InvalidLength)?;

        let ed25519 =
            Ed25519VerifyingKey::from_bytes(&ed_bytes).map_err(|_| Error::InvalidEd25519Key)?;

        let mut falcon_pk = [0u8; FALCON_PUBLIC_KEY_SIZE];
        falcon_pk.copy_from_slice(&bytes[ED25519_PUBLIC_KEY_SIZE..]);

        // validate falcon public key by attempting to decode it
        let _: VerifyingKey512 = FnDsaVerifyingKey::decode(&falcon_pk)
            .ok_or(Error::InvalidFalconKey)?;

        Ok(Self { ed25519, falcon_pk })
    }

    /// access the inner ed25519 verifying key.
    ///
    /// # hazmat
    ///
    /// this exposes the raw ed25519 key. you probably don't need this.
    pub fn ed25519(&self) -> &Ed25519VerifyingKey {
        &self.ed25519
    }

    /// access the inner falcon public key bytes.
    ///
    /// # hazmat
    ///
    /// this exposes the raw falcon key bytes. you probably don't need this.
    pub fn falcon_public_key(&self) -> &[u8; FALCON_PUBLIC_KEY_SIZE] {
        &self.falcon_pk
    }
}

impl TryFrom<&[u8]> for VerifyingKey {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != VERIFYING_KEY_SIZE {
            return Err(Error::InvalidLength);
        }
        let arr: &[u8; VERIFYING_KEY_SIZE] = bytes.try_into().map_err(|_| Error::InvalidLength)?;
        Self::from_bytes(arr)
    }
}

impl PartialEq for VerifyingKey {
    fn eq(&self, other: &Self) -> bool {
        self.to_bytes().ct_eq(&other.to_bytes()).into()
    }
}

impl Eq for VerifyingKey {}

#[cfg(feature = "serde")]
impl serde::Serialize for VerifyingKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.to_bytes())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for VerifyingKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct VerifyingKeyVisitor;

        impl<'de> serde::de::Visitor<'de> for VerifyingKeyVisitor {
            type Value = VerifyingKey;

            fn expecting(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                write!(f, "{} bytes", VERIFYING_KEY_SIZE)
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                VerifyingKey::try_from(v).map_err(E::custom)
            }
        }

        deserializer.deserialize_bytes(VerifyingKeyVisitor)
    }
}

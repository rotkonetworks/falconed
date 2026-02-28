//! substrate integration.
//!
//! provides wrapper types implementing [`sp_core::crypto::Pair`] for use in
//! substrate runtimes and tooling. enable with `features = ["substrate"]`.

use alloc::vec::Vec;
use codec::{Decode, Encode, Input, MaxEncodedLen, Output};
use sp_core::crypto::{
    ByteArray, CryptoType, CryptoTypeId, Derive, DeriveError, DeriveJunction,
    Pair as TraitPair, Public as TraitPublic, SecretStringError,
    Signature as TraitSignature,
};

use crate::{SEED_SIZE, SIGNATURE_SIZE, SIGNING_KEY_SIZE, VERIFYING_KEY_SIZE};

/// crypto type identifier: `*b"flcd"`.
pub const CRYPTO_ID: CryptoTypeId = CryptoTypeId(*b"flcd");

// ---------- Public ----------

/// 929-byte verifying key wrapper for substrate.
///
/// wraps the combined ed25519 + falcon-512 verifying key as a flat byte
/// array, implementing `AsRef<[u8]>` (which the core [`crate::VerifyingKey`]
/// cannot due to its non-contiguous internal layout).
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Public(pub [u8; VERIFYING_KEY_SIZE]);

impl Public {
    /// construct from a raw byte array.
    pub fn from_raw(data: [u8; VERIFYING_KEY_SIZE]) -> Self {
        Self(data)
    }
}

impl core::fmt::Debug for Public {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Public({:02x}{:02x}{:02x}{:02x}..)",
            self.0[0], self.0[1], self.0[2], self.0[3]
        )
    }
}

impl AsRef<[u8]> for Public {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for Public {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl TryFrom<&[u8]> for Public {
    type Error = ();

    fn try_from(data: &[u8]) -> Result<Self, ()> {
        if data.len() != VERIFYING_KEY_SIZE {
            return Err(());
        }
        let mut arr = [0u8; VERIFYING_KEY_SIZE];
        arr.copy_from_slice(data);
        Ok(Self(arr))
    }
}

impl Encode for Public {
    fn size_hint(&self) -> usize {
        VERIFYING_KEY_SIZE
    }

    fn encode_to<T: Output + ?Sized>(&self, dest: &mut T) {
        dest.write(&self.0);
    }
}

impl Decode for Public {
    fn decode<I: Input>(input: &mut I) -> Result<Self, codec::Error> {
        let mut arr = [0u8; VERIFYING_KEY_SIZE];
        input.read(&mut arr)?;
        Ok(Self(arr))
    }
}

impl MaxEncodedLen for Public {
    fn max_encoded_len() -> usize {
        VERIFYING_KEY_SIZE
    }
}

impl scale_info::TypeInfo for Public {
    type Identity = Self;

    fn type_info() -> scale_info::Type {
        scale_info::Type::builder()
            .path(scale_info::Path::new("Public", module_path!()))
            .composite(
                scale_info::build::Fields::unnamed()
                    .field(|f| f.ty::<[u8; VERIFYING_KEY_SIZE]>().type_name("[u8; 929]")),
            )
    }
}

impl ByteArray for Public {
    const LEN: usize = VERIFYING_KEY_SIZE;
}

impl Derive for Public {}

impl CryptoType for Public {
    type Pair = Pair;
}

impl TraitPublic for Public {}

// ---------- Signature ----------

/// 730-byte hybrid signature wrapper for substrate.
///
/// wraps the combined ed25519 + falcon-512 signature as a flat byte array.
#[derive(Clone, PartialEq, Eq)]
pub struct Signature(pub [u8; SIGNATURE_SIZE]);

impl Signature {
    /// construct from raw bytes.
    pub fn from_raw(data: [u8; SIGNATURE_SIZE]) -> Self {
        Self(data)
    }
}

impl core::fmt::Debug for Signature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Signature({:02x}{:02x}{:02x}{:02x}..)",
            self.0[0], self.0[1], self.0[2], self.0[3]
        )
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for Signature {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl TryFrom<&[u8]> for Signature {
    type Error = ();

    fn try_from(data: &[u8]) -> Result<Self, ()> {
        if data.len() != SIGNATURE_SIZE {
            return Err(());
        }
        let mut arr = [0u8; SIGNATURE_SIZE];
        arr.copy_from_slice(data);
        Ok(Self(arr))
    }
}

impl Encode for Signature {
    fn size_hint(&self) -> usize {
        SIGNATURE_SIZE
    }

    fn encode_to<T: Output + ?Sized>(&self, dest: &mut T) {
        dest.write(&self.0);
    }
}

impl Decode for Signature {
    fn decode<I: Input>(input: &mut I) -> Result<Self, codec::Error> {
        let mut arr = [0u8; SIGNATURE_SIZE];
        input.read(&mut arr)?;
        Ok(Self(arr))
    }
}

impl MaxEncodedLen for Signature {
    fn max_encoded_len() -> usize {
        SIGNATURE_SIZE
    }
}

impl scale_info::TypeInfo for Signature {
    type Identity = Self;

    fn type_info() -> scale_info::Type {
        scale_info::Type::builder()
            .path(scale_info::Path::new("Signature", module_path!()))
            .composite(
                scale_info::build::Fields::unnamed()
                    .field(|f| f.ty::<[u8; SIGNATURE_SIZE]>().type_name("[u8; 730]")),
            )
    }
}

impl ByteArray for Signature {
    const LEN: usize = SIGNATURE_SIZE;
}

impl CryptoType for Signature {
    type Pair = Pair;
}

impl TraitSignature for Signature {}

// ---------- Pair ----------

/// falconed keypair for substrate.
///
/// caches serialized key bytes to avoid repeated derivation. the seed
/// enables hierarchical key derivation (hard junctions only).
pub struct Pair {
    seed: [u8; SEED_SIZE],
    signing_key_bytes: [u8; SIGNING_KEY_SIZE],
    public_bytes: [u8; VERIFYING_KEY_SIZE],
}

impl Clone for Pair {
    fn clone(&self) -> Self {
        Self {
            seed: self.seed,
            signing_key_bytes: self.signing_key_bytes,
            public_bytes: self.public_bytes,
        }
    }
}

impl CryptoType for Pair {
    type Pair = Pair;
}

impl TraitPair for Pair {
    type Public = Public;
    type Seed = [u8; SEED_SIZE];
    type Signature = Signature;

    fn from_seed_slice(seed_slice: &[u8]) -> Result<Self, SecretStringError> {
        if seed_slice.len() != SEED_SIZE {
            return Err(SecretStringError::InvalidSeedLength);
        }
        let mut seed = [0u8; SEED_SIZE];
        seed.copy_from_slice(seed_slice);

        let signing_key = crate::SigningKey::from_seed(&seed);
        let verifying_key = signing_key
            .verifying_key()
            .map_err(|_| SecretStringError::InvalidSeed)?;

        Ok(Pair {
            seed,
            signing_key_bytes: signing_key.to_bytes(),
            public_bytes: verifying_key.to_bytes(),
        })
    }

    fn derive<Iter: Iterator<Item = DeriveJunction>>(
        &self,
        path: Iter,
        _seed: Option<[u8; SEED_SIZE]>,
    ) -> Result<(Self, Option<[u8; SEED_SIZE]>), DeriveError> {
        let mut acc = self.seed;
        for j in path {
            match j {
                DeriveJunction::Soft(_) => return Err(DeriveError::SoftKeyInPath),
                DeriveJunction::Hard(cc) => acc = derive_hard_junction(&acc, &cc),
            }
        }
        let pair = Self::from_seed_slice(&acc).expect("valid seed produces valid pair");
        Ok((pair, Some(acc)))
    }

    fn public(&self) -> Public {
        Public(self.public_bytes)
    }

    fn sign(&self, message: &[u8]) -> Signature {
        let sk = crate::SigningKey::from_bytes(&self.signing_key_bytes)
            .expect("stored signing key bytes are valid");
        let sig = sk.sign(message).expect("signing with valid key succeeds");
        Signature(sig.to_bytes())
    }

    fn verify<M: AsRef<[u8]>>(sig: &Signature, message: M, pubkey: &Public) -> bool {
        let Ok(vk) = crate::VerifyingKey::from_bytes(&pubkey.0) else {
            return false;
        };
        let Ok(s) = crate::Signature::from_bytes(&sig.0) else {
            return false;
        };
        vk.verify(message.as_ref(), &s).is_ok()
    }

    fn to_raw_vec(&self) -> Vec<u8> {
        self.seed.to_vec()
    }
}

fn derive_hard_junction(seed: &[u8; SEED_SIZE], cc: &[u8; 32]) -> [u8; SEED_SIZE] {
    use codec::Encode;
    ("falconedHDKD", seed, cc).using_encoded(sp_crypto_hashing::blake2_256)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use sp_core::crypto::Pair as PairT;

    #[test]
    fn generate_sign_verify() {
        let (pair, _seed) = Pair::generate();
        let msg = b"substrate test";
        let sig = pair.sign(msg);
        assert!(Pair::verify(&sig, msg, &pair.public()));
    }

    #[test]
    fn from_seed_deterministic() {
        let seed = [42u8; SEED_SIZE];
        let p1 = Pair::from_seed_slice(&seed).unwrap();
        let p2 = Pair::from_seed_slice(&seed).unwrap();
        assert_eq!(p1.public(), p2.public());
    }

    #[test]
    fn hard_derivation() {
        let (pair, _) = Pair::generate();
        let path = vec![DeriveJunction::hard("test")];
        let (derived, _) = pair.derive(path.into_iter(), None).unwrap();
        assert_ne!(pair.public(), derived.public());

        let sig = derived.sign(b"derived");
        assert!(Pair::verify(&sig, b"derived", &derived.public()));
    }

    #[test]
    fn soft_derivation_rejected() {
        let (pair, _) = Pair::generate();
        let path = vec![DeriveJunction::soft("nope")];
        assert!(pair.derive(path.into_iter(), None).is_err());
    }

    #[test]
    fn phrase_roundtrip() {
        let (pair1, phrase, seed) = Pair::generate_with_phrase(None);
        let (pair2, seed2) = Pair::from_phrase(&phrase, None).unwrap();
        assert_eq!(pair1.public(), pair2.public());
        assert_eq!(seed, seed2);
    }
}

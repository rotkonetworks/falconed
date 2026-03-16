//! unified key hierarchy: spending key → full viewing key → component keys.
//!
//! this module provides [`SpendingKey`] (root authority) and [`FullViewingKey`]
//! (verify + decrypt, but not sign). these compose the lower-level primitives
//! from [`crate::signing`], [`crate::verifying`], and [`crate::encryption`]
//! into a typed hierarchy where capabilities narrow as you go:
//!
//! ```text
//! SpendingKey (can sign + verify + decrypt)
//!   ├─ .signing_key()         → &SigningKey
//!   ├─ .full_viewing_key()    → FullViewingKey
//!   ├─ .viewing_key()         → &ViewingKey
//!   └─ .verifying_key()       → VerifyingKey
//!
//! FullViewingKey (can verify + decrypt, NOT sign)
//!   ├─ .verifying_key()         → &VerifyingKey
//!   ├─ .viewing_key()           → &ViewingKey
//!   └─ .encryption_public_key() → EncryptionPublicKey
//! ```

use crate::encryption::{EncryptionPublicKey, ViewingKey};
use crate::error::Error;
use crate::signature::Signature;
use crate::signing::SigningKey;
use crate::verifying::VerifyingKey;
use crate::SEED_SIZE;

/// combined full viewing key size: verifying key + viewing key.
pub const FULL_VIEWING_KEY_SIZE: usize =
    crate::VERIFYING_KEY_SIZE + crate::encryption::VIEWING_KEY_SIZE;

// --- SpendingKey ---

/// root spending authority: holds the master seed and can sign, verify, and decrypt.
///
/// this is the highest-privilege key type. it can derive all other keys.
/// store it securely — compromise of the spending key compromises everything.
///
/// ```
/// use falconed::SpendingKey;
/// use rand_core::OsRng;
///
/// let sk = SpendingKey::generate(&mut OsRng);
///
/// // sign
/// let sig = sk.sign(b"hello").unwrap();
///
/// // derive the full viewing key (can verify + decrypt, but NOT sign)
/// let fvk = sk.full_viewing_key().unwrap();
/// assert!(fvk.verify(b"hello", &sig).is_ok());
/// ```
pub struct SpendingKey {
    seed: [u8; SEED_SIZE],
    signing_key: SigningKey,
    viewing_key: ViewingKey,
}

impl SpendingKey {
    /// generate a new spending key from a csprng.
    pub fn generate<R>(csprng: &mut R) -> Self
    where
        R: rand_core::CryptoRng + rand_core::RngCore,
    {
        let mut seed = [0u8; SEED_SIZE];
        csprng.fill_bytes(&mut seed);
        Self::from_seed(&seed)
    }

    /// derive a spending key deterministically from a 32-byte master seed.
    pub fn from_seed(seed: &[u8; SEED_SIZE]) -> Self {
        let signing_key = SigningKey::from_seed(seed);
        let viewing_key = ViewingKey::from_seed(seed);
        let mut stored_seed = [0u8; SEED_SIZE];
        stored_seed.copy_from_slice(seed);
        Self {
            seed: stored_seed,
            signing_key,
            viewing_key,
        }
    }

    /// derive a spending key from a seed slice.
    pub fn from_seed_slice(seed: &[u8]) -> Result<Self, Error> {
        let seed: &[u8; SEED_SIZE] = seed.try_into().map_err(|_| Error::InvalidLength)?;
        Ok(Self::from_seed(seed))
    }

    /// access the stored master seed.
    ///
    /// useful for backup / export. handle with care — the seed can
    /// re-derive the entire key hierarchy.
    pub fn seed(&self) -> &[u8; SEED_SIZE] {
        &self.seed
    }

    /// borrow the inner signing key.
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    /// borrow the inner viewing key (decryption capability).
    pub fn viewing_key(&self) -> &ViewingKey {
        &self.viewing_key
    }

    /// derive the verifying key (public, for signature verification).
    pub fn verifying_key(&self) -> Result<VerifyingKey, Error> {
        self.signing_key.verifying_key()
    }

    /// derive the encryption public key (public, for encrypting to this identity).
    pub fn encryption_public_key(&self) -> EncryptionPublicKey {
        self.viewing_key.encryption_public_key()
    }

    /// construct a [`FullViewingKey`] — can verify and decrypt, but not sign.
    ///
    /// the full viewing key is safe to export to watch-only clients.
    pub fn full_viewing_key(&self) -> Result<FullViewingKey, Error> {
        let verifying_key = self.signing_key.verifying_key()?;
        // re-derive from seed (ViewingKey intentionally does not impl Clone)
        let viewing_key = ViewingKey::from_seed(&self.seed);
        Ok(FullViewingKey {
            verifying_key,
            viewing_key,
        })
    }

    /// sign a message. delegates to the inner [`SigningKey`].
    pub fn sign(&self, msg: &[u8]) -> Result<Signature, Error> {
        self.signing_key.sign(msg)
    }

    /// sign a message with explicit rng. delegates to the inner [`SigningKey`].
    pub fn sign_with_rng<R>(&self, rng: &mut R, msg: &[u8]) -> Result<Signature, Error>
    where
        R: rand_core::CryptoRng + rand_core::RngCore,
    {
        self.signing_key.sign_with_rng(rng, msg)
    }
}

impl Drop for SpendingKey {
    fn drop(&mut self) {
        // zeroize the seed; inner keys handle their own drop
        for byte in self.seed.iter_mut() {
            unsafe { core::ptr::write_volatile(byte, 0) };
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(feature = "zeroize")]
impl zeroize::ZeroizeOnDrop for SpendingKey {}

impl signature::Signer<Signature> for SpendingKey {
    fn try_sign(&self, msg: &[u8]) -> Result<Signature, signature::Error> {
        self.sign(msg).map_err(|_| signature::Error::new())
    }
}

// --- FullViewingKey ---

/// full viewing key: can verify signatures and decrypt messages, but cannot sign.
///
/// this is the natural export boundary — give this to a watch-only wallet,
/// browser extension, or indexer that needs to read data but must not have
/// spending authority.
///
/// ```
/// use falconed::{SpendingKey, encryption};
/// use rand_core::OsRng;
///
/// let sk = SpendingKey::generate(&mut OsRng);
/// let fvk = sk.full_viewing_key().unwrap();
///
/// // verify
/// let sig = sk.sign(b"msg").unwrap();
/// assert!(fvk.verify(b"msg", &sig).is_ok());
///
/// // encrypt + decrypt
/// let epk = fvk.encryption_public_key();
/// let encrypted = encryption::seal(&mut OsRng, &epk, b"secret").unwrap();
/// let plaintext = encryption::open(fvk.viewing_key(), &encrypted).unwrap();
/// assert_eq!(&plaintext, b"secret");
/// ```
pub struct FullViewingKey {
    verifying_key: VerifyingKey,
    viewing_key: ViewingKey,
}

impl FullViewingKey {
    /// construct from component keys.
    ///
    /// use this when you have a verifying key and viewing key from separate
    /// sources (e.g. deserialized independently).
    pub fn new(verifying_key: VerifyingKey, viewing_key: ViewingKey) -> Self {
        Self {
            verifying_key,
            viewing_key,
        }
    }

    /// borrow the verifying key (signature verification).
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    /// borrow the viewing key (decryption capability).
    pub fn viewing_key(&self) -> &ViewingKey {
        &self.viewing_key
    }

    /// derive the encryption public key.
    pub fn encryption_public_key(&self) -> EncryptionPublicKey {
        self.viewing_key.encryption_public_key()
    }

    /// verify a signature. delegates to the inner [`VerifyingKey`].
    pub fn verify(&self, msg: &[u8], sig: &Signature) -> Result<(), Error> {
        self.verifying_key.verify(msg, sig)
    }

    /// verify a signature, always checking both components.
    /// delegates to [`VerifyingKey::verify_all`].
    pub fn verify_all(&self, msg: &[u8], sig: &Signature) -> Result<(), Error> {
        self.verifying_key.verify_all(msg, sig)
    }

    /// serialize to bytes.
    ///
    /// format: `verifying_key || viewing_key`
    pub fn to_bytes(&self) -> [u8; FULL_VIEWING_KEY_SIZE] {
        let mut out = [0u8; FULL_VIEWING_KEY_SIZE];
        let vk_bytes = self.verifying_key.to_bytes();
        let viewing_bytes = self.viewing_key.to_bytes();
        out[..crate::VERIFYING_KEY_SIZE].copy_from_slice(&vk_bytes);
        out[crate::VERIFYING_KEY_SIZE..].copy_from_slice(&viewing_bytes);
        out
    }

    /// deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != FULL_VIEWING_KEY_SIZE {
            return Err(Error::InvalidLength);
        }

        let vk_arr: &[u8; crate::VERIFYING_KEY_SIZE] = bytes[..crate::VERIFYING_KEY_SIZE]
            .try_into()
            .map_err(|_| Error::InvalidLength)?;
        let verifying_key = VerifyingKey::from_bytes(vk_arr)?;
        let viewing_key = ViewingKey::from_bytes(&bytes[crate::VERIFYING_KEY_SIZE..])?;

        Ok(Self {
            verifying_key,
            viewing_key,
        })
    }
}

#[cfg(feature = "zeroize")]
impl zeroize::ZeroizeOnDrop for FullViewingKey {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryption;

    #[test]
    fn spending_key_from_seed_deterministic() {
        let seed = [42u8; SEED_SIZE];
        let sk1 = SpendingKey::from_seed(&seed);
        let sk2 = SpendingKey::from_seed(&seed);
        assert_eq!(sk1.signing_key().to_bytes(), sk2.signing_key().to_bytes());
        assert_eq!(sk1.viewing_key().to_bytes(), sk2.viewing_key().to_bytes());
    }

    #[test]
    fn different_seeds_different_keys() {
        let sk1 = SpendingKey::from_seed(&[1u8; SEED_SIZE]);
        let sk2 = SpendingKey::from_seed(&[2u8; SEED_SIZE]);
        assert_ne!(sk1.signing_key().to_bytes(), sk2.signing_key().to_bytes());
    }

    #[test]
    fn sign_with_spending_key_verify_with_fvk() {
        let sk = SpendingKey::generate(&mut rand_core::OsRng);
        let fvk = sk.full_viewing_key().unwrap();

        let sig = sk.sign(b"test message").unwrap();
        assert!(fvk.verify(b"test message", &sig).is_ok());
        assert!(fvk.verify(b"wrong", &sig).is_err());
    }

    #[test]
    fn encrypt_to_fvk_decrypt_with_fvk() {
        let mut rng = rand_core::OsRng;
        let sk = SpendingKey::generate(&mut rng);
        let fvk = sk.full_viewing_key().unwrap();

        let epk = fvk.encryption_public_key();
        let plaintext = b"post-quantum secrets";
        let encrypted = encryption::seal(&mut rng, &epk, plaintext).unwrap();
        let decrypted = encryption::open(fvk.viewing_key(), &encrypted).unwrap();

        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn spending_key_shortcuts_match_fvk() {
        let sk = SpendingKey::from_seed(&[99u8; SEED_SIZE]);
        let fvk = sk.full_viewing_key().unwrap();

        // verifying keys should match
        let vk_direct = sk.verifying_key().unwrap();
        assert_eq!(vk_direct.to_bytes(), fvk.verifying_key().to_bytes());

        // viewing keys should match
        assert_eq!(sk.viewing_key().to_bytes(), fvk.viewing_key().to_bytes());

        // encryption public keys should match
        assert_eq!(
            sk.encryption_public_key().to_bytes(),
            fvk.encryption_public_key().to_bytes(),
        );
    }

    #[test]
    fn seed_is_preserved() {
        let seed = [77u8; SEED_SIZE];
        let sk = SpendingKey::from_seed(&seed);
        assert_eq!(sk.seed(), &seed);
    }

    #[test]
    fn full_viewing_key_serialization_roundtrip() {
        let sk = SpendingKey::generate(&mut rand_core::OsRng);
        let fvk = sk.full_viewing_key().unwrap();

        let bytes = fvk.to_bytes();
        assert_eq!(bytes.len(), FULL_VIEWING_KEY_SIZE);

        let fvk2 = FullViewingKey::from_bytes(&bytes).unwrap();
        assert_eq!(fvk.to_bytes(), fvk2.to_bytes());
    }

    #[test]
    fn full_viewing_key_rejects_invalid_length() {
        assert!(FullViewingKey::from_bytes(&[0u8; 10]).is_err());
        assert!(FullViewingKey::from_bytes(&[]).is_err());
    }

    #[test]
    fn signer_trait_on_spending_key() {
        use ::signature::Signer as _;

        let sk = SpendingKey::generate(&mut rand_core::OsRng);
        let sig = sk.try_sign(b"trait test").unwrap();
        let fvk = sk.full_viewing_key().unwrap();
        assert!(fvk.verify(b"trait test", &sig).is_ok());
    }

    #[test]
    fn full_viewing_key_from_parts() {
        let sk = SpendingKey::from_seed(&[55u8; SEED_SIZE]);
        let vk = sk.verifying_key().unwrap();
        let viewing = ViewingKey::from_seed(&[55u8; SEED_SIZE]);

        let fvk = FullViewingKey::new(vk, viewing);
        let sig = sk.sign(b"parts test").unwrap();
        assert!(fvk.verify(b"parts test", &sig).is_ok());
    }

    #[test]
    fn cross_identity_decrypt_fails() {
        let mut rng = rand_core::OsRng;
        let sk1 = SpendingKey::from_seed(&[1u8; SEED_SIZE]);
        let sk2 = SpendingKey::from_seed(&[2u8; SEED_SIZE]);

        let fvk1 = sk1.full_viewing_key().unwrap();
        let fvk2 = sk2.full_viewing_key().unwrap();

        let encrypted = encryption::seal(&mut rng, &fvk1.encryption_public_key(), b"private").unwrap();
        assert!(encryption::open(fvk2.viewing_key(), &encrypted).is_err());
    }
}

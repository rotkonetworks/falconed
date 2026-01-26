//! signing key implementation.

use crate::error::Error;
use crate::signature::Signature;
use crate::verifying::VerifyingKey;
use crate::{ED25519_SEED_SIZE, FALCON_PUBLIC_KEY_SIZE, FALCON_SECRET_KEY_SIZE, FALCON_SIGNATURE_SIZE, SIGNING_KEY_SIZE};

use ed25519_dalek::SigningKey as Ed25519SigningKey;
use fn_dsa::{
    KeyPairGenerator, KeyPairGenerator512, SigningKey as FnDsaSigningKey,
    SigningKey512, FN_DSA_LOGN_512, DOMAIN_NONE, HASH_ID_RAW,
};

// note: SigningKey512 derives ZeroizeOnDrop, so decoded keys are
// automatically zeroized when they go out of scope.

/// hybrid signing key: ed25519 + falcon-512.
///
/// this type intentionally does not implement `Clone` - secret keys should not
/// be trivially copyable. use [`to_bytes`](Self::to_bytes) and
/// [`from_bytes`](Self::from_bytes) for explicit serialization when needed.
///
/// the falcon public key is derived on demand from the secret key rather than
/// stored, saving 897 bytes per key instance.
pub struct SigningKey {
    ed25519: Ed25519SigningKey,
    falcon_sk: [u8; FALCON_SECRET_KEY_SIZE],
}

impl SigningKey {
    /// generate a new signing key from a csprng.
    pub fn generate<R>(csprng: &mut R) -> Self
    where
        R: rand_core::CryptoRng + rand_core::RngCore,
    {
        let ed25519 = Ed25519SigningKey::generate(csprng);

        let mut falcon_sk = [0u8; FALCON_SECRET_KEY_SIZE];
        let mut falcon_pk = [0u8; FALCON_PUBLIC_KEY_SIZE];

        let mut kg = KeyPairGenerator512::default();
        kg.keygen(FN_DSA_LOGN_512, csprng, &mut falcon_sk, &mut falcon_pk);

        // falcon_pk is discarded - we derive it on demand from falcon_sk

        Self { ed25519, falcon_sk }
    }

    /// sign a message.
    ///
    /// produces a hybrid signature containing both ed25519 and falcon
    /// signatures over the same message.
    ///
    /// # errors
    ///
    /// returns an error if the internal key state is corrupted.
    pub fn sign(&self, msg: &[u8]) -> Result<Signature, Error> {
        self.sign_with_rng(&mut rand_core::OsRng, msg)
    }

    /// sign a message with explicit rng.
    ///
    /// # errors
    ///
    /// returns an error if the internal key state is corrupted.
    pub fn sign_with_rng<R>(&self, rng: &mut R, msg: &[u8]) -> Result<Signature, Error>
    where
        R: rand_core::CryptoRng + rand_core::RngCore,
    {
        use ed25519_dalek::Signer;

        let ed_sig = self.ed25519.sign(msg);

        let mut falcon_signer: SigningKey512 = FnDsaSigningKey::decode(&self.falcon_sk)
            .ok_or(Error::InvalidFalconKey)?;

        let mut falcon_sig = [0u8; FALCON_SIGNATURE_SIZE];
        falcon_signer.sign(rng, &DOMAIN_NONE, &HASH_ID_RAW, msg, &mut falcon_sig);
        // falcon_signer is ZeroizeOnDrop, automatically zeroized here

        Ok(Signature::from_parts(ed_sig, falcon_sig))
    }

    /// get the corresponding verifying key.
    ///
    /// this derives the falcon public key from the secret key on each call.
    /// if you need the verifying key multiple times, store the result.
    ///
    /// # errors
    ///
    /// returns an error if the internal falcon key state is corrupted.
    /// this should not happen under normal operation but can occur due to
    /// memory corruption or unsafe code.
    pub fn verifying_key(&self) -> Result<VerifyingKey, Error> {
        let ed_vk = self.ed25519.verifying_key();

        // derive falcon public key from secret key
        let falcon_signer: SigningKey512 = FnDsaSigningKey::decode(&self.falcon_sk)
            .ok_or(Error::InvalidFalconKey)?;

        let mut falcon_pk = [0u8; FALCON_PUBLIC_KEY_SIZE];
        falcon_signer.to_verifying_key(&mut falcon_pk);
        // falcon_signer is ZeroizeOnDrop, automatically zeroized here

        Ok(VerifyingKey::from_parts(ed_vk, falcon_pk))
    }

    /// serialize the signing key to bytes.
    ///
    /// format: `ed25519_seed (32) || falcon_sk (1281)`
    pub fn to_bytes(&self) -> [u8; SIGNING_KEY_SIZE] {
        let mut out = [0u8; SIGNING_KEY_SIZE];

        out[..ED25519_SEED_SIZE].copy_from_slice(&self.ed25519.to_bytes());
        out[ED25519_SEED_SIZE..].copy_from_slice(&self.falcon_sk);

        out
    }

    /// deserialize a signing key from bytes.
    pub fn from_bytes(bytes: &[u8; SIGNING_KEY_SIZE]) -> Result<Self, Error> {
        let ed_seed: [u8; ED25519_SEED_SIZE] = bytes[..ED25519_SEED_SIZE]
            .try_into()
            .map_err(|_| Error::InvalidLength)?;

        let ed25519 = Ed25519SigningKey::from_bytes(&ed_seed);

        let mut falcon_sk = [0u8; FALCON_SECRET_KEY_SIZE];
        falcon_sk.copy_from_slice(&bytes[ED25519_SEED_SIZE..]);

        // validate falcon key by attempting to decode it
        let _: SigningKey512 = FnDsaSigningKey::decode(&falcon_sk)
            .ok_or(Error::InvalidFalconKey)?;

        Ok(Self { ed25519, falcon_sk })
    }
}

/// hazmat: direct access to internal key components.
///
/// these methods expose raw cryptographic keys. misuse can compromise security.
/// only use if you know exactly what you're doing.
#[cfg(feature = "hazmat")]
impl SigningKey {
    /// access the inner ed25519 signing key.
    pub fn ed25519_key(&self) -> &Ed25519SigningKey {
        &self.ed25519
    }

    /// access the inner falcon secret key bytes.
    pub fn falcon_secret_key_bytes(&self) -> &[u8; FALCON_SECRET_KEY_SIZE] {
        &self.falcon_sk
    }
}

impl TryFrom<&[u8]> for SigningKey {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != SIGNING_KEY_SIZE {
            return Err(Error::InvalidLength);
        }
        let arr: &[u8; SIGNING_KEY_SIZE] = bytes.try_into().map_err(|_| Error::InvalidLength)?;
        Self::from_bytes(arr)
    }
}

impl Drop for SigningKey {
    fn drop(&mut self) {
        // always zeroize secret key material on drop
        // use volatile write to prevent compiler from optimizing this away
        for byte in self.falcon_sk.iter_mut() {
            unsafe {
                core::ptr::write_volatile(byte, 0);
            }
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(feature = "zeroize")]
impl zeroize::Zeroize for SigningKey {
    fn zeroize(&mut self) {
        // ed25519-dalek's SigningKey implements ZeroizeOnDrop internally
        zeroize::Zeroize::zeroize(&mut self.falcon_sk);
    }
}

#[cfg(feature = "zeroize")]
impl zeroize::ZeroizeOnDrop for SigningKey {}

impl signature::Signer<Signature> for SigningKey {
    fn try_sign(&self, msg: &[u8]) -> Result<Signature, signature::Error> {
        self.sign(msg).map_err(|_| signature::Error::new())
    }
}

impl signature::RandomizedSigner<Signature> for SigningKey {
    fn try_sign_with_rng(
        &self,
        rng: &mut impl rand_core::CryptoRngCore,
        msg: &[u8],
    ) -> Result<Signature, signature::Error> {
        self.sign_with_rng(rng, msg).map_err(|_| signature::Error::new())
    }
}

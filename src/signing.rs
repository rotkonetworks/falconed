//! signing key implementation.

use crate::error::Error;
use crate::signature::Signature;
use crate::verifying::VerifyingKey;
use crate::{ED25519_SEED_SIZE, FALCON_PUBLIC_KEY_SIZE, FALCON_SECRET_KEY_SIZE, FALCON_SIGNATURE_SIZE, SEED_SIZE, SIGNING_KEY_SIZE};

use ed25519_dalek::SigningKey as Ed25519SigningKey;
use fn_dsa::{
    KeyPairGenerator, KeyPairGenerator512, SigningKey as FnDsaSigningKey,
    SigningKey512, FN_DSA_LOGN_512, HASH_ID_RAW,
};
use sha2::{Sha512, Digest};

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
    ///
    /// draws 32 bytes from the rng as a master seed, then derives
    /// independent ed25519 and falcon keys via [`from_seed`](Self::from_seed).
    pub fn generate<R>(csprng: &mut R) -> Self
    where
        R: rand_core::CryptoRng + rand_core::RngCore,
    {
        let mut seed = [0u8; SEED_SIZE];
        csprng.fill_bytes(&mut seed);
        let key = Self::from_seed(&seed);

        // zeroize the seed on the stack
        for byte in seed.iter_mut() {
            unsafe { core::ptr::write_volatile(byte, 0) };
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);

        key
    }

    /// derive a signing key deterministically from a 32-byte master seed.
    ///
    /// the seed is expanded via SHA-512 into independent keying material:
    /// - ed25519 seed = `SHA-512("falconed-ed25519" || master)[0..32]`
    /// - falcon rng seed = `SHA-512("falconed-falcon" || master)[0..32]`
    ///
    /// the master seed is not stored — [`to_bytes`](Self::to_bytes) returns
    /// the expanded `ed25519_seed || falcon_sk`. callers who need the seed
    /// for backup or derivation must store it themselves.
    pub fn from_seed(seed: &[u8; SEED_SIZE]) -> Self {
        use rand_chacha::rand_core::SeedableRng;

        // derive ed25519 seed
        let ed_hash = Sha512::new()
            .chain_update(b"falconed-ed25519")
            .chain_update(seed)
            .finalize();
        let mut ed_seed = [0u8; 32];
        ed_seed.copy_from_slice(&ed_hash[..32]);
        let ed25519 = Ed25519SigningKey::from_bytes(&ed_seed);

        // derive falcon rng seed
        let falcon_hash = Sha512::new()
            .chain_update(b"falconed-falcon")
            .chain_update(seed)
            .finalize();
        let mut falcon_rng_seed = [0u8; 32];
        falcon_rng_seed.copy_from_slice(&falcon_hash[..32]);
        let mut falcon_rng = rand_chacha::ChaCha20Rng::from_seed(falcon_rng_seed);

        let mut falcon_sk = [0u8; FALCON_SECRET_KEY_SIZE];
        let mut falcon_pk = [0u8; FALCON_PUBLIC_KEY_SIZE];
        let mut kg = KeyPairGenerator512::default();
        kg.keygen(FN_DSA_LOGN_512, &mut falcon_rng, &mut falcon_sk, &mut falcon_pk);

        // zeroize intermediates
        for byte in ed_seed.iter_mut().chain(falcon_rng_seed.iter_mut()) {
            unsafe { core::ptr::write_volatile(byte, 0) };
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);

        Self { ed25519, falcon_sk }
    }

    /// derive a signing key from a seed slice.
    ///
    /// # errors
    ///
    /// returns [`Error::InvalidLength`] if the slice is not exactly 32 bytes.
    pub fn from_seed_slice(seed: &[u8]) -> Result<Self, Error> {
        let seed: &[u8; SEED_SIZE] = seed.try_into().map_err(|_| Error::InvalidLength)?;
        Ok(Self::from_seed(seed))
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

        let ed_msg = crate::tagged_message(crate::ED25519_DOMAIN_TAG, msg);
        let ed_sig = self.ed25519.sign(&ed_msg);

        let mut falcon_signer: SigningKey512 = FnDsaSigningKey::decode(&self.falcon_sk)
            .ok_or(Error::InvalidFalconKey)?;

        let mut falcon_sig = [0u8; FALCON_SIGNATURE_SIZE];
        falcon_signer.sign(rng, &crate::FALCON_DOMAIN_CTX, &HASH_ID_RAW, msg, &mut falcon_sig);
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

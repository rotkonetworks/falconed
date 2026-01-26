//! signing key implementation.

use crate::error::Error;
use crate::signature::Signature;
use crate::verifying::VerifyingKey;
use crate::{
    ED25519_SEED_SIZE, FALCON_PUBLIC_KEY_SIZE, FALCON_SECRET_KEY_SIZE,
    FALCON_SIGNATURE_SIZE, SIGNING_KEY_SIZE,
};

use ed25519_dalek::SigningKey as Ed25519SigningKey;
use fn_dsa::{
    KeyPairGenerator, KeyPairGenerator512, SigningKey as FnDsaSigningKey,
    SigningKey512, FN_DSA_LOGN_512, DOMAIN_NONE, HASH_ID_RAW,
};

/// hybrid signing key: ed25519 + falcon-512.
///
/// contains the secret key material for both schemes.
/// generate with [`SigningKey::generate`].
#[derive(Clone)]
pub struct SigningKey {
    ed25519: Ed25519SigningKey,
    falcon_sk: [u8; FALCON_SECRET_KEY_SIZE],
    falcon_pk: [u8; FALCON_PUBLIC_KEY_SIZE],
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

        Self {
            ed25519,
            falcon_sk,
            falcon_pk,
        }
    }

    /// sign a message.
    ///
    /// produces a hybrid signature containing both ed25519 and falcon
    /// signatures over the same message.
    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.sign_with_rng(&mut rand_core::OsRng, msg)
    }

    /// sign a message with explicit rng.
    pub fn sign_with_rng<R>(&self, rng: &mut R, msg: &[u8]) -> Signature
    where
        R: rand_core::CryptoRng + rand_core::RngCore,
    {
        use ed25519_dalek::Signer;

        let ed_sig = self.ed25519.sign(msg);

        let mut falcon_signer: SigningKey512 = FnDsaSigningKey::decode(&self.falcon_sk)
            .expect("valid falcon signing key");

        let mut falcon_sig = [0u8; FALCON_SIGNATURE_SIZE];
        falcon_signer.sign(rng, &DOMAIN_NONE, &HASH_ID_RAW, msg, &mut falcon_sig);

        Signature::from_parts(ed_sig, falcon_sig)
    }

    /// get the corresponding verifying key.
    pub fn verifying_key(&self) -> VerifyingKey {
        let ed_vk = self.ed25519.verifying_key();
        VerifyingKey::from_parts(ed_vk, self.falcon_pk)
    }

    /// serialize the signing key to bytes.
    ///
    /// format: `ed25519_seed (32) || falcon_sk`
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

        // derive the falcon public key from the signing key
        let falcon_signer: SigningKey512 = FnDsaSigningKey::decode(&falcon_sk)
            .ok_or(Error::InvalidFalconKey)?;

        let mut falcon_pk = [0u8; FALCON_PUBLIC_KEY_SIZE];
        falcon_signer.to_verifying_key(&mut falcon_pk);

        Ok(Self {
            ed25519,
            falcon_sk,
            falcon_pk,
        })
    }

    /// access the inner ed25519 signing key.
    ///
    /// # hazmat
    ///
    /// this exposes the raw ed25519 key. you probably don't need this.
    pub fn ed25519(&self) -> &Ed25519SigningKey {
        &self.ed25519
    }

    /// access the inner falcon secret key bytes.
    ///
    /// # hazmat
    ///
    /// this exposes the raw falcon key bytes. you probably don't need this.
    pub fn falcon_secret_key(&self) -> &[u8; FALCON_SECRET_KEY_SIZE] {
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

#[cfg(feature = "zeroize")]
impl zeroize::Zeroize for SigningKey {
    fn zeroize(&mut self) {
        // ed25519-dalek's SigningKey implements ZeroizeOnDrop internally,
        // so we only need to zeroize the falcon key material.
        zeroize::Zeroize::zeroize(&mut self.falcon_sk);
        zeroize::Zeroize::zeroize(&mut self.falcon_pk);
    }
}

#[cfg(feature = "zeroize")]
impl zeroize::ZeroizeOnDrop for SigningKey {}

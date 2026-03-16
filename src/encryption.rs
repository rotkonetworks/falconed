//! hybrid post-quantum encryption keys: x25519 + ml-kem-768.
//!
//! derived from the same master seed as the signing keys via domain-separated
//! SHA-512 expansion. the viewing key (decapsulation key + x25519 secret) can
//! decrypt but never sign — one-way derivation from the master seed prevents
//! recovering the signing key from the viewing key.
//!
//! ## key hierarchy
//!
//! ```text
//! master_seed (32 bytes)
//!   ├─ SHA-512("falconed-ed25519" || seed)  → ed25519 signing key
//!   ├─ SHA-512("falconed-falcon"  || seed)  → falcon-512 signing key
//!   ├─ SHA-512("falconed-x25519"  || seed)  → x25519 ECDH secret key
//!   └─ SHA-512("falconed-mlkem"   || seed)  → ml-kem-768 decapsulation key
//! ```
//!
//! ## viewing key
//!
//! the [`ViewingKey`] contains the x25519 secret + ml-kem decapsulation key.
//! it can be exported separately from the signing key and given to a
//! watch-only client (like a browser extension) that needs to decrypt
//! incoming messages without spending authority.
//!
//! ## encrypted messages
//!
//! use [`seal`] and [`open`] to encrypt/decrypt messages. the KEM internals
//! (`encapsulate`/`decapsulate`) are not exposed — `seal`/`open` compose the
//! KEM, key commitment, and AEAD correctly.
//!
//! ## security considerations
//!
//! **KEM combiner**: the hybrid KEM combiner hashes both shared secrets together
//! with full transcript binding (all public keys and ciphertexts) to ensure both
//! components contribute to the final shared secret.
//!
//! **key commitment**: encrypted messages include a key commitment tag that
//! prevents invisible salamander attacks (where a single ciphertext decrypts
//! to different plaintexts under different keys).
//!
//! **small-order rejection**: x25519 DH results are checked for contributory
//! behaviour. small-order ephemeral keys that would zero out the x25519
//! component are rejected.
//!
//! **deterministic derivation**: key derivation from seeds depends on the
//! internal behaviour of the `ml-kem` and `rand_chacha` crates. upgrading
//! these dependencies may change derived keys for the same seed. pin
//! dependency versions and verify test vectors before upgrading.
//!
//! **viewing key isolation**: the x25519 static secret in a [`ViewingKey`]
//! MUST NOT be reused in other protocols (Noise, WireGuard, etc.). the
//! domain separation in the KEM combiner does not protect against
//! cross-protocol attacks at the DH level.

use crate::error::Error;
use crate::SEED_SIZE;

use alloc::vec::Vec;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{Ciphertext, EncodedSizeUser, KemCore, MlKem768};
use ml_kem::array::typenum::Unsigned;
use sha2::{Digest, Sha512};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};

// --- size constants (all derived from the type system) ---

/// x25519 public key size.
pub const X25519_PUBLIC_KEY_SIZE: usize = 32;

/// x25519 secret key size.
pub const X25519_SECRET_KEY_SIZE: usize = 32;

/// ml-kem-768 ciphertext size in bytes.
const MLKEM_CIPHERTEXT_SIZE: usize = <MlKem768 as KemCore>::CiphertextSize::USIZE;

/// ml-kem-768 encapsulation key size.
const MLKEM_EK_SIZE: usize = <MlKemEk as EncodedSizeUser>::EncodedSize::USIZE;

/// ml-kem-768 decapsulation key size.
const MLKEM_DK_SIZE: usize = <MlKemDk as EncodedSizeUser>::EncodedSize::USIZE;

/// capsule size: x25519 ephemeral pk (32) + ml-kem ciphertext.
pub const CAPSULE_SIZE: usize = X25519_PUBLIC_KEY_SIZE + MLKEM_CIPHERTEXT_SIZE;

/// viewing key size: x25519 secret (32) + ml-kem decapsulation key.
pub const VIEWING_KEY_SIZE: usize = X25519_SECRET_KEY_SIZE + MLKEM_DK_SIZE;

/// encryption public key size: x25519 public key (32) + ml-kem encapsulation key.
pub const ENCRYPTION_PUBLIC_KEY_SIZE: usize = X25519_PUBLIC_KEY_SIZE + MLKEM_EK_SIZE;

/// combined shared secret size (both KEM outputs hashed together).
const SHARED_SECRET_SIZE: usize = 32;

/// AEAD nonce size for ChaCha20-Poly1305.
const NONCE_SIZE: usize = 12;

/// AEAD tag size for ChaCha20-Poly1305.
const TAG_SIZE: usize = 16;

/// key commitment tag size (SHA-512 truncated to 32 bytes).
const KEY_COMMITMENT_SIZE: usize = 32;

// --- compile-time consistency checks ---

const _: () = assert!(CAPSULE_SIZE == X25519_PUBLIC_KEY_SIZE + MLKEM_CIPHERTEXT_SIZE);
const _: () = assert!(VIEWING_KEY_SIZE == X25519_SECRET_KEY_SIZE + MLKEM_DK_SIZE);
const _: () = assert!(ENCRYPTION_PUBLIC_KEY_SIZE == X25519_PUBLIC_KEY_SIZE + MLKEM_EK_SIZE);

// --- type aliases ---

type MlKemDk = <MlKem768 as KemCore>::DecapsulationKey;
type MlKemEk = <MlKem768 as KemCore>::EncapsulationKey;
type MlKemCt = Ciphertext<MlKem768>;

// --- shared secret newtype ---

/// a shared secret derived from the hybrid KEM.
///
/// this type intentionally does not implement `Clone`, `Copy`, `Debug`, or
/// `AsRef<[u8]>`. it is zeroized on drop. the only way to consume it is
/// through `seal`/`open` or the explicit (crate-private) `.0` access.
struct SharedSecret([u8; SHARED_SECRET_SIZE]);

impl Drop for SharedSecret {
    fn drop(&mut self) {
        zeroize_bytes(&mut self.0);
    }
}

// --- utility functions ---

/// zeroize a byte slice via volatile writes + compiler fence.
///
/// this is a best-effort fallback for when the `zeroize` crate feature
/// is not enabled. volatile writes are not formally guaranteed by rust's
/// memory model to prevent elision, but work in practice on current compilers.
fn zeroize_bytes(bytes: &mut [u8]) {
    for byte in bytes.iter_mut() {
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// domain-separated KDF: `SHA-512(len(tag) || tag || input)`.
///
/// the length prefix prevents ambiguity between tags that are prefixes
/// of each other. tags must be <= 255 bytes (enforced by taking `&[u8; N]`
/// through the call sites, but asserted here defensively).
fn domain_kdf(tag: &[u8], input: &[u8]) -> [u8; 64] {
    debug_assert!(tag.len() <= 255, "domain tag exceeds u8 length prefix");
    let hash = Sha512::new()
        .chain_update(&[tag.len() as u8])
        .chain_update(tag)
        .chain_update(input)
        .finalize();
    let mut out = [0u8; 64];
    out.copy_from_slice(&hash);
    out
}

/// compute a key commitment tag.
///
/// binds the shared secret, nonce, and capsule to prevent invisible
/// salamander attacks where a single ciphertext decrypts to different
/// plaintexts under different keys.
fn key_commitment(
    shared_secret: &[u8; SHARED_SECRET_SIZE],
    nonce: &[u8; NONCE_SIZE],
    capsule_bytes: &[u8; CAPSULE_SIZE],
) -> [u8; KEY_COMMITMENT_SIZE] {
    let hash = Sha512::new()
        .chain_update(b"falconed-key-commit")
        .chain_update(shared_secret)
        .chain_update(nonce)
        .chain_update(capsule_bytes)
        .finalize();
    let mut tag = [0u8; KEY_COMMITMENT_SIZE];
    tag.copy_from_slice(&hash[..KEY_COMMITMENT_SIZE]);
    tag
}

// --- public types ---

/// hybrid encryption public key: x25519 public key + ml-kem-768 encapsulation key.
///
/// this is what senders use to encrypt messages to this recipient.
/// it contains no secret material.
#[derive(Clone, Debug, PartialEq)]
pub struct EncryptionPublicKey {
    x25519: X25519PublicKey,
    mlkem_ek: MlKemEk,
}

/// hybrid viewing key: x25519 secret + ml-kem-768 decapsulation key.
///
/// can decrypt messages but cannot sign. derived from the master seed
/// via one-way domain-separated expansion — cannot recover the signing key.
///
/// this type intentionally does not implement `Clone`, `Debug`, or
/// `AsRef<[u8]>` — secret key material should not be trivially copyable
/// or accidentally logged.
pub struct ViewingKey {
    x25519: StaticSecret,
    mlkem_dk: MlKemDk,
}

/// encapsulation result: ephemeral x25519 public key + ml-kem ciphertext.
///
/// sent alongside the encrypted message so the recipient can decapsulate.
/// this is public, non-secret data.
#[derive(Clone)]
pub struct Capsule {
    x25519_ephemeral: X25519PublicKey,
    mlkem_ciphertext: MlKemCt,
}

/// an encrypted message: capsule + nonce + key commitment + AEAD ciphertext.
///
/// wire format: `capsule || nonce (12) || key_commitment (32) || aead_ciphertext`
///
/// the capsule contains the hybrid KEM material (x25519 ephemeral pk + ml-kem ciphertext).
/// the recipient decapsulates to recover the shared secret, verifies the key commitment,
/// then decrypts with ChaCha20-Poly1305.
pub struct EncryptedMessage {
    capsule: Capsule,
    nonce: [u8; NONCE_SIZE],
    key_commitment: [u8; KEY_COMMITMENT_SIZE],
    ciphertext: Vec<u8>,
}

// --- ViewingKey ---

impl ViewingKey {
    /// derive a viewing key from a 32-byte master seed.
    ///
    /// uses the same seed as [`SigningKey::from_seed`](crate::SigningKey::from_seed)
    /// but with different domain tags, so the viewing key is independent.
    pub fn from_seed(seed: &[u8; SEED_SIZE]) -> Self {
        // derive x25519 secret key via length-prefixed domain KDF
        let mut x_kdf = domain_kdf(b"falconed-x25519", seed);
        let mut x_seed = [0u8; 32];
        x_seed.copy_from_slice(&x_kdf[..32]);
        let x25519 = StaticSecret::from(x_seed);
        zeroize_bytes(&mut x_kdf);

        // derive ml-kem-768 keypair from deterministically seeded rng
        let mut mlkem_kdf = domain_kdf(b"falconed-mlkem", seed);
        let mut mlkem_rng_seed = [0u8; 32];
        mlkem_rng_seed.copy_from_slice(&mlkem_kdf[..32]);
        zeroize_bytes(&mut mlkem_kdf);

        use rand_chacha::rand_core::SeedableRng;
        let mut mlkem_rng = rand_chacha::ChaCha20Rng::from_seed(mlkem_rng_seed);
        let (mlkem_dk, _mlkem_ek) = MlKem768::generate(&mut mlkem_rng);

        zeroize_bytes(&mut x_seed);
        zeroize_bytes(&mut mlkem_rng_seed);

        Self { x25519, mlkem_dk }
    }

    /// derive a viewing key from a seed slice.
    pub fn from_seed_slice(seed: &[u8]) -> Result<Self, Error> {
        let seed: &[u8; SEED_SIZE] = seed.try_into().map_err(|_| Error::InvalidLength)?;
        Ok(Self::from_seed(seed))
    }

    /// get the corresponding encryption public key.
    pub fn encryption_public_key(&self) -> EncryptionPublicKey {
        let x25519 = X25519PublicKey::from(&self.x25519);
        let mlkem_ek = self.mlkem_dk.encapsulation_key().clone();
        EncryptionPublicKey { x25519, mlkem_ek }
    }

    /// decapsulate a hybrid capsule to recover the shared secret.
    ///
    /// combines x25519 ECDH + ml-kem decapsulation, then hashes both
    /// shared secrets together with full transcript binding.
    fn decapsulate(&self, capsule: &Capsule) -> Result<SharedSecret, Error> {
        let x_shared = self.x25519.diffie_hellman(&capsule.x25519_ephemeral);

        if !x_shared.was_contributory() {
            return Err(Error::DecryptionFailed);
        }

        let x_static_pk = X25519PublicKey::from(&self.x25519);
        let mlkem_ek = self.mlkem_dk.encapsulation_key();

        let mlkem_shared = self.mlkem_dk.decapsulate(&capsule.mlkem_ciphertext)
            .map_err(|_| Error::DecryptionFailed)?;

        let combined = Sha512::new()
            .chain_update(b"falconed-hybrid-kem")
            .chain_update(x_shared.as_bytes())
            .chain_update(&mlkem_shared)
            .chain_update(capsule.x25519_ephemeral.as_bytes())
            .chain_update(x_static_pk.as_bytes())
            .chain_update(mlkem_ek.as_bytes().as_slice())
            .chain_update(capsule.mlkem_ciphertext.as_slice())
            .finalize();

        let mut out = [0u8; SHARED_SECRET_SIZE];
        out.copy_from_slice(&combined[..32]);
        Ok(SharedSecret(out))
    }

    /// serialize the viewing key to bytes.
    ///
    /// format: `x25519_secret (32) || mlkem_dk`
    pub fn to_bytes(&self) -> [u8; VIEWING_KEY_SIZE] {
        let mut out = [0u8; VIEWING_KEY_SIZE];
        out[..X25519_SECRET_KEY_SIZE].copy_from_slice(&self.x25519.to_bytes());
        let dk_bytes = self.mlkem_dk.as_bytes();
        out[X25519_SECRET_KEY_SIZE..].copy_from_slice(dk_bytes.as_slice());
        out
    }

    /// deserialize a viewing key from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != VIEWING_KEY_SIZE {
            return Err(Error::InvalidLength);
        }

        let mut x_bytes = [0u8; 32];
        x_bytes.copy_from_slice(&bytes[..X25519_SECRET_KEY_SIZE]);
        let x25519 = StaticSecret::from(x_bytes);
        zeroize_bytes(&mut x_bytes);

        let dk_bytes = &bytes[X25519_SECRET_KEY_SIZE..];
        let dk_encoded: &ml_kem::Encoded<MlKemDk> =
            dk_bytes.try_into().map_err(|_| Error::InvalidLength)?;
        let mlkem_dk = MlKemDk::from_bytes(dk_encoded);

        // validate: re-encode and check round-trip consistency
        if mlkem_dk.as_bytes() != *dk_encoded {
            return Err(Error::InvalidLength);
        }

        Ok(Self { x25519, mlkem_dk })
    }
}

impl Drop for ViewingKey {
    fn drop(&mut self) {
        // StaticSecret handles its own zeroization via x25519-dalek.
        // zeroize the ml-kem decapsulation key by overwriting with a zeroed key.
        let zeroed = MlKemDk::from_bytes(&ml_kem::Encoded::<MlKemDk>::default());
        unsafe { core::ptr::write_volatile(&mut self.mlkem_dk as *mut MlKemDk, zeroed) };
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(feature = "zeroize")]
impl zeroize::ZeroizeOnDrop for ViewingKey {}

// --- EncryptionPublicKey ---

impl EncryptionPublicKey {
    /// encapsulate: generate an ephemeral shared secret + capsule.
    fn encapsulate<R>(&self, rng: &mut R) -> Result<(Capsule, SharedSecret), Error>
    where
        R: rand_core::CryptoRng + rand_core::RngCore,
    {
        let x_ephemeral = EphemeralSecret::random_from_rng(&mut *rng);
        let x_ephemeral_pk = X25519PublicKey::from(&x_ephemeral);
        let x_shared = x_ephemeral.diffie_hellman(&self.x25519);

        if !x_shared.was_contributory() {
            return Err(Error::EncryptionFailed);
        }

        let (mlkem_ct, mlkem_shared) = self.mlkem_ek.encapsulate(rng)
            .map_err(|_| Error::EncryptionFailed)?;

        let combined = Sha512::new()
            .chain_update(b"falconed-hybrid-kem")
            .chain_update(x_shared.as_bytes())
            .chain_update(&mlkem_shared)
            .chain_update(x_ephemeral_pk.as_bytes())
            .chain_update(self.x25519.as_bytes())
            .chain_update(self.mlkem_ek.as_bytes().as_slice())
            .chain_update(mlkem_ct.as_slice())
            .finalize();

        let mut secret = [0u8; SHARED_SECRET_SIZE];
        secret.copy_from_slice(&combined[..32]);

        let capsule = Capsule {
            x25519_ephemeral: x_ephemeral_pk,
            mlkem_ciphertext: mlkem_ct,
        };

        Ok((capsule, SharedSecret(secret)))
    }

    /// serialize the encryption public key to bytes.
    ///
    /// format: `x25519_pk (32) || mlkem_ek`
    pub fn to_bytes(&self) -> [u8; ENCRYPTION_PUBLIC_KEY_SIZE] {
        let mut out = [0u8; ENCRYPTION_PUBLIC_KEY_SIZE];
        out[..X25519_PUBLIC_KEY_SIZE].copy_from_slice(self.x25519.as_bytes());
        let ek_bytes = self.mlkem_ek.as_bytes();
        out[X25519_PUBLIC_KEY_SIZE..].copy_from_slice(ek_bytes.as_slice());
        out
    }

    /// deserialize an encryption public key from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != ENCRYPTION_PUBLIC_KEY_SIZE {
            return Err(Error::InvalidLength);
        }

        let mut x_bytes = [0u8; 32];
        x_bytes.copy_from_slice(&bytes[..X25519_PUBLIC_KEY_SIZE]);
        let x25519 = X25519PublicKey::from(x_bytes);

        let ek_bytes = &bytes[X25519_PUBLIC_KEY_SIZE..];
        let ek_encoded: &ml_kem::Encoded<MlKemEk> =
            ek_bytes.try_into().map_err(|_| Error::InvalidLength)?;
        let mlkem_ek = MlKemEk::from_bytes(ek_encoded);

        // validate: re-encode and check round-trip consistency
        if mlkem_ek.as_bytes() != *ek_encoded {
            return Err(Error::InvalidLength);
        }

        Ok(Self { x25519, mlkem_ek })
    }
}

impl core::fmt::Display for EncryptionPublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for byte in &self.to_bytes() {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

// --- Capsule ---

impl Capsule {
    /// serialize the capsule to bytes.
    ///
    /// format: `x25519_ephemeral_pk (32) || mlkem_ciphertext`
    pub fn to_bytes(&self) -> [u8; CAPSULE_SIZE] {
        let mut out = [0u8; CAPSULE_SIZE];
        out[..X25519_PUBLIC_KEY_SIZE].copy_from_slice(self.x25519_ephemeral.as_bytes());
        out[X25519_PUBLIC_KEY_SIZE..].copy_from_slice(self.mlkem_ciphertext.as_slice());
        out
    }

    /// deserialize a capsule from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != CAPSULE_SIZE {
            return Err(Error::InvalidLength);
        }

        let mut x_bytes = [0u8; 32];
        x_bytes.copy_from_slice(&bytes[..X25519_PUBLIC_KEY_SIZE]);
        let x25519_ephemeral = X25519PublicKey::from(x_bytes);

        let ct_bytes = &bytes[X25519_PUBLIC_KEY_SIZE..];
        let mlkem_ciphertext = ct_bytes.try_into().map_err(|_| Error::InvalidLength)?;

        Ok(Self {
            x25519_ephemeral,
            mlkem_ciphertext,
        })
    }
}

// --- EncryptedMessage ---

impl EncryptedMessage {
    /// serialize to bytes.
    ///
    /// format: `capsule || nonce (12) || key_commitment (32) || aead_ciphertext`
    pub fn to_bytes(&self) -> Vec<u8> {
        let capsule_bytes = self.capsule.to_bytes();
        let mut out = Vec::with_capacity(
            CAPSULE_SIZE + NONCE_SIZE + KEY_COMMITMENT_SIZE + self.ciphertext.len(),
        );
        out.extend_from_slice(&capsule_bytes);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.key_commitment);
        out.extend_from_slice(&self.ciphertext);
        out
    }

    /// deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let min_size = CAPSULE_SIZE + NONCE_SIZE + KEY_COMMITMENT_SIZE + TAG_SIZE;
        if bytes.len() < min_size {
            return Err(Error::InvalidLength);
        }

        let capsule = Capsule::from_bytes(&bytes[..CAPSULE_SIZE])?;

        let nonce_start = CAPSULE_SIZE;
        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(&bytes[nonce_start..nonce_start + NONCE_SIZE]);

        let commit_start = nonce_start + NONCE_SIZE;
        let mut kc = [0u8; KEY_COMMITMENT_SIZE];
        kc.copy_from_slice(&bytes[commit_start..commit_start + KEY_COMMITMENT_SIZE]);

        let ciphertext = bytes[commit_start + KEY_COMMITMENT_SIZE..].to_vec();

        Ok(Self { capsule, nonce, key_commitment: kc, ciphertext })
    }
}

// --- seal / open ---

/// encrypt a message to a recipient's encryption public key.
///
/// performs hybrid KEM (x25519 + ml-kem-768) to establish a shared secret,
/// then encrypts the plaintext with ChaCha20-Poly1305.
///
/// returns an [`EncryptedMessage`] containing everything the recipient needs to decrypt.
pub fn seal<R>(
    rng: &mut R,
    recipient: &EncryptionPublicKey,
    plaintext: &[u8],
) -> Result<EncryptedMessage, Error>
where
    R: rand_core::CryptoRng + rand_core::RngCore,
{
    let (capsule, secret) = recipient.encapsulate(rng)?;

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    rng.fill_bytes(&mut nonce_bytes);

    let capsule_bytes = capsule.to_bytes();
    let kc = key_commitment(&secret.0, &nonce_bytes, &capsule_bytes);

    let cipher = ChaCha20Poly1305::new_from_slice(&secret.0)
        .map_err(|_| Error::InvalidLength)?;
    // secret is zeroized on drop

    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, plaintext)
        .map_err(|_| Error::EncryptionFailed)?;

    Ok(EncryptedMessage {
        capsule,
        nonce: nonce_bytes,
        key_commitment: kc,
        ciphertext,
    })
}

/// decrypt a message using the recipient's viewing key.
///
/// decapsulates the hybrid KEM to recover the shared secret,
/// verifies the key commitment, then decrypts with ChaCha20-Poly1305.
///
/// returns the plaintext on success.
pub fn open(
    viewing_key: &ViewingKey,
    message: &EncryptedMessage,
) -> Result<Vec<u8>, Error> {
    let secret = viewing_key.decapsulate(&message.capsule)?;

    let capsule_bytes = message.capsule.to_bytes();
    let expected_kc = key_commitment(&secret.0, &message.nonce, &capsule_bytes);
    if expected_kc != message.key_commitment {
        return Err(Error::DecryptionFailed);
    }

    let cipher = ChaCha20Poly1305::new_from_slice(&secret.0)
        .map_err(|_| Error::InvalidLength)?;
    // secret is zeroized on drop

    let nonce = Nonce::from_slice(&message.nonce);

    cipher.decrypt(nonce, message.ciphertext.as_slice())
        .map_err(|_| Error::DecryptionFailed)
}

// --- tests ---

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn viewing_key_from_seed_deterministic() {
        let seed = [42u8; SEED_SIZE];
        let vk1 = ViewingKey::from_seed(&seed);
        let vk2 = ViewingKey::from_seed(&seed);
        assert_eq!(vk1.to_bytes(), vk2.to_bytes());
    }

    #[test]
    fn different_seeds_different_keys() {
        let vk1 = ViewingKey::from_seed(&[1u8; SEED_SIZE]);
        let vk2 = ViewingKey::from_seed(&[2u8; SEED_SIZE]);
        assert_ne!(vk1.to_bytes(), vk2.to_bytes());
    }

    #[test]
    fn seal_open_roundtrip() {
        let mut rng = rand_core::OsRng;
        let seed = [42u8; SEED_SIZE];
        let vk = ViewingKey::from_seed(&seed);
        let epk = vk.encryption_public_key();

        let plaintext = b"post-quantum hello world";
        let encrypted = seal(&mut rng, &epk, plaintext).unwrap();
        let decrypted = open(&vk, &encrypted).unwrap();

        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn seal_open_empty_message() {
        let mut rng = rand_core::OsRng;
        let vk = ViewingKey::from_seed(&[11u8; SEED_SIZE]);
        let epk = vk.encryption_public_key();

        let encrypted = seal(&mut rng, &epk, b"").unwrap();
        let decrypted = open(&vk, &encrypted).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn seal_wrong_viewing_key_fails() {
        let mut rng = rand_core::OsRng;
        let vk1 = ViewingKey::from_seed(&[1u8; SEED_SIZE]);
        let vk2 = ViewingKey::from_seed(&[2u8; SEED_SIZE]);
        let epk = vk1.encryption_public_key();

        let encrypted = seal(&mut rng, &epk, b"secret").unwrap();
        let result = open(&vk2, &encrypted);
        assert_eq!(result, Err(Error::DecryptionFailed));
    }

    #[test]
    fn signing_and_viewing_keys_independent() {
        let seed = [77u8; SEED_SIZE];
        let sk = crate::SigningKey::from_seed(&seed);
        let vk = ViewingKey::from_seed(&seed);

        let sk_bytes = sk.to_bytes();
        let vk_bytes = vk.to_bytes();
        assert_ne!(&sk_bytes[..32], &vk_bytes[..32]);
    }

    #[test]
    fn serialization_roundtrip_viewing_key() {
        let vk = ViewingKey::from_seed(&[55u8; SEED_SIZE]);
        let bytes = vk.to_bytes();
        let vk2 = ViewingKey::from_bytes(&bytes).unwrap();
        assert_eq!(vk.to_bytes(), vk2.to_bytes());
    }

    #[test]
    fn serialization_roundtrip_encryption_public_key() {
        let vk = ViewingKey::from_seed(&[55u8; SEED_SIZE]);
        let epk = vk.encryption_public_key();
        let bytes = epk.to_bytes();
        let epk2 = EncryptionPublicKey::from_bytes(&bytes).unwrap();
        assert_eq!(epk.to_bytes(), epk2.to_bytes());
    }

    #[test]
    fn encrypted_message_serialization_roundtrip() {
        let mut rng = rand_core::OsRng;
        let vk = ViewingKey::from_seed(&[33u8; SEED_SIZE]);
        let epk = vk.encryption_public_key();

        let plaintext = b"roundtrip through bytes";
        let encrypted = seal(&mut rng, &epk, plaintext).unwrap();
        let bytes = encrypted.to_bytes();
        let encrypted2 = EncryptedMessage::from_bytes(&bytes).unwrap();
        let decrypted = open(&vk, &encrypted2).unwrap();

        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn fixed_size_to_bytes() {
        let vk = ViewingKey::from_seed(&[1u8; SEED_SIZE]);
        let vk_bytes: [u8; VIEWING_KEY_SIZE] = vk.to_bytes();
        assert_eq!(vk_bytes.len(), VIEWING_KEY_SIZE);

        let epk = vk.encryption_public_key();
        let epk_bytes: [u8; ENCRYPTION_PUBLIC_KEY_SIZE] = epk.to_bytes();
        assert_eq!(epk_bytes.len(), ENCRYPTION_PUBLIC_KEY_SIZE);
    }

    #[test]
    fn capsule_to_bytes_is_fixed_size() {
        let mut rng = rand_core::OsRng;
        let vk = ViewingKey::from_seed(&[1u8; SEED_SIZE]);
        let epk = vk.encryption_public_key();
        let encrypted = seal(&mut rng, &epk, b"test").unwrap();
        let capsule_bytes: [u8; CAPSULE_SIZE] = encrypted.capsule.to_bytes();
        assert_eq!(capsule_bytes.len(), CAPSULE_SIZE);
    }

    #[test]
    fn encryption_public_key_equality() {
        let vk = ViewingKey::from_seed(&[1u8; SEED_SIZE]);
        let epk1 = vk.encryption_public_key();
        let epk2 = vk.encryption_public_key();
        assert_eq!(epk1, epk2);

        let vk2 = ViewingKey::from_seed(&[2u8; SEED_SIZE]);
        let epk3 = vk2.encryption_public_key();
        assert_ne!(epk1, epk3);
    }

    #[test]
    fn encryption_public_key_display() {
        use alloc::format;
        let vk = ViewingKey::from_seed(&[1u8; SEED_SIZE]);
        let epk = vk.encryption_public_key();
        let hex = format!("{}", epk);
        assert_eq!(hex.len(), ENCRYPTION_PUBLIC_KEY_SIZE * 2);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    // --- rejection tests ---

    #[test]
    fn from_bytes_rejects_truncated_viewing_key() {
        let vk = ViewingKey::from_seed(&[55u8; SEED_SIZE]);
        let bytes = vk.to_bytes();
        assert!(matches!(ViewingKey::from_bytes(&bytes[..bytes.len() - 1]), Err(Error::InvalidLength)));
        let mut extended = bytes.to_vec();
        extended.push(0);
        assert!(matches!(ViewingKey::from_bytes(&extended), Err(Error::InvalidLength)));
        assert!(matches!(ViewingKey::from_bytes(&[]), Err(Error::InvalidLength)));
    }

    #[test]
    fn from_bytes_rejects_truncated_encryption_public_key() {
        let vk = ViewingKey::from_seed(&[55u8; SEED_SIZE]);
        let epk = vk.encryption_public_key();
        let bytes = epk.to_bytes();
        assert!(matches!(EncryptionPublicKey::from_bytes(&bytes[..bytes.len() - 1]), Err(Error::InvalidLength)));
        let mut extended = bytes.to_vec();
        extended.push(0);
        assert!(matches!(EncryptionPublicKey::from_bytes(&extended), Err(Error::InvalidLength)));
    }

    #[test]
    fn from_bytes_rejects_truncated_capsule() {
        let mut rng = rand_core::OsRng;
        let vk = ViewingKey::from_seed(&[55u8; SEED_SIZE]);
        let epk = vk.encryption_public_key();
        let encrypted = seal(&mut rng, &epk, b"test").unwrap();
        let bytes = encrypted.capsule.to_bytes();
        assert!(matches!(Capsule::from_bytes(&bytes[..bytes.len() - 1]), Err(Error::InvalidLength)));
        let mut extended = bytes.to_vec();
        extended.push(0);
        assert!(matches!(Capsule::from_bytes(&extended), Err(Error::InvalidLength)));
    }

    #[test]
    fn from_bytes_rejects_truncated_encrypted_message() {
        use alloc::vec;
        let min_size = CAPSULE_SIZE + NONCE_SIZE + KEY_COMMITMENT_SIZE + TAG_SIZE;
        assert!(matches!(EncryptedMessage::from_bytes(&vec![0u8; min_size - 1]), Err(Error::InvalidLength)));
    }

    // --- tamper tests ---

    #[test]
    fn tampered_ciphertext_fails() {
        let mut rng = rand_core::OsRng;
        let vk = ViewingKey::from_seed(&[44u8; SEED_SIZE]);
        let epk = vk.encryption_public_key();

        let encrypted = seal(&mut rng, &epk, b"do not tamper").unwrap();
        let mut bytes = encrypted.to_bytes();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        let tampered = EncryptedMessage::from_bytes(&bytes).unwrap();
        assert_eq!(open(&vk, &tampered), Err(Error::DecryptionFailed));
    }

    #[test]
    fn tampered_capsule_x25519_fails_decryption() {
        let mut rng = rand_core::OsRng;
        let vk = ViewingKey::from_seed(&[66u8; SEED_SIZE]);
        let epk = vk.encryption_public_key();

        let encrypted = seal(&mut rng, &epk, b"test").unwrap();
        let mut bytes = encrypted.to_bytes();
        bytes[0] ^= 0x01;
        let tampered = EncryptedMessage::from_bytes(&bytes).unwrap();
        assert_eq!(open(&vk, &tampered), Err(Error::DecryptionFailed));
    }

    #[test]
    fn tampered_capsule_mlkem_fails_decryption() {
        let mut rng = rand_core::OsRng;
        let vk = ViewingKey::from_seed(&[77u8; SEED_SIZE]);
        let epk = vk.encryption_public_key();

        let encrypted = seal(&mut rng, &epk, b"test").unwrap();
        let mut bytes = encrypted.to_bytes();
        bytes[33] ^= 0x01;
        let tampered = EncryptedMessage::from_bytes(&bytes).unwrap();
        assert_eq!(open(&vk, &tampered), Err(Error::DecryptionFailed));
    }

    #[test]
    fn tampered_key_commitment_fails() {
        let mut rng = rand_core::OsRng;
        let vk = ViewingKey::from_seed(&[55u8; SEED_SIZE]);
        let epk = vk.encryption_public_key();

        let encrypted = seal(&mut rng, &epk, b"commitment test").unwrap();
        let mut bytes = encrypted.to_bytes();
        bytes[CAPSULE_SIZE + NONCE_SIZE] ^= 0x01;
        let tampered = EncryptedMessage::from_bytes(&bytes).unwrap();
        assert_eq!(open(&vk, &tampered), Err(Error::DecryptionFailed));
    }

    #[test]
    fn tampered_nonce_fails_decryption() {
        let mut rng = rand_core::OsRng;
        let vk = ViewingKey::from_seed(&[88u8; SEED_SIZE]);
        let epk = vk.encryption_public_key();

        let encrypted = seal(&mut rng, &epk, b"test").unwrap();
        let mut bytes = encrypted.to_bytes();
        bytes[CAPSULE_SIZE] ^= 0x01;
        let tampered = EncryptedMessage::from_bytes(&bytes).unwrap();
        assert_eq!(open(&vk, &tampered), Err(Error::DecryptionFailed));
    }

    // --- pinned test vector ---

    #[test]
    fn deterministic_keygen_test_vector() {
        // pinned test vector: if this fails after a dependency upgrade,
        // seed -> key derivation has changed. this is a breaking change.
        let seed = [0xABu8; SEED_SIZE];
        let vk = ViewingKey::from_seed(&seed);
        let bytes = vk.to_bytes();

        assert_eq!(&bytes[..8], &[0xa0, 0xd6, 0x6f, 0x42, 0xd6, 0x46, 0x5f, 0x6e]);
        assert_eq!(&bytes[bytes.len() - 8..], &[0x2c, 0x8d, 0x50, 0x83, 0x7b, 0xb1, 0x34, 0xe6]);

        let epk = vk.encryption_public_key();
        let epk_bytes = epk.to_bytes();
        assert_eq!(&epk_bytes[..8], &[0xf0, 0x3a, 0xda, 0xe7, 0x69, 0xad, 0x9c, 0x01]);
    }

    #[test]
    fn key_commitment_prevents_wrong_key_decrypt() {
        let mut rng = rand_core::OsRng;
        let vk1 = ViewingKey::from_seed(&[1u8; SEED_SIZE]);
        let vk2 = ViewingKey::from_seed(&[2u8; SEED_SIZE]);
        let epk = vk1.encryption_public_key();

        let encrypted = seal(&mut rng, &epk, b"committed").unwrap();
        let result = open(&vk2, &encrypted);
        assert_eq!(result, Err(Error::DecryptionFailed));
    }
}

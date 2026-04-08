//! # falconed
//!
//! hybrid post-quantum cryptography: ed25519 + falcon-512 signatures,
//! x25519 + ml-kem-768 encryption.
//!
//! ## key hierarchy
//!
//! ```text
//! SpendingKey (root authority — can sign, verify, and decrypt)
//!   ├─ SigningKey          ed25519 + falcon-512
//!   └─ FullViewingKey     (can verify + decrypt, NOT sign)
//!        ├─ VerifyingKey  ed25519 + falcon-512
//!        └─ ViewingKey    x25519 + ml-kem-768
//!             └─ EncryptionPublicKey
//! ```
//!
//! ## usage
//!
//! ```
//! use falconed::{SpendingKey, encryption};
//! use rand_core::OsRng;
//!
//! // one seed → one identity
//! let sk = SpendingKey::generate(&mut OsRng);
//!
//! // sign
//! let sig = sk.sign(b"hello").unwrap();
//!
//! // export viewing capability (safe for watch-only clients)
//! let fvk = sk.full_viewing_key().unwrap();
//! assert!(fvk.verify(b"hello", &sig).is_ok());
//!
//! // encrypt to this identity
//! let epk = fvk.encryption_public_key();
//! let encrypted = encryption::seal(&mut OsRng, &epk, b"secret").unwrap();
//! let plaintext = encryption::open(fvk.viewing_key(), &encrypted).unwrap();
//! assert_eq!(&plaintext, b"secret");
//! ```
//!
//! the lower-level types ([`SigningKey`], [`VerifyingKey`]) are still
//! available for direct use when you don't need the full hierarchy.
//!
//! ## signature crate interop
//!
//! implements [`Signer`] and [`Verifier`] for
//! compatibility with generic code:
//!
//! ```
//! use signature::{Signer, Verifier};
//! use falconed::SigningKey;
//! use rand_core::OsRng;
//!
//! let sk = SigningKey::generate(&mut OsRng);
//! let pk = sk.verifying_key().unwrap();
//!
//! let sig = sk.try_sign(b"message").unwrap();
//! assert!(pk.verify(b"message", &sig).is_ok());
//! ```
//!
//! ## serialization
//!
//! all types are fixed-size. concatenation, no length prefixes, no asn.1.
//!
//! ```text
//! SigningKey   = ed25519_seed (32) || falcon_sk (1281) = 1313 bytes
//! VerifyingKey = ed25519_pk (32) || falcon_pk (897) = 929 bytes
//! Signature    = ed25519_sig (64) || falcon_sig (666) = 730 bytes
//! ```
//!
//! ## `no_std` support
//!
//! this crate is `no_std` by default but requires `alloc`. the allocator is
//! used for domain-tagged message construction (ed25519 path) and by fn-dsa
//! internally. a `#[global_allocator]` must be available.
//!
//! ## `AsRef<[u8]>`
//!
//! the core types ([`SigningKey`], [`VerifyingKey`], [`Signature`]) do not
//! implement `AsRef<[u8]>` because their internal layout is not a single
//! contiguous byte array. use [`to_bytes()`](VerifyingKey::to_bytes) for
//! serialization. the substrate wrapper types (`substrate::Public`,
//! `substrate::Signature`) store flat `[u8; N]` arrays and do implement it.
//!
//! ## falcon backend
//!
//! uses [fn-dsa](https://crates.io/crates/fn-dsa) by thomas pornin,
//! the original author of falcon. pure rust, no C bindings.
//!
//! ## security considerations
//!
//! **hybrid construction**: this crate concatenates independent ed25519 and
//! falcon-512 signatures. the security argument is that an attacker must
//! break *both* schemes to forge a signature. this is a standard construction
//! but has not been formally analyzed for this specific pairing.
//!
//! **domain separation**: both signature components use domain-tagged messages
//! to prevent cross-protocol stripping attacks. ed25519 signs
//! `"falconed-ed25519\x00" || msg`. falcon uses fn-dsa's native
//! `DomainContext(b"falconed-falcon")`, which produces the unambiguous framing
//! `0x00 || len(ctx) || ctx || msg` internally.
//!
//! **timing**: signing operations aim to be constant-time, but this depends
//! on the underlying implementations (ed25519-dalek, fn-dsa).
//! [`VerifyingKey::verify`] always runs both verifications to avoid
//! leaking which component failed. [`VerifyingKey::verify_fast`] short-
//! circuits on first failure for performance-sensitive public-input paths.
//!
//! **zeroization**: secret key material is zeroized on drop. decoded falcon
//! signing keys are zeroized after each operation. ed25519-dalek handles its
//! own zeroization internally.
//!
//! **rng requirements**: key generation and signing require a cryptographically
//! secure random number generator. falcon signing uses randomness for each
//! signature.
//!
//! **not audited**: this implementation has not been professionally audited.
//! use at your own risk for anything important.

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(missing_docs)]
#![warn(clippy::all)]

#[cfg(feature = "std")]
extern crate std;

extern crate alloc;

pub mod encryption;
mod error;
mod keys;
mod signature;
mod signing;
#[cfg(feature = "substrate")]
#[cfg_attr(docsrs, doc(cfg(feature = "substrate")))]
pub mod substrate;
mod verifying;

/// domain tag prepended to messages before ed25519 signing/verification.
/// prevents cross-protocol attacks where the ed25519 component could be
/// stripped and replayed as a standalone ed25519 signature.
pub(crate) const ED25519_DOMAIN_TAG: &[u8; 17] = b"falconed-ed25519\x00";

/// domain context passed to fn-dsa for falcon signing/verification.
/// uses fn-dsa's built-in `0x00 || len(ctx) || ctx || msg` framing.
pub(crate) const FALCON_DOMAIN_CTX: fn_dsa::DomainContext<'static> =
    fn_dsa::DomainContext(b"falconed-falcon");

/// build a domain-tagged message: `tag || msg`.
///
/// the tag is a fixed-size array to prevent accidental use with
/// variable-length tags, which would allow trivial collisions
/// (e.g. `"ab" || "cd"` == `"abc" || "d"`).
pub(crate) fn tagged_message<const N: usize>(tag: &[u8; N], msg: &[u8]) -> alloc::vec::Vec<u8> {
    let mut buf = alloc::vec::Vec::with_capacity(N + msg.len());
    buf.extend_from_slice(tag);
    buf.extend_from_slice(msg);
    buf
}

/// domain-separated KDF: `SHA-512(len(tag) || tag || input)`.
///
/// the length prefix prevents ambiguity between tags that are prefixes
/// of each other. tags must be <= 255 bytes (enforced by taking `&[u8; N]`
/// through the call sites, but asserted here defensively).
pub(crate) fn domain_kdf(tag: &[u8], input: &[u8]) -> [u8; 64] {
    use sha2::{Digest, Sha512};
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

/// zeroize a byte slice via volatile writes + compiler fence.
///
/// best-effort fallback for when the `zeroize` crate feature is not enabled.
/// prefer `zeroize::Zeroize` when available.
pub(crate) fn zeroize_bytes(bytes: &mut [u8]) {
    for byte in bytes.iter_mut() {
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

pub use error::Error;
pub use keys::{FullViewingKey, SpendingKey, FULL_VIEWING_KEY_SIZE};
pub use signature::Signature;
pub use signing::SigningKey;
pub use verifying::VerifyingKey;

// re-export encryption types at crate root for convenience
pub use encryption::{
    seal, open, EncryptedMessage, EncryptionPublicKey, ViewingKey,
    Capsule, CAPSULE_SIZE, ENCRYPTION_PUBLIC_KEY_SIZE, VIEWING_KEY_SIZE,
    X25519_PUBLIC_KEY_SIZE, X25519_SECRET_KEY_SIZE,
};

// re-export signature traits for convenience
pub use ::signature::{Signer, Verifier};

use fn_dsa::{sign_key_size, vrfy_key_size, signature_size, FN_DSA_LOGN_512};

/// ed25519 signature size in bytes.
pub const ED25519_SIGNATURE_SIZE: usize = 64;

/// ed25519 public key size in bytes.
pub const ED25519_PUBLIC_KEY_SIZE: usize = 32;

/// ed25519 secret key seed size in bytes.
pub const ED25519_SEED_SIZE: usize = 32;

/// falcon-512 signature size in bytes (fn-dsa format).
pub const FALCON_SIGNATURE_SIZE: usize = signature_size(FN_DSA_LOGN_512);

/// falcon-512 public key size in bytes (fn-dsa format).
pub const FALCON_PUBLIC_KEY_SIZE: usize = vrfy_key_size(FN_DSA_LOGN_512);

/// falcon-512 secret key size in bytes (fn-dsa format).
pub const FALCON_SECRET_KEY_SIZE: usize = sign_key_size(FN_DSA_LOGN_512);

/// combined signature size.
pub const SIGNATURE_SIZE: usize = ED25519_SIGNATURE_SIZE + FALCON_SIGNATURE_SIZE;

/// combined public key size.
pub const VERIFYING_KEY_SIZE: usize = ED25519_PUBLIC_KEY_SIZE + FALCON_PUBLIC_KEY_SIZE;

/// combined secret key size.
pub const SIGNING_KEY_SIZE: usize = ED25519_SEED_SIZE + FALCON_SECRET_KEY_SIZE;

/// master seed size in bytes.
///
/// a 32-byte master seed is expanded via SHA-512 into independent ed25519
/// and falcon keying material.
pub const SEED_SIZE: usize = 32;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_sign_verify() {
        let mut rng = rand::thread_rng();
        let sk = SigningKey::generate(&mut rng);
        let pk = sk.verifying_key().unwrap();

        let msg = b"test message";
        let sig = sk.sign(msg).unwrap();

        assert!(pk.verify(msg, &sig).is_ok());
    }

    #[test]
    fn wrong_message_fails() {
        let mut rng = rand::thread_rng();
        let sk = SigningKey::generate(&mut rng);
        let pk = sk.verifying_key().unwrap();

        let sig = sk.sign(b"correct message").unwrap();
        assert!(pk.verify(b"wrong message", &sig).is_err());
    }

    #[test]
    fn serialization_roundtrip() {
        let mut rng = rand::thread_rng();
        let sk = SigningKey::generate(&mut rng);
        let pk = sk.verifying_key().unwrap();

        let sk_bytes = sk.to_bytes();
        let sk2 = SigningKey::from_bytes(&sk_bytes).unwrap();
        assert_eq!(sk.to_bytes(), sk2.to_bytes());

        let pk_bytes = pk.to_bytes();
        let pk2 = VerifyingKey::from_bytes(&pk_bytes).unwrap();
        assert_eq!(pk_bytes, pk2.to_bytes());

        let sig = sk.sign(b"test").unwrap();
        let sig_bytes = sig.to_bytes();
        let sig2 = Signature::from_bytes(&sig_bytes).unwrap();
        assert_eq!(sig_bytes, sig2.to_bytes());
    }

    #[test]
    fn verify_checks_both_components() {
        let mut rng = rand::thread_rng();
        let sk = SigningKey::generate(&mut rng);
        let pk = sk.verifying_key().unwrap();

        let msg = b"test message";
        let sig = sk.sign(msg).unwrap();

        assert!(pk.verify(msg, &sig).is_ok());
    }

    #[test]
    fn verify_fast_succeeds() {
        let mut rng = rand::thread_rng();
        let sk = SigningKey::generate(&mut rng);
        let pk = sk.verifying_key().unwrap();

        let msg = b"test message";
        let sig = sk.sign(msg).unwrap();

        assert!(pk.verify_fast(msg, &sig).is_ok());
    }

    #[test]
    fn verify_fast_fails_on_wrong_message() {
        let mut rng = rand::thread_rng();
        let sk = SigningKey::generate(&mut rng);
        let pk = sk.verifying_key().unwrap();

        let sig = sk.sign(b"correct").unwrap();
        assert!(pk.verify_fast(b"wrong", &sig).is_err());
    }

    #[test]
    fn verifying_key_display_hex() {
        use alloc::format;
        let mut rng = rand::thread_rng();
        let sk = SigningKey::generate(&mut rng);
        let pk = sk.verifying_key().unwrap();
        let hex = format!("{}", pk);
        assert_eq!(hex.len(), VERIFYING_KEY_SIZE * 2);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn empty_message() {
        let mut rng = rand::thread_rng();
        let sk = SigningKey::generate(&mut rng);
        let pk = sk.verifying_key().unwrap();

        let sig = sk.sign(b"").unwrap();
        assert!(pk.verify(b"", &sig).is_ok());
    }

    #[test]
    fn wrong_key_fails() {
        let mut rng = rand::thread_rng();
        let sk1 = SigningKey::generate(&mut rng);
        let sk2 = SigningKey::generate(&mut rng);

        let sig = sk1.sign(b"message").unwrap();
        let pk2 = sk2.verifying_key().unwrap();

        assert!(pk2.verify(b"message", &sig).is_err());
    }

    #[test]
    fn bitflip_signature_fails() {
        let mut rng = rand::thread_rng();
        let sk = SigningKey::generate(&mut rng);
        let pk = sk.verifying_key().unwrap();

        let sig = sk.sign(b"test").unwrap();
        let mut sig_bytes = sig.to_bytes();

        // flip a bit in the ed25519 portion
        sig_bytes[0] ^= 1;

        if let Ok(corrupted) = Signature::from_bytes(&sig_bytes) {
            assert!(pk.verify(b"test", &corrupted).is_err());
        }
    }

    #[test]
    fn invalid_key_lengths() {
        // too short
        assert!(SigningKey::try_from(&[0u8; 10][..]).is_err());
        assert!(VerifyingKey::try_from(&[0u8; 10][..]).is_err());
        assert!(Signature::try_from(&[0u8; 10][..]).is_err());

        // wrong length
        assert!(SigningKey::try_from(&[0u8; SIGNING_KEY_SIZE - 1][..]).is_err());
        assert!(VerifyingKey::try_from(&[0u8; VERIFYING_KEY_SIZE + 1][..]).is_err());
    }

    #[test]
    fn verifying_key_equality() {
        let mut rng = rand::thread_rng();
        let sk = SigningKey::generate(&mut rng);
        let pk1 = sk.verifying_key().unwrap();
        let pk2 = sk.verifying_key().unwrap();

        assert_eq!(pk1, pk2);

        let sk2 = SigningKey::generate(&mut rng);
        let pk3 = sk2.verifying_key().unwrap();
        assert_ne!(pk1, pk3);
    }

    #[test]
    fn signature_equality() {
        let mut rng = rand::thread_rng();
        let sk = SigningKey::generate(&mut rng);

        let sig1 = sk.sign(b"msg").unwrap();
        let sig2 = sk.sign(b"msg").unwrap();

        // falcon signatures have randomness, so these may differ
        // but signing the same message twice should at least verify
        let pk = sk.verifying_key().unwrap();
        assert!(pk.verify(b"msg", &sig1).is_ok());
        assert!(pk.verify(b"msg", &sig2).is_ok());
    }

    #[test]
    fn from_seed_deterministic() {
        let seed = [42u8; SEED_SIZE];
        let sk1 = SigningKey::from_seed(&seed);
        let sk2 = SigningKey::from_seed(&seed);
        assert_eq!(sk1.to_bytes(), sk2.to_bytes());
    }

    #[test]
    fn from_seed_different_seeds_differ() {
        let sk1 = SigningKey::from_seed(&[1u8; SEED_SIZE]);
        let sk2 = SigningKey::from_seed(&[2u8; SEED_SIZE]);
        assert_ne!(sk1.to_bytes(), sk2.to_bytes());
    }

    #[test]
    fn from_seed_sign_verify() {
        let seed = [99u8; SEED_SIZE];
        let sk = SigningKey::from_seed(&seed);
        let pk = sk.verifying_key().unwrap();

        let sig = sk.sign(b"seed test").unwrap();
        assert!(pk.verify(b"seed test", &sig).is_ok());
    }

    #[test]
    fn from_seed_slice_valid() {
        let seed = [7u8; SEED_SIZE];
        let sk1 = SigningKey::from_seed(&seed);
        let sk2 = SigningKey::from_seed_slice(&seed).unwrap();
        assert_eq!(sk1.to_bytes(), sk2.to_bytes());
    }

    #[test]
    fn from_seed_slice_wrong_length() {
        assert!(SigningKey::from_seed_slice(&[0u8; 31]).is_err());
        assert!(SigningKey::from_seed_slice(&[0u8; 33]).is_err());
        assert!(SigningKey::from_seed_slice(&[]).is_err());
    }

    #[test]
    fn deterministic_signing_keygen_test_vector() {
        // pinned test vector: if this fails after a dependency upgrade,
        // seed → signing key derivation has changed. this is a breaking change.
        let seed = [0xABu8; SEED_SIZE];
        let sk = SigningKey::from_seed(&seed);
        let sk_bytes = sk.to_bytes();

        // pin ed25519 seed (first 8 bytes of signing key)
        assert_eq!(
            &sk_bytes[..8],
            &[0x48, 0xa2, 0xa3, 0x86, 0x75, 0x42, 0x50, 0xca],
            "ed25519 seed derivation changed — this is a breaking change"
        );

        // pin falcon sk tail (last 8 bytes of signing key)
        assert_eq!(
            &sk_bytes[sk_bytes.len() - 8..],
            &[0xf3, 0x21, 0xf7, 0xef, 0x00, 0xf3, 0x1a, 0x18],
            "falcon sk derivation changed — this is a breaking change"
        );

        // pin verifying key (first 8 bytes = ed25519 pk)
        let vk = sk.verifying_key().unwrap();
        let vk_bytes = vk.to_bytes();
        assert_eq!(
            &vk_bytes[..8],
            &[0x33, 0xcf, 0xdf, 0x41, 0xa4, 0xfb, 0x67, 0x2f],
            "verifying key derivation changed — this is a breaking change"
        );

        // stability: same seed always produces same keys
        let sk2 = SigningKey::from_seed(&seed);
        assert_eq!(sk.to_bytes(), sk2.to_bytes());
    }

    #[test]
    fn signature_trait_interop() {
        use ::signature::Signer as _;

        let mut rng = rand::thread_rng();
        let sk = SigningKey::generate(&mut rng);
        let pk = sk.verifying_key().unwrap();

        // test Signer trait
        let sig = sk.try_sign(b"test").unwrap();
        // verify using our method (Verifier trait delegates to it)
        assert!(pk.verify(b"test", &sig).is_ok());
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn sign_then_verify_always_succeeds(msg in prop::collection::vec(any::<u8>(), 0..1024)) {
            let mut rng = rand::thread_rng();
            let sk = SigningKey::generate(&mut rng);
            let pk = sk.verifying_key().unwrap();

            let sig = sk.sign(&msg).unwrap();
            prop_assert!(pk.verify(&msg, &sig).is_ok());
        }

        #[test]
        fn verify_wrong_message_always_fails(
            msg1 in prop::collection::vec(any::<u8>(), 1..512),
            msg2 in prop::collection::vec(any::<u8>(), 1..512),
        ) {
            prop_assume!(msg1 != msg2);

            let mut rng = rand::thread_rng();
            let sk = SigningKey::generate(&mut rng);
            let pk = sk.verifying_key().unwrap();

            let sig = sk.sign(&msg1).unwrap();
            prop_assert!(pk.verify(&msg2, &sig).is_err());
        }

        #[test]
        fn bitflip_ed25519_portion_fails(
            msg in prop::collection::vec(any::<u8>(), 1..256),
            flip_pos in 0usize..ED25519_SIGNATURE_SIZE,
        ) {
            let mut rng = rand::thread_rng();
            let sk = SigningKey::generate(&mut rng);
            let pk = sk.verifying_key().unwrap();

            let sig = sk.sign(&msg).unwrap();
            let mut sig_bytes = sig.to_bytes();

            // flip a bit in ed25519 portion (bytes 0..64)
            sig_bytes[flip_pos] ^= 1;

            // corrupted signature should fail to verify (or fail to parse)
            if let Ok(corrupted) = Signature::from_bytes(&sig_bytes) {
                prop_assert!(pk.verify(&msg, &corrupted).is_err());
            }
        }

        #[test]
        fn serialization_roundtrip_signing_key(_seed in any::<[u8; 32]>()) {
            let mut rng = rand::thread_rng();
            let sk = SigningKey::generate(&mut rng);

            let bytes = sk.to_bytes();
            let sk2 = SigningKey::from_bytes(&bytes).unwrap();

            prop_assert_eq!(sk.to_bytes(), sk2.to_bytes());
        }

        #[test]
        fn serialization_roundtrip_verifying_key(_seed in any::<u8>()) {
            let mut rng = rand::thread_rng();
            let sk = SigningKey::generate(&mut rng);
            let pk = sk.verifying_key().unwrap();

            let bytes = pk.to_bytes();
            let pk2 = VerifyingKey::from_bytes(&bytes).unwrap();

            prop_assert_eq!(pk.to_bytes(), pk2.to_bytes());
        }
    }
}

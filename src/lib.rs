//! # falconed
//!
//! hybrid post-quantum signatures: ed25519 + falcon-512.
//!
//! both signatures are computed over the message. both must verify.
//! if either is broken, you still have the other.
//!
//! ## usage
//!
//! ```
//! use falconed::{SigningKey, VerifyingKey, Signature};
//! use rand_core::OsRng;
//!
//! // generate a keypair
//! let sk = SigningKey::generate(&mut OsRng);
//! let pk = sk.verifying_key().unwrap();
//!
//! // sign a message
//! let msg = b"the quick brown fox";
//! let sig = sk.sign(msg).unwrap();
//!
//! // verify
//! assert!(pk.verify(msg, &sig).is_ok());
//! ```
//!
//! ## signature crate interop
//!
//! implements [`signature::Signer`] and [`signature::Verifier`] for
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
//! **timing**: signing operations aim to be constant-time, but this depends
//! on the underlying implementations (ed25519-dalek, fn-dsa). verification
//! is explicitly *not* constant-time - it operates on public inputs only.
//! [`VerifyingKey::verify_strict`] always runs both verifications but does
//! not guarantee constant-time execution.
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

mod error;
mod signature;
mod signing;
mod verifying;

pub use error::Error;
pub use signature::Signature;
pub use signing::SigningKey;
pub use verifying::VerifyingKey;

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
    fn verify_strict_succeeds() {
        let mut rng = rand::thread_rng();
        let sk = SigningKey::generate(&mut rng);
        let pk = sk.verifying_key().unwrap();

        let msg = b"test message";
        let sig = sk.sign(msg).unwrap();

        assert!(pk.verify_strict(msg, &sig).is_ok());
    }

    #[test]
    fn verify_strict_fails_on_wrong_message() {
        let mut rng = rand::thread_rng();
        let sk = SigningKey::generate(&mut rng);
        let pk = sk.verifying_key().unwrap();

        let sig = sk.sign(b"correct").unwrap();
        assert!(pk.verify_strict(b"wrong", &sig).is_err());
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

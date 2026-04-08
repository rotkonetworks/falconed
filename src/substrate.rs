//! substrate integration.
//!
//! provides wrapper types implementing [`sp_core::crypto::Pair`] and
//! [`sp_runtime::traits::Verify`] for use in substrate runtimes.
//! enable with `features = ["substrate"]`.
//!
//! ## account model
//!
//! the [`Public`] type is a full public identity containing both the
//! verifying key (for signature verification) and the encryption public
//! key (for encrypting messages to this account). on-chain, accounts are
//! addressed by `AccountId32 = blake2_256(Public)` for compact storage
//! and ecosystem compatibility. the full `Public` is stored once at
//! account creation and looked up when cryptographic operations are needed.

use alloc::vec::Vec;
use codec::{Decode, Encode, Input, MaxEncodedLen, Output};
use sp_core::crypto::{
    ByteArray, CryptoType, CryptoTypeId, Derive, DeriveError, DeriveJunction,
    Pair as TraitPair, Public as TraitPublic, SecretStringError,
    Signature as TraitSignature,
};

use crate::{
    ENCRYPTION_PUBLIC_KEY_SIZE, SEED_SIZE, SIGNATURE_SIZE, SIGNING_KEY_SIZE, VERIFYING_KEY_SIZE,
};

/// crypto type identifier: `*b"flcd"`.
pub const CRYPTO_ID: CryptoTypeId = CryptoTypeId(*b"flcd");

/// public identity size: verifying key + encryption public key.
pub const PUBLIC_IDENTITY_SIZE: usize = VERIFYING_KEY_SIZE + ENCRYPTION_PUBLIC_KEY_SIZE;

// ---------- Public ----------

/// full public identity: verifying key + encryption public key.
///
/// this is the account's complete public material. anyone holding it can
/// verify signatures and encrypt messages to this account. on-chain,
/// `AccountId32 = blake2_256(Public)` is used for compact addressing.
///
/// layout: `verifying_key (929) || encryption_public_key (1216) = 2145 bytes`
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Public(pub [u8; PUBLIC_IDENTITY_SIZE]);

impl Public {
    /// construct from a raw byte array.
    pub fn from_raw(data: [u8; PUBLIC_IDENTITY_SIZE]) -> Self {
        Self(data)
    }

    /// extract the verifying key portion.
    pub fn verifying_key_bytes(&self) -> &[u8; VERIFYING_KEY_SIZE] {
        self.0[..VERIFYING_KEY_SIZE].try_into().unwrap()
    }

    /// extract the encryption public key portion.
    pub fn encryption_public_key_bytes(&self) -> &[u8] {
        &self.0[VERIFYING_KEY_SIZE..]
    }

    /// parse the verifying key from this identity.
    pub fn verifying_key(&self) -> Result<crate::VerifyingKey, crate::Error> {
        crate::VerifyingKey::from_bytes(self.verifying_key_bytes())
    }

    /// parse the encryption public key from this identity.
    pub fn encryption_public_key(&self) -> Result<crate::EncryptionPublicKey, crate::Error> {
        crate::EncryptionPublicKey::from_bytes(self.encryption_public_key_bytes())
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
        if data.len() != PUBLIC_IDENTITY_SIZE {
            return Err(());
        }
        let mut arr = [0u8; PUBLIC_IDENTITY_SIZE];
        arr.copy_from_slice(data);
        Ok(Self(arr))
    }
}

impl Encode for Public {
    fn size_hint(&self) -> usize {
        PUBLIC_IDENTITY_SIZE
    }

    fn encode_to<T: Output + ?Sized>(&self, dest: &mut T) {
        dest.write(&self.0);
    }
}

impl Decode for Public {
    fn decode<I: Input>(input: &mut I) -> Result<Self, codec::Error> {
        let mut arr = [0u8; PUBLIC_IDENTITY_SIZE];
        input.read(&mut arr)?;
        Ok(Self(arr))
    }
}

impl MaxEncodedLen for Public {
    fn max_encoded_len() -> usize {
        PUBLIC_IDENTITY_SIZE
    }
}

impl scale_info::TypeInfo for Public {
    type Identity = Self;

    fn type_info() -> scale_info::Type {
        scale_info::Type::builder()
            .path(scale_info::Path::new("Public", module_path!()))
            .composite(
                scale_info::build::Fields::unnamed()
                    .field(|f| {
                        f.ty::<[u8; PUBLIC_IDENTITY_SIZE]>()
                            .type_name("[u8; 2145]")
                    }),
            )
    }
}

impl ByteArray for Public {
    const LEN: usize = PUBLIC_IDENTITY_SIZE;
}

impl Derive for Public {}

impl CryptoType for Public {
    type Pair = Pair;
}

impl TraitPublic for Public {}

// ---------- IdentifyAccount: Public → AccountId32 ----------

impl sp_runtime::traits::IdentifyAccount for Public {
    type AccountId = sp_core::crypto::AccountId32;

    fn into_account(self) -> sp_core::crypto::AccountId32 {
        let hash = sp_crypto_hashing::blake2_256(self.as_ref());
        sp_core::crypto::AccountId32::new(hash)
    }
}

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

// ---------- Verify: Signature → AccountId32 ----------

impl sp_runtime::traits::Verify for Signature {
    type Signer = Public;

    /// **not implementable**: falconed signatures require the full 2145-byte
    /// `Public` key for verification, but this trait only provides an
    /// `AccountId32` (a 32-byte blake2 hash). it is impossible to recover
    /// the public key from its hash.
    ///
    /// runtimes MUST use [`Pair::verify_with_public`] instead, resolving
    /// `AccountId32` → `Public` from on-chain storage before verifying.
    ///
    /// # panics
    ///
    /// always panics. this is intentional: a silent `false` would cause
    /// valid transactions to be silently rejected with no diagnostic.
    /// a panic makes the misuse immediately visible during development.
    fn verify<L: sp_runtime::traits::Lazy<[u8]>>(
        &self,
        _msg: L,
        _signer: &sp_core::crypto::AccountId32,
    ) -> bool {
        panic!(
            "falconed::substrate::Signature::verify() cannot verify from AccountId32. \
             Use Pair::verify_with_public() with the full Public key instead. \
             See the substrate module docs for the correct verification path."
        );
    }
}

// ---------- Pair ----------

/// falconed keypair for substrate.
///
/// caches serialized key bytes to avoid repeated derivation. the seed
/// enables hierarchical key derivation (hard junctions only).
///
/// the public key includes both the verifying key and the encryption
/// public key, forming a complete public identity.
pub struct Pair {
    seed: [u8; SEED_SIZE],
    signing_key_bytes: [u8; SIGNING_KEY_SIZE],
    public_bytes: [u8; PUBLIC_IDENTITY_SIZE],
}

/// clone is required by the `sp_core::Pair` trait bound.
///
/// **security warning**: cloning copies secret key material. avoid holding
/// multiple copies of a `Pair` — clone only when required by substrate APIs,
/// and drop the clone as soon as possible.
impl Clone for Pair {
    fn clone(&self) -> Self {
        Self {
            seed: self.seed,
            signing_key_bytes: self.signing_key_bytes,
            public_bytes: self.public_bytes,
        }
    }
}

impl Drop for Pair {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            zeroize::Zeroize::zeroize(&mut self.seed);
            zeroize::Zeroize::zeroize(&mut self.signing_key_bytes);
        }
        #[cfg(not(feature = "zeroize"))]
        {
            crate::zeroize_bytes(&mut self.seed);
            crate::zeroize_bytes(&mut self.signing_key_bytes);
        }
        // public_bytes is public material, no need to zeroize
    }
}

#[cfg(feature = "zeroize")]
impl zeroize::ZeroizeOnDrop for Pair {}

impl CryptoType for Pair {
    type Pair = Pair;
}

impl Pair {
    /// get the `AccountId32` for this keypair.
    pub fn account_id(&self) -> sp_core::crypto::AccountId32 {
        use sp_runtime::traits::IdentifyAccount;
        self.public().into_account()
    }

    /// verify a signature against the full public identity (not the hashed account id).
    ///
    /// this is the correct verification path for runtimes: resolve
    /// `AccountId32` → `Public` from storage, then call this.
    pub fn verify_with_public<M: AsRef<[u8]>>(
        sig: &Signature,
        message: M,
        pubkey: &Public,
    ) -> bool {
        let Ok(vk) = crate::VerifyingKey::from_bytes(pubkey.verifying_key_bytes()) else {
            return false;
        };
        let Ok(s) = crate::Signature::from_bytes(&sig.0) else {
            return false;
        };
        vk.verify(message.as_ref(), &s).is_ok()
    }
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

        let spending_key = crate::SpendingKey::from_seed(&seed);
        let verifying_key = spending_key
            .verifying_key()
            .map_err(|_| SecretStringError::InvalidSeed)?;
        let encryption_public_key = spending_key.encryption_public_key();

        let mut public_bytes = [0u8; PUBLIC_IDENTITY_SIZE];
        public_bytes[..VERIFYING_KEY_SIZE].copy_from_slice(&verifying_key.to_bytes());
        public_bytes[VERIFYING_KEY_SIZE..].copy_from_slice(&encryption_public_key.to_bytes());

        Ok(Pair {
            seed,
            signing_key_bytes: spending_key.signing_key().to_bytes(),
            public_bytes,
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
        Pair::verify_with_public(sig, message, pubkey)
    }

    fn to_raw_vec(&self) -> Vec<u8> {
        // WARNING: returns the master seed as an unzeroized Vec.
        // callers MUST zeroize this Vec when done (e.g. via zeroize::Zeroize).
        // required by the sp_core::Pair trait.
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

    #[test]
    fn public_identity_size() {
        let (pair, _) = Pair::generate();
        let public = pair.public();
        assert_eq!(public.as_ref().len(), PUBLIC_IDENTITY_SIZE);
        assert_eq!(PUBLIC_IDENTITY_SIZE, VERIFYING_KEY_SIZE + ENCRYPTION_PUBLIC_KEY_SIZE);
    }

    #[test]
    fn public_identity_contains_both_keys() {
        let (pair, _) = Pair::generate();
        let public = pair.public();
        // both portions should parse successfully
        assert!(public.verifying_key().is_ok());
        assert!(public.encryption_public_key().is_ok());
    }

    #[test]
    fn account_id_is_blake2_hash() {
        let (pair, _) = Pair::generate();
        let public = pair.public();
        let account_id = pair.account_id();
        let expected = sp_crypto_hashing::blake2_256(public.as_ref());
        assert_eq!(AsRef::<[u8; 32]>::as_ref(&account_id), &expected);
    }

    #[test]
    fn different_seeds_different_account_ids() {
        let p1 = Pair::from_seed_slice(&[1u8; SEED_SIZE]).unwrap();
        let p2 = Pair::from_seed_slice(&[2u8; SEED_SIZE]).unwrap();
        assert_ne!(p1.account_id(), p2.account_id());
    }

    #[test]
    fn can_encrypt_to_public_identity() {
        let (pair, _) = Pair::generate();
        let public = pair.public();
        let epk = public.encryption_public_key().unwrap();

        // derive viewing key from same seed to decrypt
        let spending = crate::SpendingKey::from_seed_slice(pair.to_raw_vec().as_slice()).unwrap();
        let viewing = spending.viewing_key();

        let mut rng = rand_core::OsRng;
        let encrypted = crate::encryption::seal(&mut rng, &epk, b"hello chain").unwrap();
        let decrypted = crate::encryption::open(viewing, &encrypted).unwrap();
        assert_eq!(&decrypted, b"hello chain");
    }
}

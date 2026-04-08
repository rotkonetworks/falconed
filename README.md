# falconed

a hybrid signature scheme combining ed25519 and falcon-512, and a hybrid
KEM combining x25519 and ML-KEM-768.

the design goal is simple: if either the classical or post-quantum
component is broken, the hybrid construction remains at least as strong
as the surviving component. this is the standard "concatenation combiner"
approach — the hybrid is no weaker than its strongest constituent.

## design

### signatures

a `SigningKey` holds an ed25519 signing key and a falcon-512 signing key,
both derived deterministically from a 32-byte seed via domain-separated
SHA-512:

```text
ed25519_seed  = SHA-512(len("falconed-ed25519")  || "falconed-ed25519"  || seed)[..32]
falcon_seed   = SHA-512(len("falconed-falcon")   || "falconed-falcon"   || seed)[..32]
```

signing produces the concatenation `ed25519_sig || falcon_sig`. both
components sign the same message. verification checks both components
unconditionally — `verify()` does not short-circuit on the first failure,
preventing timing side-channels that would reveal which component failed.
a `verify_fast()` method is provided for contexts where all inputs are
public and timing is irrelevant.

### encryption

the hybrid KEM combines x25519 ECDH with ML-KEM-768. the KEM combiner
follows the [X-Wing][xwing] design philosophy, placing the ML-KEM shared
secret first in the KDF input for alignment with FIPS SP 800-56Cr2.
the combiner binds the full transcript: both public keys and both
ciphertexts are included in the KDF input. decapsulation runs both
KEMs unconditionally before checking for errors.

authenticated encryption uses ChaCha20-Poly1305 with a key commitment
scheme to prevent invisible salamanders (key-commitment attacks on AEAD).

### key hierarchy

`SpendingKey` is the master secret (a 32-byte seed). it derives:
- a `SigningKey` (ed25519 + falcon-512) for signatures
- a `ViewingKey` (x25519 + ML-KEM-768) for encryption

all derivation is deterministic and domain-separated. if you don't need
the master seed after derivation, `into_keys()` zeroizes it immediately.

[xwing]: https://eprint.iacr.org/2024/039

## usage

```rust
use falconed::{SigningKey, VerifyingKey, Signature};
use rand_core::OsRng;

let sk = SigningKey::generate(&mut OsRng);
let vk = sk.verifying_key().unwrap();

let msg = b"the quick brown fox";
let sig = sk.sign(msg).unwrap();

assert!(vk.verify(msg, &sig).is_ok());
```

implements `signature::Signer` and `signature::Verifier` for
interoperability with the `signature` crate ecosystem.

## wire format

fixed-size concatenation. no length prefixes, no ASN.1, no negotiation.

```text
SigningKey    = ed25519_seed (32) || falcon_sk (1281)  = 1313 bytes
VerifyingKey  = ed25519_vk  (32) || falcon_vk (897)   = 929 bytes
Signature     = ed25519_sig (64) || falcon_sig (666)   = 730 bytes
```

`to_bytes()` / `from_bytes()` on all types. `TryFrom<&[u8]>` works as
expected.

## features

| feature | default | description |
|---------|---------|-------------|
| `std` | yes | std support via ed25519-dalek |
| `zeroize` | yes | zeroize secrets on drop via the `zeroize` crate |
| `serde` | no | serde `Serialize`/`Deserialize` |
| `hazmat` | no | expose internal key components |
| `simd` | no | AVX2 acceleration for falcon on x86_64 |
| `substrate` | no | substrate `sp_core::Pair` integration |

### `no_std`

disable default features. requires `alloc` — falcon's internals and
domain-tagged message construction need a global allocator.

```toml
falconed = { version = "0.1", default-features = false }
```

## security

**combiner model.** the signature combiner is concatenation: sign with
both, verify both. an attacker must break *both* ed25519 and falcon-512
to forge. the two components are not cryptographically bound to each
other beyond sharing the same message; security relies on both
components being checked. this is a standard construction but has not
been formally analyzed for this specific instantiation.

**timing.** `verify()` evaluates both components unconditionally to avoid
leaking which failed. `verify_fast()` short-circuits and must only be
used when timing is irrelevant (all inputs public). decapsulation runs
both KEMs before returning. key commitment uses `subtle::ConstantTimeEq`.
constant-time properties of the underlying primitives depend on
`ed25519-dalek` and `fn-dsa`.

**zeroization.** secret material is zeroized on drop via volatile writes
and compiler fences. the `zeroize` feature (on by default) additionally
uses the `zeroize` crate. decoded falcon signing keys are zeroized after
each signing operation. `SpendingKey::into_keys()` zeroizes the seed
immediately. note that we cannot guarantee that the optimizer, OS, or
hardware will not copy secrets elsewhere in memory — this is a
best-effort defense.

**deterministic derivation.** key derivation from seeds is deterministic
but depends on the internal RNG consumption patterns of `fn-dsa`,
`ml-kem`, and `rand_chacha`. upgrading these dependencies may silently
change derived keys for the same seed. all three are pinned to exact
versions. test vectors catch derivation drift in CI. **do not unpin
these dependencies without re-verifying all test vectors.**

**not audited.** this crate has not received a professional security
audit. use it at your own risk.

## benchmarks

AMD Ryzen 9 7950X, single-threaded:

| operation | time |
|-----------|------|
| keygen | ~2.0 ms |
| sign | ~162 µs |
| verify | ~34 µs |

## implementation

the falcon backend is [fn-dsa](https://crates.io/crates/fn-dsa) by
thomas pornin (the original falcon author). pure rust, no C bindings.

MSRV: **1.82** (required by fn-dsa).

## license

MIT or Apache-2.0.

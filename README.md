# falconed

hybrid post-quantum signatures for people who ship things.

## what

this crate combines ed25519 with falcon-512. both signatures are computed
over the message. both must verify. if either is broken, you still have
the other.

this is the conservative choice for systems that need to last.

## why

- 48% of nist pqc round-1 submissions are broken
- falcon might join them someday
- ed25519 will fall to cryptographically relevant quantum computers
- hedge your bets

## usage

```rust
use falconed::{SigningKey, VerifyingKey, Signature};
use rand_core::OsRng;

// generate a keypair
let sk = SigningKey::generate(&mut OsRng);
let pk = sk.verifying_key().unwrap();

// sign a message
let msg = b"the quick brown fox";
let sig = sk.sign(msg).unwrap();

// verify
assert!(pk.verify(msg, &sig).is_ok());
```

## signature crate interop

implements `signature::Signer` and `signature::Verifier`:

```rust
use signature::{Signer, Verifier};
use falconed::SigningKey;
use rand_core::OsRng;

let sk = SigningKey::generate(&mut OsRng);
let pk = sk.verifying_key().unwrap();

let sig = sk.try_sign(b"message").unwrap();
assert!(pk.verify(b"message", &sig).is_ok());
```

## serialization

all types are fixed-size. concatenation, no length prefixes, no asn.1.

```text
SigningKey   = ed25519_seed (32) || falcon_sk (1281) = 1313 bytes
VerifyingKey = ed25519_pk (32) || falcon_pk (897) = 929 bytes
Signature    = ed25519_sig (64) || falcon_sig (666) = 730 bytes
```

`to_bytes()` and `from_bytes()` on everything. `TryFrom<&[u8]>` does
what you expect.

## verification semantics

`verify()` always checks both ed25519 and falcon components regardless
of whether either fails. this prevents leaking which component failed
through timing differences.

`verify_fast()` short-circuits on first failure for performance-sensitive
paths where timing is irrelevant (public inputs only).

```rust
// default: always checks both (prefer this)
pk.verify(msg, &sig)?;

// fast path: short-circuits on ed25519 failure
pk.verify_fast(msg, &sig)?;
```

## features

```toml
[features]
default = ["std"]
std = []
serde = ["dep:serde"]
zeroize = ["dep:zeroize"]
hazmat = []  # expose internal key components
simd = []    # avx2 acceleration on x86_64
```

## no_std

disable default features. requires `alloc` — a `#[global_allocator]` must be
available. the allocator is used for domain-tagged message construction and
by fn-dsa internally.

```toml
[dependencies]
falconed = { version = "0.1", default-features = false }
```

## key management

`SpendingKey` retains the master seed for backup/export. if you don't
need it after derivation, use `into_keys()` to zeroize the seed
immediately:

```rust
use falconed::SpendingKey;
use rand_core::OsRng;

let sk = SpendingKey::generate(&mut OsRng);
let (signing, viewing) = sk.into_keys();
// seed is zeroized — only the derived keys remain in memory
```

## security considerations

**hybrid signatures**: this crate concatenates independent ed25519 and
falcon-512 signatures. an attacker must break *both* schemes to forge a
signature. the two signature components are not cryptographically bound
to each other — security relies on domain-tagged messages and both
components being verified. this is a standard concatenation combiner
but has not been formally analyzed for this specific pairing.

**hybrid encryption**: the KEM combiner follows the X-Wing design
philosophy (Barbosa, Connolly et al.) with ml-kem shared secret first
in the KDF input for FIPS SP 800-56Cr2 alignment. both KEM components
run unconditionally during decapsulation to prevent timing side-channels.
includes full transcript binding (all public keys and ciphertexts).

**timing**: signing operations aim to be constant-time, but this depends
on the underlying implementations (ed25519-dalek, fn-dsa). `verify()`
always checks both components to avoid leaking which failed.
`verify_fast()` short-circuits and should only be used on public-input
paths. key commitment comparison uses constant-time equality.
decapsulation runs both x25519 and ml-kem before checking for errors.

**zeroization**: secret key material is zeroized on drop via volatile
writes + compiler fences. decoded falcon signing keys are zeroized after
each operation. `SpendingKey::into_keys()` zeroizes the seed immediately.
enable the `zeroize` feature for additional guarantees via the `zeroize`
crate.

**deterministic derivation**: key derivation from seeds depends on the
internal behaviour of `fn-dsa`, `ml-kem`, and `rand_chacha`. upgrading
these dependencies may change derived keys for the same seed. pinned
test vectors for both signing and viewing key derivation will catch
this in CI. pin dependency versions before deploying.

**not audited**: this implementation has not been professionally audited.
use at your own risk for anything important.

## benchmarks

measured on amd ryzen 9 7950x:

| operation | time |
|-----------|------|
| keygen | ~2.0 ms |
| sign | ~162 µs |
| verify | ~34 µs |

## falcon backend

uses [fn-dsa](https://crates.io/crates/fn-dsa) by thomas pornin,
the original author of falcon. pure rust, no C bindings.

## msrv

1.82 (required by fn-dsa)

## license

mit or apache-2.0, your choice.

## status

this is alpha software. the api may change. don't use it for anything
important until it's been audited.

## acknowledgments

built on:
- [ed25519-dalek](https://github.com/dalek-cryptography/ed25519-dalek)
- [fn-dsa](https://github.com/pornin/rust-fn-dsa) by thomas pornin

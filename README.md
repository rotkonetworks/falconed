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
let pk = sk.verifying_key();

// sign a message
let msg = b"the quick brown fox";
let sig = sk.sign(msg);

// verify
assert!(pk.verify(msg, &sig).is_ok());
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

`verify()` checks ed25519 first. if it fails, returns early without
checking falcon. this is faster and leaks nothing—verification is a
public operation on public inputs.

`verify_strict()` checks both regardless for constant-time behavior.

```rust
// fast path (default)
pk.verify(msg, &sig)?;

// constant-time (both always checked)
pk.verify_strict(msg, &sig)?;
```

## features

```toml
[features]
default = ["std"]
std = []
serde = ["dep:serde"]
zeroize = ["dep:zeroize"]
simd = []  # avx2 acceleration on x86_64
```

## no_std

disable default features. requires `alloc`.

```toml
[dependencies]
falconed = { version = "0.1", default-features = false }
```

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

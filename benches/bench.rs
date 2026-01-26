//! benchmarks for falconed.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use falconed::SigningKey;
use rand::rngs::OsRng;

fn bench_keygen(c: &mut Criterion) {
    c.bench_function("SigningKey::generate", |b| {
        b.iter(|| {
            let sk = SigningKey::generate(&mut OsRng);
            black_box(sk)
        })
    });
}

fn bench_sign(c: &mut Criterion) {
    let sk = SigningKey::generate(&mut OsRng);
    let msg = b"the quick brown fox jumps over the lazy dog";

    c.bench_function("SigningKey::sign", |b| {
        b.iter(|| {
            let sig = sk.sign(black_box(msg)).unwrap();
            black_box(sig)
        })
    });
}

fn bench_verify(c: &mut Criterion) {
    let sk = SigningKey::generate(&mut OsRng);
    let pk = sk.verifying_key().unwrap();
    let msg = b"the quick brown fox jumps over the lazy dog";
    let sig = sk.sign(msg).unwrap();

    c.bench_function("VerifyingKey::verify", |b| {
        b.iter(|| {
            let result = pk.verify(black_box(msg), black_box(&sig));
            black_box(result)
        })
    });
}

fn bench_verify_strict(c: &mut Criterion) {
    let sk = SigningKey::generate(&mut OsRng);
    let pk = sk.verifying_key().unwrap();
    let msg = b"the quick brown fox jumps over the lazy dog";
    let sig = sk.sign(msg).unwrap();

    c.bench_function("VerifyingKey::verify_strict", |b| {
        b.iter(|| {
            let result = pk.verify_strict(black_box(msg), black_box(&sig));
            black_box(result)
        })
    });
}

fn bench_verifying_key_derivation(c: &mut Criterion) {
    let sk = SigningKey::generate(&mut OsRng);

    c.bench_function("SigningKey::verifying_key", |b| {
        b.iter(|| {
            let pk = sk.verifying_key().unwrap();
            black_box(pk)
        })
    });
}

criterion_group!(
    benches,
    bench_keygen,
    bench_sign,
    bench_verify,
    bench_verify_strict,
    bench_verifying_key_derivation,
);

criterion_main!(benches);

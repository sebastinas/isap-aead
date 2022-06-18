// Copyright 2022 Sebastian Ramacher
// SPDX-License-Identifier: MIT

use criterion::{
    black_box, criterion_group, criterion_main, Bencher, BenchmarkId, Criterion, Throughput,
};
use isap_aead::aead::{generic_array::typenum::Unsigned, Aead, AeadInPlace, NewAead};
use rand::{rngs::StdRng, RngCore, SeedableRng};

const KB: usize = 1024;

fn bench_for_size<A: NewAead + Aead>(b: &mut Bencher, rng: &mut dyn RngCore, size: usize) {
    let mut key = vec![0u8; A::KeySize::USIZE];
    rng.fill_bytes(key.as_mut_slice());
    let mut nonce = vec![0u8; A::NonceSize::USIZE];
    rng.fill_bytes(nonce.as_mut_slice());
    let mut plaintext = vec![0u8; size];
    rng.fill_bytes(plaintext.as_mut_slice());

    let cipher = A::new(key.as_slice().into());
    let nonce = nonce.as_slice().into();

    b.iter(|| black_box(cipher.encrypt(nonce, plaintext.as_slice())));
}

fn bench_for_size_inplace<A: NewAead + AeadInPlace>(
    b: &mut Bencher,
    rng: &mut dyn RngCore,
    size: usize,
) {
    let mut key = vec![0u8; A::KeySize::USIZE];
    rng.fill_bytes(key.as_mut_slice());
    let mut nonce = vec![0u8; A::NonceSize::USIZE];
    rng.fill_bytes(nonce.as_mut_slice());
    let mut buffer = vec![0u8; size + 16];
    rng.fill_bytes(buffer.as_mut_slice());

    let cipher = A::new(key.as_slice().into());
    let nonce = nonce.as_slice().into();

    b.iter(|| black_box(cipher.encrypt_in_place(nonce, b"", &mut buffer)));
}

fn criterion_benchmark<A: NewAead + Aead>(c: &mut Criterion, name: &str) {
    let mut rng = StdRng::seed_from_u64(0x0123456789abcdef);
    let mut group = c.benchmark_group(name);
    for size in [KB, 2 * KB, 4 * KB, 8 * KB, 16 * KB, 32 * KB, 64 * KB].iter() {
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            bench_for_size::<A>(b, &mut rng, size)
        });
    }
    group.finish();
}

fn criterion_benchmark_inplace<A: NewAead + AeadInPlace>(c: &mut Criterion, name: &str) {
    let mut rng = StdRng::seed_from_u64(0x0123456789abcdef);
    let mut group = c.benchmark_group(name);
    for size in [KB, 2 * KB, 4 * KB, 8 * KB, 16 * KB, 32 * KB, 64 * KB].iter() {
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            bench_for_size_inplace::<A>(b, &mut rng, size)
        });
    }
    group.finish();
}

fn criterion_bench_isapascon128(c: &mut Criterion) {
    criterion_benchmark::<isap_aead::IsapAscon128>(c, "ISAP-Ascon-128");
}

fn criterion_bench_isapascon128a(c: &mut Criterion) {
    criterion_benchmark::<isap_aead::IsapAscon128A>(c, "ISAP-Ascon-128A");
}

fn criterion_bench_isapascon128_inplace(c: &mut Criterion) {
    criterion_benchmark_inplace::<isap_aead::IsapAscon128>(c, "ISAP-Ascon-128 (inplace)");
}

fn criterion_bench_isapascon128a_inplace(c: &mut Criterion) {
    criterion_benchmark_inplace::<isap_aead::IsapAscon128A>(c, "ISAP-Ascon-128A (inplace)");
}

fn criterion_bench_isapkeccak128(c: &mut Criterion) {
    criterion_benchmark::<isap_aead::IsapKeccak128>(c, "ISAP-Keccak-128");
}

fn criterion_bench_isapkeccak128a(c: &mut Criterion) {
    criterion_benchmark::<isap_aead::IsapKeccak128A>(c, "ISAP-Keccak-128A");
}

fn criterion_bench_isapkeccak128_inplace(c: &mut Criterion) {
    criterion_benchmark_inplace::<isap_aead::IsapKeccak128>(c, "ISAP-Keccak-128 (inplace)");
}

fn criterion_bench_isapkeccak128a_inplace(c: &mut Criterion) {
    criterion_benchmark_inplace::<isap_aead::IsapKeccak128A>(c, "ISAP-Keccak-128A (inplace)");
}

criterion_group!(
    bench_isapascon128,
    criterion_bench_isapascon128,
    criterion_bench_isapascon128_inplace,
);
criterion_group!(
    bench_isapascon128a,
    criterion_bench_isapascon128a,
    criterion_bench_isapascon128a_inplace,
);
criterion_group!(
    bench_isapkeccak128,
    criterion_bench_isapkeccak128,
    criterion_bench_isapkeccak128_inplace,
);
criterion_group!(
    bench_isapkeccak128a,
    criterion_bench_isapkeccak128a,
    criterion_bench_isapkeccak128a_inplace,
);
criterion_main!(
    bench_isapascon128,
    bench_isapascon128a,
    bench_isapkeccak128,
    bench_isapkeccak128a
);

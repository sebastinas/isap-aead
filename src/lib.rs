// Copyright 2022 Sebastian Ramacher
// SPDX-License-Identifier: MIT

#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![warn(missing_docs)]

//! ## Usage
//!
//! Simple usage (allocating, no associated data):
//!
//! ```
//! # #[cfg(feature="ascon")] {
//! use isap_aead::IsapAscon128; // Or `IsapAscon128A`, `IsapKeccak128`, `IsapKeccak128A`
//! use isap_aead::aead::{Aead, KeyInit};
//!
//! let key = b"very secret key.";
//! let cipher = IsapAscon128::new(key.into());
//! let nonce = b"unique nonce 012"; // 128-bits; unique per message
//!
//! let ciphertext = cipher.encrypt(nonce.into(), b"plaintext message".as_ref())
//!     .expect("encryption failure!"); // NOTE: handle this error to avoid panics!
//!
//! let plaintext = cipher.decrypt(nonce.into(), ciphertext.as_ref())
//!     .expect("decryption failure!"); // NOTE: handle this error to avoid panics!
//!
//! assert_eq!(&plaintext, b"plaintext message");
//! # }
//! ```
//!
//! ## In-place Usage (eliminates `alloc` requirement)
//!
//! Similar to other crates implementing [`aead`] interfaces, this crate also offers an optional
//! `alloc` feature which can be disabled in e.g. microcontroller environments that don't have a
//! heap. See [`aead::AeadInPlace`] for more details.
//!
//! ```
//! # #[cfg(all(feature = "heapless", feature="ascon"))] {
//! use isap_aead::IsapAscon128; // Or `IsapAscon128A`, `IsapKeccak128`, `IsapKeccak128A`
//! use isap_aead::aead::{AeadInPlace, KeyInit};
//! use isap_aead::aead::heapless::Vec;
//!
//! let key = b"very secret key.";
//! let cipher = IsapAscon128::new(key.into());
//! let nonce = b"unique nonce 012"; // 128-bits; unique per message
//!
//! let mut buffer: Vec<u8, 128> = Vec::new(); // Buffer needs 16-bytes overhead for authentication tag
//! buffer.extend_from_slice(b"plaintext message");
//!
//! // Encrypt `buffer` in-place, replacing the plaintext contents with ciphertext
//! cipher.encrypt_in_place(nonce.into(), b"", &mut buffer).expect("encryption failure!");
//!
//! // `buffer` now contains the message ciphertext
//! assert_ne!(&buffer, b"plaintext message");
//!
//! // Decrypt `buffer` in-place, replacing its ciphertext context with the original plaintext
//! cipher.decrypt_in_place(nonce.into(), b"", &mut buffer).expect("decryption failure!");
//! assert_eq!(&buffer, b"plaintext message");
//! # }
//! ```
//!
//! Similarly, enabling the `arrayvec` feature of this crate will provide an impl of
//! [`aead::Buffer`] for `arrayvec::ArrayVec`.

use core::ops::Sub;

pub use aead::{self, AeadCore, AeadInPlace, Error, Key, KeyInit, Nonce, Result, Tag};
use aead::{
    consts::{U0, U16},
    generic_array::{GenericArray, typenum::Unsigned},
};
use subtle::ConstantTimeEq;

#[cfg(feature = "ascon")]
mod ascon_impl;

#[cfg(feature = "keccak")]
mod keccak_impl;

#[cfg(feature = "ascon")]
pub use ascon_impl::{IsapAscon128, IsapAscon128A};

#[cfg(feature = "keccak")]
pub use keccak_impl::{IsapKeccak128, IsapKeccak128A};

/// Helper trait to subtract `U16` from an `Unsigned`
trait U16Subtractable: Sub<U16> {
    type Output: Unsigned;
}

impl<T> U16Subtractable for T
where
    T: Unsigned + Sub<U16>,
    <T as Sub<U16>>::Output: Unsigned,
{
    type Output = <T as Sub<U16>>::Output;
}

/// A permutation state that can (1) absorb an arbitrary number of bytes and (2) extract bytes from the state.
///
/// The state needs to keep track one the number of processed bytes to perform a permutation after absorbing `RATE` bytes.
trait AbsorbingState: Default {
    /// Absorbing rate (in bytes), i.e., how many bytes can be absorbed before a permutation is performed.
    const RATE: usize;
    /// Size of the internal state.
    type StateSize: Unsigned + U16Subtractable;

    /// Absorb one byte and permute if `RATE` has been reached.
    fn absorb_byte<R: Unsigned>(&mut self, byte: u8);
    /// Absorb bytes and permute whenever `RATE` bytes have been processed.
    fn absorb_bytes<R: Unsigned>(&mut self, bytes: &[u8]);
    /// Absorb data, add padding and permute
    fn absorb_bytes_pad_permute<R: Unsigned>(&mut self, data: &[u8]) {
        self.absorb_bytes::<R>(data);
        self.absorb_byte::<R>(0x80);
        self.permute_n_if::<R>();
    }
    /// Perform a permutation.
    fn permute_n<R: Unsigned>(&mut self);
    /// Perform a permutation if a non-zero amount of bytes have been processed after the last permutation.
    fn permute_n_if<R: Unsigned>(&mut self);
    /// Seperate domains.
    fn seperate_domains(&mut self);

    /// Extract bytes from the beginning of the state.
    fn extract_bytes<const LEN: usize>(&self) -> [u8; LEN];
    /// Overwrite any bytes of the state.
    fn overwrite_bytes<const LEN: usize, O: Unsigned>(&mut self, bytes: &[u8; LEN]);
}

/// Helper trait for all ISAP parameters and algorithms.
///
/// Implementors only need provide implementations to apply the key stream to blocks/bytes of the message.
trait Isap {
    /// The state.
    type State: AbsorbingState;
    /// Size of the keys; always `U128`.
    type KeySizeBits: Unsigned; //  = U128;
    /// Absorbation rate for encryption and MAC, i.e., `r_H`.
    type RateBits: Unsigned;
    type RateBytes: Unsigned;
    /// Absorbation rate for session key, i.e., `r_B`; always `U1`.
    type RateSessionKeyBits: Unsigned; // = 1;
    /// Rounds of the permutation for long term key absorbation, i.e., `s_K`.
    type RoundsKey: Unsigned;
    //// Rounds of the permutation for bit absorbation, i.e., `s_B`.
    type RoundsBit: Unsigned;
    /// Rounds of the permutation for encrytion, i.e., `s_E`.
    type RoundsEncryption: Unsigned;
    /// Rounds of the permutation for MAC, i.e., `s_H`.
    type RoundsMAC: Unsigned;

    /// IV for MAC
    const ISAP_IV_A: [u8; 8] = [
        0x01,
        Self::KeySizeBits::U8,
        Self::RateBits::U8,
        Self::RateSessionKeyBits::U8,
        Self::RoundsMAC::U8,
        Self::RoundsBit::U8,
        Self::RoundsEncryption::U8,
        Self::RoundsKey::U8,
    ];
    /// IV for MAC key derivation
    const ISAP_IV_KA: [u8; 8] = [
        0x02,
        Self::KeySizeBits::U8,
        Self::RateBits::U8,
        Self::RateSessionKeyBits::U8,
        Self::RoundsMAC::U8,
        Self::RoundsBit::U8,
        Self::RoundsEncryption::U8,
        Self::RoundsKey::U8,
    ];
    /// IV for encryption key derivation
    const ISAP_IV_KE: [u8; 8] = [
        0x03,
        Self::KeySizeBits::U8,
        Self::RateBits::U8,
        Self::RateSessionKeyBits::U8,
        Self::RoundsMAC::U8,
        Self::RoundsBit::U8,
        Self::RoundsEncryption::U8,
        Self::RoundsKey::U8,
    ];

    /// Process one full block of the message/ciphertext and encrypt/decrypt.
    fn isap_enc_process_block(state: &Self::State, buffer: &mut [u8]);
    /// Process the remaining bytes of the message/ciphertext and encrypt/decrypt.
    fn isap_enc_process_bytes(state: Self::State, buffer: &mut [u8]);

    /// Perform encryption
    fn isap_enc(key: &[u8; 16], nonce: &[u8; 16], mut buffer: &mut [u8]) {
        let mut state =
            isap_rk::<Self::State, Self::RoundsKey, Self::RoundsBit>(key, Self::ISAP_IV_KE, nonce);
        state.overwrite_bytes::<16, <<Self::State as AbsorbingState>::StateSize as U16Subtractable>::Output>(nonce);

        while buffer.len() >= Self::RateBytes::USIZE {
            state.permute_n::<Self::RoundsEncryption>();
            // process full block
            Self::isap_enc_process_block(&state, buffer);
            buffer = &mut buffer[Self::RateBytes::USIZE..];
        }

        if !buffer.is_empty() {
            state.permute_n::<Self::RoundsEncryption>();
            // process remaining bytes
            Self::isap_enc_process_bytes(state, buffer);
        }
    }

    /// Compute authentication tag
    fn isap_mac(
        k: &[u8; 16],
        nonce: &[u8; 16],
        associated_data: &[u8],
        ciphertext: &[u8],
    ) -> [u8; 16] {
        let mut state = Self::State::default();
        state.overwrite_bytes::<16, U0>(nonce);
        state.overwrite_bytes::<8, U16>(&Self::ISAP_IV_A);
        state.permute_n::<Self::RoundsMAC>();

        // absorb associated data
        state.absorb_bytes_pad_permute::<Self::RoundsMAC>(associated_data);
        // domain seperation
        state.seperate_domains();
        // absorb ciphertext
        state.absorb_bytes_pad_permute::<Self::RoundsMAC>(ciphertext);

        // derive Ka*
        let y: [u8; 16] = state.extract_bytes();
        let state2 =
            isap_rk::<Self::State, Self::RoundsKey, Self::RoundsBit>(k, Self::ISAP_IV_KA, &y);

        // squeeze tag
        state.overwrite_bytes::<16, U0>(&state2.extract_bytes());
        state.permute_n::<Self::RoundsMAC>();
        state.extract_bytes()
    }

    /// Full implementation of the ISAP encryption algorithm.
    fn encrypt_impl(
        key: &[u8; 16],
        nonce: &GenericArray<u8, U16>,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<[u8; 16]> {
        if !buffer.is_empty() {
            Self::isap_enc(key, nonce.as_ref(), buffer);
        }
        Ok(Self::isap_mac(key, nonce.as_ref(), associated_data, buffer))
    }

    /// Full implementation of the ISAP decryption algorithm.
    fn decrypt_impl(
        key: &[u8; 16],
        nonce: &GenericArray<u8, U16>,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &[u8],
    ) -> Result<()> {
        if bool::from(Self::isap_mac(key, nonce.as_ref(), associated_data, buffer).ct_eq(tag)) {
            if !buffer.is_empty() {
                Self::isap_enc(key, nonce.as_ref(), buffer);
            }
            Ok(())
        } else {
            Err(Error)
        }
    }
}

/// Derive session key `K_A^*` and `K_E^*`, respectively, from long term key `K`.
fn isap_rk<State: AbsorbingState, RoundsKey: Unsigned, RoundsBit: Unsigned>(
    k: &[u8; 16],
    iv: [u8; 8],
    input: &[u8],
) -> State {
    let mut state = State::default();
    state.overwrite_bytes::<16, U0>(k);
    state.overwrite_bytes::<8, U16>(&iv);
    state.permute_n::<RoundsKey>();

    for byte in &input[..input.len() - 1] {
        for bit_index in 0..8 {
            state.absorb_byte::<RoundsBit>((byte << bit_index) & 0x80);
            state.permute_n::<RoundsBit>();
        }
    }
    let byte = input[input.len() - 1];
    for bit_index in 0..7 {
        state.absorb_byte::<RoundsBit>((byte << bit_index) & 0x80);
        state.permute_n::<RoundsBit>();
    }
    state.absorb_byte::<RoundsKey>((byte << 7) & 0x80);
    state.permute_n::<RoundsKey>();

    state
}

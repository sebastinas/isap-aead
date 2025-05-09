// Copyright 2022 Sebastian Ramacher
// SPDX-License-Identifier: MIT

use aead::{
    KeySizeUser,
    consts::{U0, U1, U8, U12, U16, U18, U20, U50, U128, U144},
    generic_array::typenum::Unsigned,
};
use keccak::keccak_p;

use crate::{AbsorbingState, AeadCore, AeadInPlace, Isap, Key, KeyInit, Nonce, Result, Tag};

#[derive(Debug, Default)]
#[cfg_attr(feature = "zeroize", derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop))]
pub(crate) struct KeccakState {
    state: [u16; 25],
    idx: usize,
}

impl KeccakState {
    fn absorb_two_bytes<R: Unsigned>(&mut self, byte0: u8, byte1: u8) {
        debug_assert!(self.idx % 2 == 0);
        self.state[self.idx / 2] ^= u16::from_le_bytes([byte0, byte1]);
        self.idx += 2;
        if self.idx == Self::RATE {
            self.permute_n::<R>();
        }
    }
}

impl AbsorbingState for KeccakState {
    const RATE: usize = 18;
    type StateSize = U50;

    fn absorb_byte<R: Unsigned>(&mut self, byte: u8) {
        self.state[self.idx / 2] ^= (byte as u16) << ((self.idx % 2) * 8);
        self.idx += 1;
        if self.idx == Self::RATE {
            self.permute_n::<R>();
        }
    }

    fn absorb_bytes<R: Unsigned>(&mut self, mut bytes: &[u8]) {
        // process until full block reached
        if self.idx % 2 != 0 && !bytes.is_empty() {
            self.absorb_byte::<R>(bytes[0]);
            bytes = &bytes[1..];
        }

        // process full blocks
        let chunks = bytes.chunks_exact(2);
        let reminder = chunks.remainder();
        for chunk in chunks {
            self.absorb_two_bytes::<R>(chunk[0], chunk[1]);
        }

        // process remaining bytes
        if !reminder.is_empty() {
            self.absorb_byte::<R>(reminder[0]);
        }
    }

    fn permute_n<R: Unsigned>(&mut self) {
        keccak_p(&mut self.state, R::USIZE);
        self.idx = 0;
    }

    fn permute_n_if<R: Unsigned>(&mut self) {
        if self.idx != 0 {
            self.permute_n::<R>();
        }
    }

    fn seperate_domains(&mut self) {
        self.state[24] ^= 0x100;
    }

    fn extract_bytes<const LEN: usize>(&self) -> [u8; LEN] {
        debug_assert!(LEN % 2 == 0 && LEN <= 50);

        let mut ret = [0u8; LEN];
        for (idx, chunk) in ret.chunks_exact_mut(2).enumerate() {
            chunk.copy_from_slice(&u16::to_le_bytes(self.state[idx]));
        }
        ret
    }

    fn overwrite_bytes<const LEN: usize, O: Unsigned>(&mut self, bytes: &[u8; LEN]) {
        debug_assert!(LEN % 2 == 0);
        debug_assert!(O::USIZE % 2 == 0);
        debug_assert!(LEN + O::USIZE <= 50);

        for (idx, chunk) in bytes.chunks_exact(2).enumerate() {
            self.state[idx + O::USIZE / 2] = u16::from_le_bytes(chunk.try_into().unwrap());
        }
    }
}

/// ISAP-Keccask128
#[derive(Clone, Debug)]
#[cfg_attr(feature = "zeroize", derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop))]
pub struct IsapKeccak128 {
    k: [u8; 16],
}

impl Isap for IsapKeccak128 {
    type KeySizeBits = U128;
    type RateBits = U144;
    type RateBytes = U18;
    type RateSessionKeyBits = U1;
    type RoundsKey = U12;
    type RoundsBit = U12;
    type RoundsEncryption = U12;
    type RoundsMAC = U20;
    type State = KeccakState;

    fn isap_enc_process_block(state: &Self::State, buffer: &mut [u8]) {
        let key_stream: [u8; 18] = state.extract_bytes();
        // TODO: this is a mess, but faster
        let t = u64::from_ne_bytes(key_stream[..8].try_into().unwrap())
            ^ u64::from_ne_bytes(buffer[..8].try_into().unwrap());
        buffer[..8].copy_from_slice(&u64::to_ne_bytes(t));
        let t = u64::from_ne_bytes(key_stream[8..16].try_into().unwrap())
            ^ u64::from_ne_bytes(buffer[8..16].try_into().unwrap());
        buffer[8..16].copy_from_slice(&u64::to_ne_bytes(t));
        let t = u16::from_ne_bytes(key_stream[16..18].try_into().unwrap())
            ^ u16::from_ne_bytes(buffer[16..18].try_into().unwrap());
        buffer[16..18].copy_from_slice(&u16::to_ne_bytes(t));
    }

    fn isap_enc_process_bytes(state: Self::State, buffer: &mut [u8]) {
        let key_stream: [u8; 18] = state.extract_bytes();
        for (b, k) in buffer.iter_mut().zip(key_stream.into_iter()) {
            *b ^= k;
        }
    }
}

impl AeadCore for IsapKeccak128 {
    type NonceSize = U16;
    type TagSize = U16;
    type CiphertextOverhead = U0;
}

impl KeySizeUser for IsapKeccak128 {
    type KeySize = U16;
}

impl KeyInit for IsapKeccak128 {
    fn new(key: &Key<Self>) -> Self {
        Self { k: (*key).into() }
    }
}

impl AeadInPlace for IsapKeccak128 {
    fn encrypt_in_place_detached(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<Tag<Self>> {
        Self::encrypt_impl(&self.k, nonce, associated_data, buffer).map(Into::into)
    }

    fn decrypt_in_place_detached(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &Tag<Self>,
    ) -> Result<()> {
        Self::decrypt_impl(&self.k, nonce, associated_data, buffer, tag)
    }
}

/// ISAP-Keccak128A
#[derive(Clone, Debug)]
#[cfg_attr(feature = "zeroize", derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop))]
pub struct IsapKeccak128A {
    k: [u8; 16],
}

impl Isap for IsapKeccak128A {
    type KeySizeBits = U128;
    type RateBits = U144;
    type RateBytes = U18;
    type RateSessionKeyBits = U1;
    type RoundsKey = U8;
    type RoundsBit = U1;
    type RoundsEncryption = U8;
    type RoundsMAC = U16;
    type State = KeccakState;

    fn isap_enc_process_block(state: &Self::State, buffer: &mut [u8]) {
        let key_stream: [u8; 18] = state.extract_bytes();
        // TODO: this is a mess, but faster
        let t = u64::from_ne_bytes(key_stream[..8].try_into().unwrap())
            ^ u64::from_ne_bytes(buffer[..8].try_into().unwrap());
        buffer[..8].copy_from_slice(&u64::to_ne_bytes(t));
        let t = u64::from_ne_bytes(key_stream[8..16].try_into().unwrap())
            ^ u64::from_ne_bytes(buffer[8..16].try_into().unwrap());
        buffer[8..16].copy_from_slice(&u64::to_ne_bytes(t));
        let t = u16::from_ne_bytes(key_stream[16..18].try_into().unwrap())
            ^ u16::from_ne_bytes(buffer[16..18].try_into().unwrap());
        buffer[16..18].copy_from_slice(&u16::to_ne_bytes(t));
    }

    fn isap_enc_process_bytes(state: Self::State, buffer: &mut [u8]) {
        let key_stream: [u8; 18] = state.extract_bytes();
        for (b, k) in buffer.iter_mut().zip(key_stream.into_iter()) {
            *b ^= k;
        }
    }
}

impl AeadCore for IsapKeccak128A {
    type NonceSize = U16;
    type TagSize = U16;
    type CiphertextOverhead = U0;
}

impl KeySizeUser for IsapKeccak128A {
    type KeySize = U16;
}

impl KeyInit for IsapKeccak128A {
    fn new(key: &Key<Self>) -> Self {
        Self { k: (*key).into() }
    }
}

impl AeadInPlace for IsapKeccak128A {
    fn encrypt_in_place_detached(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<Tag<Self>> {
        Self::encrypt_impl(&self.k, nonce, associated_data, buffer).map(Into::into)
    }

    fn decrypt_in_place_detached(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &Tag<Self>,
    ) -> aead::Result<()> {
        Self::decrypt_impl(&self.k, nonce, associated_data, buffer, tag)
    }
}

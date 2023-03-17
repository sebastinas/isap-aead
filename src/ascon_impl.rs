// Copyright 2022 Sebastian Ramacher
// SPDX-License-Identifier: MIT

use aead::{
    consts::{U0, U1, U12, U128, U16, U40, U6, U64, U8},
    generic_array::typenum::Unsigned,
    KeySizeUser,
};
use ascon::State;

use crate::{AbsorbingState, AeadCore, AeadInPlace, Isap, Key, KeyInit, Nonce, Result, Tag};

#[derive(Debug, Default)]
pub(crate) struct AsconState {
    state: State,
    idx: usize,
}

impl From<State> for AsconState {
    fn from(state: State) -> Self {
        Self { state, idx: 0 }
    }
}

impl From<AsconState> for State {
    fn from(state: AsconState) -> Self {
        state.state
    }
}

impl AbsorbingState for AsconState {
    const RATE: usize = 8;
    type StateSize = U40;

    fn absorb_byte<R: Unsigned>(&mut self, byte: u8) {
        self.state[0] ^= (byte as u64) << ((7 - self.idx) * 8);
        self.idx += 1;
        if self.idx == Self::RATE {
            self.permute_n::<R>();
        }
    }

    fn absorb_bytes<R: Unsigned>(&mut self, mut bytes: &[u8]) {
        // process until full block reached
        while self.idx != 0 && !bytes.is_empty() {
            self.absorb_byte::<R>(bytes[0]);
            bytes = &bytes[1..];
        }

        // process full blocks
        while bytes.len() >= Self::RATE {
            self.state[0] ^= u64::from_be_bytes(bytes[..8].try_into().unwrap());
            self.permute_n::<R>();
            bytes = &bytes[Self::RATE..];
        }

        // process remaining bytes
        if !bytes.is_empty() {
            let mut tmp = [0u8; 8];
            tmp[0..bytes.len()].copy_from_slice(bytes);
            self.state[0] ^= u64::from_be_bytes(tmp);
            self.idx = bytes.len();
        }
    }

    fn permute_n<R: Unsigned>(&mut self) {
        if R::USIZE == 12 {
            self.state.permute_12()
        } else if R::USIZE == 8 {
            self.state.permute_8();
        } else if R::USIZE == 6 {
            self.state.permute_6();
        } else if R::USIZE == 1 {
            self.state.permute_1();
        } else {
            self.state.permute_n(R::USIZE);
        }
        self.idx = 0;
    }

    fn permute_n_if<R: Unsigned>(&mut self) {
        if self.idx != 0 {
            self.permute_n::<R>();
        }
    }

    fn seperate_domains(&mut self) {
        self.state[4] ^= 0x1;
    }

    fn extract_bytes<const LEN: usize>(&self) -> [u8; LEN] {
        debug_assert!(LEN % 8 == 0 && LEN <= 40);

        let mut ret = [0u8; LEN];
        for (idx, chunk) in ret.chunks_exact_mut(8).enumerate() {
            chunk.copy_from_slice(&u64::to_be_bytes(self.state[idx]));
        }
        ret
    }

    fn overwrite_bytes<const LEN: usize, O: Unsigned>(&mut self, bytes: &[u8; LEN]) {
        debug_assert!(LEN % 8 == 0);
        debug_assert!(O::USIZE % 8 == 0);
        debug_assert!(LEN + O::USIZE <= 40);

        for (idx, chunk) in bytes.chunks_exact(8).enumerate() {
            self.state[idx + O::USIZE / 8] = u64::from_be_bytes(chunk.try_into().unwrap());
        }
    }
}

/// ISAP-Ascon128
#[derive(Clone, Debug)]
#[cfg_attr(feature = "zeroize", derive(zeroize::ZeroizeOnDrop))]
pub struct IsapAscon128 {
    k: [u8; 16],
}

impl Isap for IsapAscon128 {
    type KeySizeBits = U128;
    type RateBits = U64;
    type RateBytes = U8;
    type RateSessionKeyBits = U1;
    type RoundsKey = U12;
    type RoundsBit = U12;
    type RoundsEncryption = U12;
    type RoundsMAC = U12;
    type State = AsconState;

    fn isap_enc_process_block(state: &Self::State, buffer: &mut [u8]) {
        let t = u64::from_ne_bytes(state.extract_bytes())
            ^ u64::from_ne_bytes(buffer[..8].try_into().unwrap());
        buffer[..8].copy_from_slice(&u64::to_ne_bytes(t));
    }

    fn isap_enc_process_bytes(state: Self::State, buffer: &mut [u8]) {
        let mut tmp = [0u8; 8];
        tmp[0..buffer.len()].copy_from_slice(buffer);
        buffer.copy_from_slice(
            &u64::to_ne_bytes(u64::from_ne_bytes(state.extract_bytes()) ^ u64::from_ne_bytes(tmp))
                [0..buffer.len()],
        );
    }
}

impl AeadCore for IsapAscon128 {
    type NonceSize = U16;
    type TagSize = U16;
    type CiphertextOverhead = U0;
}

impl KeySizeUser for IsapAscon128 {
    type KeySize = U16;
}

impl KeyInit for IsapAscon128 {
    fn new(key: &Key<Self>) -> Self {
        Self { k: (*key).into() }
    }
}

impl AeadInPlace for IsapAscon128 {
    fn encrypt_in_place_detached(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<Tag<Self>> {
        Self::encrypt_impl(&self.k, nonce, associated_data, buffer).map(|tag| tag.into())
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

/// ISAP-Ascon128A
#[derive(Clone, Debug)]
#[cfg_attr(feature = "zeroize", derive(zeroize::ZeroizeOnDrop))]
pub struct IsapAscon128A {
    k: [u8; 16],
}

impl Isap for IsapAscon128A {
    type KeySizeBits = U128;
    type RateBits = U64;
    type RateBytes = U8;
    type RateSessionKeyBits = U1;
    type RoundsKey = U12;
    type RoundsBit = U1;
    type RoundsEncryption = U6;
    type RoundsMAC = U12;
    type State = AsconState;

    fn isap_enc_process_block(state: &Self::State, buffer: &mut [u8]) {
        let t = u64::from_ne_bytes(state.extract_bytes())
            ^ u64::from_ne_bytes(buffer[..8].try_into().unwrap());
        buffer[..8].copy_from_slice(&u64::to_ne_bytes(t));
    }

    fn isap_enc_process_bytes(state: Self::State, buffer: &mut [u8]) {
        let mut tmp = [0u8; 8];
        tmp[0..buffer.len()].copy_from_slice(buffer);
        buffer.copy_from_slice(
            &u64::to_ne_bytes(u64::from_ne_bytes(state.extract_bytes()) ^ u64::from_ne_bytes(tmp))
                [0..buffer.len()],
        );
    }
}

impl AeadCore for IsapAscon128A {
    type NonceSize = U16;
    type TagSize = U16;
    type CiphertextOverhead = U0;
}

impl KeySizeUser for IsapAscon128A {
    type KeySize = U16;
}

impl KeyInit for IsapAscon128A {
    fn new(key: &Key<Self>) -> Self {
        Self { k: (*key).into() }
    }
}

impl AeadInPlace for IsapAscon128A {
    fn encrypt_in_place_detached(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<Tag<Self>> {
        Self::encrypt_impl(&self.k, nonce, associated_data, buffer).map(|tag| tag.into())
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

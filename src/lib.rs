use aead::consts::{U0, U16};
pub use aead::{self, AeadCore, AeadInPlace, Error, Key, NewAead, Nonce, Tag};
use ascon_core::{pad, State};
use subtle::ConstantTimeEq;

const ISAP_K: usize = 128;
const ISAP_RH: usize = 64;
const ISAP_RB: usize = 1;
const ISAP_SK: usize = 12;
const ISAP_SB: usize = 12;
const ISAP_SE: usize = 12;
const ISAP_SH: usize = 12;
const ISAP_IV_A: u64 = u64::from_be_bytes([
    0x01,
    ISAP_K as u8,
    ISAP_RH as u8,
    ISAP_RB as u8,
    ISAP_SH as u8,
    ISAP_SB as u8,
    ISAP_SE as u8,
    ISAP_SK as u8,
]);
const ISAP_IV_KA: u64 = u64::from_be_bytes([
    0x02,
    ISAP_K as u8,
    ISAP_RH as u8,
    ISAP_RB as u8,
    ISAP_SH as u8,
    ISAP_SB as u8,
    ISAP_SE as u8,
    ISAP_SK as u8,
]);
const ISAP_IV_KE: u64 = u64::from_be_bytes([
    0x03,
    ISAP_K as u8,
    ISAP_RH as u8,
    ISAP_RB as u8,
    ISAP_SH as u8,
    ISAP_SB as u8,
    ISAP_SE as u8,
    ISAP_SK as u8,
]);

fn isap_rk(k0: u64, k1: u64, iv: u64, mut input: &[u8]) -> State {
    let mut state = State::new(k0, k1, iv, 0, 0);
    state.permute_n(ISAP_SK);

    while input.len() > 1 {
        let byte = input[0];
        for bit_index in 0..8 {
            // FIXME: not BE safe
            state[0] ^= (((byte >> (7 - bit_index)) & 0x1) as u64) << 63;
            state.permute_n(ISAP_SB);
        }
        input = &input[1..];
    }
    let byte = input[0];
    for bit_index in 0..7 {
        // FIXME: not BE safe
        state[0] ^= (((byte >> (7 - bit_index)) & 0x1) as u64) << 63;
        state.permute_n(ISAP_SB);
    }
    // FIXME: not BE safe
    state[0] ^= (((byte) & 0x1) as u64) << 63;
    state.permute_n(ISAP_SK);

    state
}

fn isap_enc(mut state: State, nonce: [u64; 2], mut buffer: &mut [u8]) {
    state[3] = nonce[0];
    state[4] = nonce[1];

    while buffer.len() >= 8 {
        state.permute_n(ISAP_SE);
        // process full block
        let t = state[0] ^ u64::from_be_bytes(buffer[..8].try_into().unwrap());
        buffer[..8].copy_from_slice(&u64::to_be_bytes(t));

        buffer = &mut buffer[8..];
    }

    if !buffer.is_empty() {
        state.permute_n(ISAP_SE);
        let mut tmp = [0u8; 8];
        tmp[0..buffer.len()].copy_from_slice(buffer);
        buffer.copy_from_slice(
            &u64::to_be_bytes(state[0] ^ u64::from_be_bytes(tmp))[0..buffer.len()],
        );
    }
}

fn absorb(mut state: State, mut data: &[u8]) -> State {
    while data.len() >= 8 {
        // process full block
        state[0] ^= u64::from_be_bytes(data[..8].try_into().unwrap());
        state.permute_n(ISAP_SH);
        data = &data[8..]
    }
    state[0] ^= pad(data.len());
    if !data.is_empty() {
        let mut tmp = [0u8; 8];
        tmp[0..data.len()].copy_from_slice(data);
        state[0] ^= u64::from_be_bytes(tmp);
    }
    state.permute_n(ISAP_SH);
    state
}

fn isap_mac(
    k0: u64,
    k1: u64,
    nonce: [u64; 2],
    associated_data: &[u8],
    ciphertext: &[u8],
) -> [u8; 16] {
    let mut state = State::new(nonce[0], nonce[1], ISAP_IV_A, 0, 0);
    state.permute_n(ISAP_SH);

    // absorb associated data
    state = absorb(state, associated_data);
    // domain seperation
    state[4] ^= 0x01;
    // absorb ciphertext
    state = absorb(state, ciphertext);

    // derive Ka*
    let y = state.as_bytes();

    let state2 = isap_rk(k0, k1, ISAP_IV_KA, &y[..16]);
    state[0] = state2[0];
    state[1] = state2[1];
    state.permute_n(ISAP_SH);
    state.as_bytes()[..16].try_into().unwrap()
}

pub struct Isap {
    k: [u64; 2],
}

impl AeadCore for Isap {
    type NonceSize = U16;
    type TagSize = U16;
    type CiphertextOverhead = U0;
}

impl NewAead for Isap {
    type KeySize = U16;

    fn new(key: &Key<Self>) -> Self {
        Self {
            k: [
                u64::from_be_bytes(key[..8].try_into().unwrap()),
                u64::from_be_bytes(key[8..16].try_into().unwrap()),
            ],
        }
    }
}

impl AeadInPlace for Isap {
    fn encrypt_in_place_detached(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> aead::Result<Tag<Self>> {
        let nonce64 = [
            u64::from_be_bytes(nonce[..8].try_into().unwrap()),
            u64::from_be_bytes(nonce[8..16].try_into().unwrap()),
        ];

        let state = isap_rk(self.k[0], self.k[1], ISAP_IV_KE, nonce);
        isap_enc(state, nonce64, buffer);

        Ok(isap_mac(self.k[0], self.k[1], nonce64, associated_data, buffer).into())
    }

    fn decrypt_in_place_detached(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &Tag<Self>,
    ) -> aead::Result<()> {
        let nonce64 = [
            u64::from_be_bytes(nonce[..8].try_into().unwrap()),
            u64::from_be_bytes(nonce[8..16].try_into().unwrap()),
        ];

        if !bool::from(isap_mac(self.k[0], self.k[1], nonce64, associated_data, buffer).ct_eq(tag))
        {
            return Err(Error);
        }

        let state = isap_rk(self.k[0], self.k[1], ISAP_IV_KE, nonce);
        isap_enc(state, nonce64, buffer);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::ISAP_IV_A;

    #[test]
    fn constants() {
        assert_eq!(u64::to_be_bytes(ISAP_IV_A), [1, 128, 64, 1, 12, 12, 12, 12]);
    }
}

// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

use crate::core::constants::*;
use crate::core::errors::ProtocolError;
use crate::crypto::CryptoInterop;

const _: () = assert!(MAX_NONCE_COUNTER <= u16::MAX as u64);
const _: () = assert!(MAX_MESSAGE_INDEX <= u16::MAX as u64);

#[derive(Clone)]
pub struct NonceState {
    prefix: [u8; NONCE_PREFIX_BYTES],
    counter: u64,
}

impl NonceState {
    pub fn new(prefix: [u8; NONCE_PREFIX_BYTES], counter: u64) -> Result<Self, ProtocolError> {
        if counter >= MAX_NONCE_COUNTER {
            return Err(ProtocolError::invalid_state(
                "Nonce counter exceeds maximum",
            ));
        }
        Ok(Self { prefix, counter })
    }

    pub const fn prefix(&self) -> &[u8; NONCE_PREFIX_BYTES] {
        &self.prefix
    }

    pub const fn counter(&self) -> u64 {
        self.counter
    }
}

pub struct NonceGenerator {
    state: NonceState,
    max_counter: u64,
}

impl NonceGenerator {
    pub fn create() -> Result<Self, ProtocolError> {
        Self::create_with_limit(MAX_NONCE_COUNTER)
    }

    pub fn create_with_limit(max_counter: u64) -> Result<Self, ProtocolError> {
        let limit = if max_counter == 0 || max_counter > MAX_NONCE_COUNTER {
            MAX_NONCE_COUNTER
        } else {
            max_counter
        };
        let random = CryptoInterop::get_random_bytes(NONCE_PREFIX_BYTES);
        if random.len() != NONCE_PREFIX_BYTES {
            return Err(ProtocolError::generic("Failed to generate nonce prefix"));
        }
        let mut prefix = [0u8; NONCE_PREFIX_BYTES];
        prefix.copy_from_slice(&random[..NONCE_PREFIX_BYTES]);
        Ok(Self {
            state: NonceState { prefix, counter: 0 },
            max_counter: limit,
        })
    }

    pub fn from_state(state: NonceState) -> Result<Self, ProtocolError> {
        Self::from_state_with_limit(state, MAX_NONCE_COUNTER)
    }

    pub fn from_state_with_limit(
        state: NonceState,
        max_counter: u64,
    ) -> Result<Self, ProtocolError> {
        let limit = if max_counter == 0 || max_counter > MAX_NONCE_COUNTER {
            MAX_NONCE_COUNTER
        } else {
            max_counter
        };
        if state.counter >= limit {
            return Err(ProtocolError::invalid_state(
                "Nonce counter exceeds maximum",
            ));
        }
        Ok(Self {
            state,
            max_counter: limit,
        })
    }

    pub fn next(&mut self, message_index: u64) -> Result<[u8; AES_GCM_NONCE_BYTES], ProtocolError> {
        if message_index >= MAX_MESSAGE_INDEX {
            return Err(ProtocolError::invalid_input(
                "Message index exceeds nonce encoding limits",
            ));
        }
        if self.state.counter >= self.max_counter {
            return Err(ProtocolError::invalid_state(
                "Nonce counter overflow - rotate keys",
            ));
        }

        let mut nonce = [0u8; AES_GCM_NONCE_BYTES];
        nonce[..NONCE_PREFIX_BYTES].copy_from_slice(&self.state.prefix);

        let counter16 = u16::try_from(self.state.counter).map_err(|_| {
            ProtocolError::invalid_state("Nonce counter does not fit 16-bit encoding")
        })?;
        for i in 0..NONCE_COUNTER_BYTES {
            #[allow(clippy::cast_possible_truncation)]
            let byte = ((counter16 >> (i * 8)) & 0xFF) as u8;
            nonce[NONCE_PREFIX_BYTES + i] = byte;
        }

        let index16 = u16::try_from(message_index).map_err(|_| {
            ProtocolError::invalid_input("Message index does not fit 16-bit nonce encoding")
        })?;
        for i in 0..NONCE_INDEX_BYTES {
            #[allow(clippy::cast_possible_truncation)]
            let byte = ((index16 >> (i * 8)) & 0xFF) as u8;
            nonce[NONCE_PREFIX_BYTES + NONCE_COUNTER_BYTES + i] = byte;
        }

        self.state.counter += 1;
        Ok(nonce)
    }

    pub fn export_state(&self) -> NonceState {
        self.state.clone()
    }
}

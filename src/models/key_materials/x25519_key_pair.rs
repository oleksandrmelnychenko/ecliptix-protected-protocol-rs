// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

use crate::core::constants::X25519_PUBLIC_KEY_BYTES;
use crate::core::errors::ProtocolError;
use crate::crypto::SecureMemoryHandle;

pub struct X25519KeyPair {
    secret_key: SecureMemoryHandle,
    public_key: Vec<u8>,
}

impl std::fmt::Debug for X25519KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X25519KeyPair")
            .field("secret_key", &"[REDACTED]")
            .field("public_key_len", &self.public_key.len())
            .finish()
    }
}

impl X25519KeyPair {
    pub fn new(secret_key: SecureMemoryHandle, public_key: Vec<u8>) -> Result<Self, ProtocolError> {
        if public_key.len() != X25519_PUBLIC_KEY_BYTES {
            return Err(ProtocolError::invalid_input(
                "Invalid X25519 public key size",
            ));
        }
        Ok(Self {
            secret_key,
            public_key,
        })
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    pub fn public_key_vec(&self) -> Vec<u8> {
        self.public_key.clone()
    }

    pub const fn secret_key_handle(&self) -> &SecureMemoryHandle {
        &self.secret_key
    }

    pub const fn secret_key_handle_mut(&mut self) -> &mut SecureMemoryHandle {
        &mut self.secret_key
    }

    pub fn take(self) -> (SecureMemoryHandle, Vec<u8>) {
        (self.secret_key, self.public_key)
    }
}

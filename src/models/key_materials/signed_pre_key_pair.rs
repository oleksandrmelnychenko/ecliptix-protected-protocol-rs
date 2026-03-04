// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

use crate::core::constants::{ED25519_SIGNATURE_BYTES, X25519_PUBLIC_KEY_BYTES};
use crate::core::errors::ProtocolError;
use crate::crypto::SecureMemoryHandle;

pub struct SignedPreKeyPair {
    id: u32,
    secret_key: SecureMemoryHandle,
    public_key: Vec<u8>,
    signature: Vec<u8>,
}

impl std::fmt::Debug for SignedPreKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignedPreKeyPair")
            .field("id", &self.id)
            .field("secret_key", &"[REDACTED]")
            .field("public_key_len", &self.public_key.len())
            .finish_non_exhaustive()
    }
}

impl SignedPreKeyPair {
    pub fn new(
        id: u32,
        secret_key: SecureMemoryHandle,
        public_key: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<Self, ProtocolError> {
        if public_key.len() != X25519_PUBLIC_KEY_BYTES {
            return Err(ProtocolError::invalid_input("Invalid SPK public key size"));
        }
        if signature.len() != ED25519_SIGNATURE_BYTES {
            return Err(ProtocolError::invalid_input("Invalid SPK signature size"));
        }
        Ok(Self {
            id,
            secret_key,
            public_key,
            signature,
        })
    }

    pub const fn id(&self) -> u32 {
        self.id
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    pub fn public_key_vec(&self) -> Vec<u8> {
        self.public_key.clone()
    }

    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    pub fn signature_vec(&self) -> Vec<u8> {
        self.signature.clone()
    }

    pub const fn secret_key_handle(&self) -> &SecureMemoryHandle {
        &self.secret_key
    }

    pub const fn secret_key_handle_mut(&mut self) -> &mut SecureMemoryHandle {
        &mut self.secret_key
    }

    pub fn take(self) -> (SecureMemoryHandle, Vec<u8>, Vec<u8>) {
        (self.secret_key, self.public_key, self.signature)
    }
}

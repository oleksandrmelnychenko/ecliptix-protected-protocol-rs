// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

use crate::core::constants::{
    X25519_CLAMP_BYTE0, X25519_CLAMP_BYTE31_HIGH, X25519_CLAMP_BYTE31_LOW, X25519_PRIVATE_KEY_BYTES,
};
use crate::core::errors::ProtocolError;
use crate::crypto::{CryptoInterop, SecureMemoryHandle};
use x25519_dalek::{PublicKey, StaticSecret};

pub struct OneTimePreKey {
    id: u32,
    private_key: SecureMemoryHandle,
    public_key: Vec<u8>,
}

impl OneTimePreKey {
    pub fn generate(id: u32) -> Result<Self, ProtocolError> {
        let (handle, public_key) = CryptoInterop::generate_x25519_keypair("opk")?;
        Ok(Self {
            id,
            private_key: handle,
            public_key,
        })
    }

    pub fn create_from_seed(id: u32, seed: &[u8]) -> Result<Self, ProtocolError> {
        if seed.len() != X25519_PRIVATE_KEY_BYTES {
            return Err(ProtocolError::key_generation(
                "Invalid seed size for OPK derivation",
            ));
        }
        let mut private_key = seed.to_vec();
        private_key[0] &= X25519_CLAMP_BYTE0;
        private_key[31] &= X25519_CLAMP_BYTE31_LOW;
        private_key[31] |= X25519_CLAMP_BYTE31_HIGH;

        let sk_array: [u8; X25519_PRIVATE_KEY_BYTES] = private_key
            .as_slice()
            .try_into()
            .map_err(|_| ProtocolError::key_generation("Invalid seed size for OPK derivation"))?;
        let secret = StaticSecret::from(sk_array);
        let public = PublicKey::from(&secret);
        let public_key = public.as_bytes().to_vec();

        let mut handle = SecureMemoryHandle::allocate(X25519_PRIVATE_KEY_BYTES).map_err(|e| {
            CryptoInterop::secure_wipe(&mut private_key);
            ProtocolError::from_crypto(e)
        })?;
        handle.write(&private_key).map_err(|e| {
            CryptoInterop::secure_wipe(&mut private_key);
            ProtocolError::from_crypto(e)
        })?;
        CryptoInterop::secure_wipe(&mut private_key);

        Ok(Self {
            id,
            private_key: handle,
            public_key,
        })
    }

    pub const fn create_from_parts(
        id: u32,
        private_key: SecureMemoryHandle,
        public_key: Vec<u8>,
    ) -> Self {
        Self {
            id,
            private_key,
            public_key,
        }
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

    pub const fn private_key_handle(&self) -> &SecureMemoryHandle {
        &self.private_key
    }

    pub const fn private_key_handle_mut(&mut self) -> &mut SecureMemoryHandle {
        &mut self.private_key
    }
}

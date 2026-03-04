// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

use super::secure_memory::SecureMemoryHandle;
use crate::core::constants::{ED25519_SECRET_KEY_BYTES, X25519_PRIVATE_KEY_BYTES};
use crate::core::errors::{CryptoError, ProtocolError};
use ed25519_dalek::SigningKey;
use rand_core::{OsRng, RngCore};
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroize;

pub struct CryptoInterop;

impl CryptoInterop {
    pub const fn initialize() -> Result<(), CryptoError> {
        Ok(())
    }

    pub const fn is_initialized() -> bool {
        true
    }

    pub const fn ensure_initialized() {}

    pub fn secure_wipe(buffer: &mut [u8]) {
        buffer.zeroize();
    }

    pub fn constant_time_equals(a: &[u8], b: &[u8]) -> Result<bool, CryptoError> {
        if a.len() != b.len() {
            return Ok(false);
        }
        Ok(bool::from(a.ct_eq(b)))
    }

    pub fn generate_x25519_keypair(
        _label: &str,
    ) -> Result<(SecureMemoryHandle, Vec<u8>), ProtocolError> {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = X25519PublicKey::from(&secret);

        let pk = public.as_bytes().to_vec();
        let mut sk_bytes = secret.to_bytes();
        let mut sk_handle = SecureMemoryHandle::allocate(X25519_PRIVATE_KEY_BYTES)
            .map_err(ProtocolError::from_crypto)?;
        sk_handle
            .write(&sk_bytes)
            .map_err(ProtocolError::from_crypto)?;
        sk_bytes.zeroize();

        Ok((sk_handle, pk))
    }

    pub fn generate_ed25519_keypair() -> Result<(SecureMemoryHandle, Vec<u8>), ProtocolError> {
        let signing_key = SigningKey::generate(&mut OsRng);
        let pk = signing_key.verifying_key().to_bytes().to_vec();
        let mut sk_bytes = signing_key.to_keypair_bytes();

        let mut sk_handle = SecureMemoryHandle::allocate(ED25519_SECRET_KEY_BYTES)
            .map_err(ProtocolError::from_crypto)?;
        sk_handle
            .write(&sk_bytes)
            .map_err(ProtocolError::from_crypto)?;
        sk_bytes.zeroize();

        Ok((sk_handle, pk))
    }

    pub fn get_random_bytes(size: usize) -> Vec<u8> {
        let mut buf = vec![0u8; size];
        OsRng.fill_bytes(&mut buf);
        buf
    }

    pub fn generate_random_u32(ensure_non_zero: bool) -> u32 {
        loop {
            let val = OsRng.next_u32();
            if !ensure_non_zero || val != 0 {
                return val;
            }
        }
    }
}

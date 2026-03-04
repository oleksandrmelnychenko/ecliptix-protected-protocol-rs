// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

use crate::core::constants::{AES_GCM_NONCE_BYTES, AES_GCM_TAG_BYTES, AES_KEY_BYTES};
use crate::core::errors::ProtocolError;
use aes_gcm_siv::{
    aead::{Aead, KeyInit, Payload},
    Aes256GcmSiv, Key, Nonce,
};

pub struct AesGcm;

impl AesGcm {
    fn validate_key_nonce(key: &[u8], nonce: &[u8]) -> Result<(), ProtocolError> {
        if key.len() != AES_KEY_BYTES {
            return Err(ProtocolError::invalid_input(format!(
                "AES-256-GCM-SIV key must be {} bytes, got {}",
                AES_KEY_BYTES,
                key.len()
            )));
        }
        if nonce.len() != AES_GCM_NONCE_BYTES {
            return Err(ProtocolError::invalid_input(format!(
                "AES-256-GCM-SIV nonce must be {} bytes, got {}",
                AES_GCM_NONCE_BYTES,
                nonce.len()
            )));
        }
        Ok(())
    }

    pub fn encrypt(
        key: &[u8],
        nonce: &[u8],
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, ProtocolError> {
        Self::validate_key_nonce(key, nonce)?;
        let key = Key::<Aes256GcmSiv>::from_slice(key);
        let cipher = Aes256GcmSiv::new(key);
        let nonce = Nonce::from_slice(nonce);
        let payload = Payload {
            msg: plaintext,
            aad: associated_data,
        };
        cipher
            .encrypt(nonce, payload)
            .map_err(|_| ProtocolError::generic("AES-256-GCM-SIV encryption failed"))
    }

    pub fn decrypt(
        key: &[u8],
        nonce: &[u8],
        ciphertext_with_tag: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, ProtocolError> {
        Self::validate_key_nonce(key, nonce)?;
        if ciphertext_with_tag.len() < AES_GCM_TAG_BYTES {
            return Err(ProtocolError::invalid_input(format!(
                "Ciphertext too small: {} bytes (minimum {} for tag)",
                ciphertext_with_tag.len(),
                AES_GCM_TAG_BYTES
            )));
        }
        let key = Key::<Aes256GcmSiv>::from_slice(key);
        let cipher = Aes256GcmSiv::new(key);
        let nonce = Nonce::from_slice(nonce);
        let payload = Payload {
            msg: ciphertext_with_tag,
            aad: associated_data,
        };
        cipher.decrypt(nonce, payload).map_err(|_| {
            ProtocolError::generic(
                "Authentication tag verification failed - data may have been tampered with",
            )
        })
    }
}

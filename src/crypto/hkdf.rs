// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

use crate::core::errors::ProtocolError;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::core::constants::HKDF_MAX_OUTPUT_BYTES;

const MAX_OUTPUT_LEN: usize = HKDF_MAX_OUTPUT_BYTES;

pub struct HkdfSha256;

impl HkdfSha256 {
    pub fn derive_key_bytes(
        ikm: &[u8],
        out_len: usize,
        salt: &[u8],
        info: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
        if out_len == 0 || out_len > MAX_OUTPUT_LEN {
            return Err(ProtocolError::derive_key(format!(
                "Invalid HKDF output length: {out_len}"
            )));
        }
        let salt_opt = if salt.is_empty() { None } else { Some(salt) };
        let (prk_arr, _) = Hkdf::<Sha256>::extract(salt_opt, ikm);
        let prk = Zeroizing::new(prk_arr.to_vec());
        let hk = Hkdf::<Sha256>::from_prk(&prk)
            .map_err(|e| ProtocolError::derive_key(format!("Invalid PRK for HKDF: {e}")))?;
        let mut okm = Zeroizing::new(vec![0u8; out_len]);
        hk.expand(info, &mut okm)
            .map_err(|e| ProtocolError::derive_key(format!("HKDF expand failed: {e}")))?;
        Ok(okm)
    }

    pub fn extract(salt: &[u8], ikm: &[u8]) -> Zeroizing<Vec<u8>> {
        let salt_opt = if salt.is_empty() { None } else { Some(salt) };
        let (prk, _) = Hkdf::<Sha256>::extract(salt_opt, ikm);
        Zeroizing::new(prk.to_vec())
    }

    pub fn expand(
        prk: &[u8],
        info: &[u8],
        out_len: usize,
    ) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
        if out_len == 0 || out_len > MAX_OUTPUT_LEN {
            return Err(ProtocolError::derive_key(format!(
                "Invalid HKDF output length: {out_len}"
            )));
        }
        let hk = Hkdf::<Sha256>::from_prk(prk)
            .map_err(|e| ProtocolError::derive_key(format!("Invalid PRK for HKDF expand: {e}")))?;
        let mut okm = Zeroizing::new(vec![0u8; out_len]);
        hk.expand(info, &mut okm)
            .map_err(|e| ProtocolError::derive_key(format!("HKDF expand failed: {e}")))?;
        Ok(okm)
    }
}

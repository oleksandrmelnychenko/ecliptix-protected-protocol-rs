// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

use blake2::digest::consts::U32;
use blake2::digest::Mac;
use blake2::Blake2bMac;

use crate::core::errors::ProtocolError;

pub struct Blake2bHash;

impl Blake2bHash {
    pub fn keyed_hash(key: &[u8], data: &[u8]) -> Result<Vec<u8>, ProtocolError> {
        let mut mac = Blake2bMac::<U32>::new_from_slice(key)
            .map_err(|e| ProtocolError::derive_key(format!("BLAKE2b-MAC init: {e}")))?;
        mac.update(data);
        Ok(mac.finalize().into_bytes().to_vec())
    }
}

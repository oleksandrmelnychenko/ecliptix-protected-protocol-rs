// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

use crate::core::constants::MESSAGE_PADDING_BLOCK_SIZE;
use crate::core::errors::ProtocolError;

pub struct MessagePadding;

impl MessagePadding {
    pub fn pad(plaintext: &[u8]) -> Vec<u8> {
        let padded_len = Self::padded_length(plaintext.len());
        let mut buf = Vec::with_capacity(padded_len);
        buf.extend_from_slice(plaintext);
        buf.push(0x01);
        buf.resize(padded_len, 0x00);
        buf
    }

    pub fn unpad(padded: &[u8]) -> Result<Vec<u8>, ProtocolError> {
        if padded.is_empty() {
            return Err(ProtocolError::decode("Invalid padding: empty input"));
        }
        if padded.len() % MESSAGE_PADDING_BLOCK_SIZE != 0 {
            return Err(ProtocolError::decode("Invalid padding: not block-aligned"));
        }

        let mut found_pos: usize = 0;
        let mut found: usize = 0;

        for (i, &byte) in padded.iter().enumerate() {
            let diff = byte ^ 0x01;
            let is_nonzero = ((u16::from(diff) | u16::from(diff).wrapping_neg()) >> 7) as usize & 1;
            let mask = is_nonzero.wrapping_sub(1);

            found_pos = (found_pos & !mask) | (i & mask);
            found |= mask & 1;
        }

        if found == 0 {
            return Err(ProtocolError::decode(
                "Invalid padding: no sentinel byte found",
            ));
        }

        let mut non_zero_after_sentinel: u8 = 0;
        for &byte in &padded[found_pos + 1..] {
            non_zero_after_sentinel |= byte;
        }
        if non_zero_after_sentinel != 0 {
            return Err(ProtocolError::decode(
                "Invalid padding: non-zero bytes after sentinel",
            ));
        }

        Ok(padded[..found_pos].to_vec())
    }

    const fn padded_length(plaintext_len: usize) -> usize {
        let with_sentinel = plaintext_len + 1;
        let blocks = with_sentinel.div_ceil(MESSAGE_PADDING_BLOCK_SIZE);
        blocks * MESSAGE_PADDING_BLOCK_SIZE
    }
}

// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

use crate::core::errors::ProtocolError;
use crate::interfaces::IKeyProvider;

pub struct ChainKey {
    provider: Box<dyn IKeyProvider>,
    index: u32,
}

impl ChainKey {
    pub fn new(provider: Box<dyn IKeyProvider>, index: u32) -> Self {
        Self { provider, index }
    }

    pub const fn index(&self) -> u32 {
        self.index
    }

    pub fn with_key_material<F, R>(&self, f: F) -> Result<R, ProtocolError>
    where
        F: FnOnce(&[u8]) -> Result<R, ProtocolError>,
    {
        let bytes = self.provider.get_key_bytes()?;
        f(&bytes)
    }
}

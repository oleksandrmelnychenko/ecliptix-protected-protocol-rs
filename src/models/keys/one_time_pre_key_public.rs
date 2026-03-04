// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

#[derive(Clone)]
pub struct OneTimePreKeyPublic {
    id: u32,
    public_key: Vec<u8>,
    kyber_public: Option<Vec<u8>>,
}

impl OneTimePreKeyPublic {
    pub const fn new(id: u32, public_key: Vec<u8>, kyber_public: Option<Vec<u8>>) -> Self {
        Self {
            id,
            public_key,
            kyber_public,
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

    pub fn kyber_public(&self) -> Option<&[u8]> {
        self.kyber_public.as_deref()
    }
}

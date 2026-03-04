// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

use crate::crypto::SecureMemoryHandle;
use crate::models::key_materials::{Ed25519KeyPair, SignedPreKeyPair, X25519KeyPair};
use crate::models::keys::OneTimePreKey;

pub struct IdentityKeyBundle {
    pub ed25519: Ed25519KeyPair,
    pub identity_x25519: X25519KeyPair,
    pub signed_pre_key: SignedPreKeyPair,
    pub one_time_pre_keys: Vec<OneTimePreKey>,
    pub kyber_secret_key: SecureMemoryHandle,
    pub kyber_public: Vec<u8>,
}

impl IdentityKeyBundle {
    pub const fn new(
        ed25519: Ed25519KeyPair,
        identity_x25519: X25519KeyPair,
        signed_pre_key: SignedPreKeyPair,
        one_time_pre_keys: Vec<OneTimePreKey>,
        kyber_secret_key: SecureMemoryHandle,
        kyber_public: Vec<u8>,
    ) -> Self {
        Self {
            ed25519,
            identity_x25519,
            signed_pre_key,
            one_time_pre_keys,
            kyber_secret_key,
            kyber_public,
        }
    }
}

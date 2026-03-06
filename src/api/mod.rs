// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

pub mod relay;

use prost::Message;
use zeroize::Zeroizing;

use crate::core::constants::{
    AES_GCM_NONCE_BYTES, AES_GCM_TAG_BYTES, DEFAULT_MESSAGES_PER_CHAIN, MAX_BUFFER_SIZE,
    MAX_ENVELOPE_MESSAGE_SIZE, OPAQUE_ROOT_INFO, OPAQUE_SESSION_KEY_BYTES, PROTOCOL_VERSION,
};
use crate::core::errors::ProtocolError;
use crate::crypto::{CryptoInterop, HkdfSha256, SecureMemoryHandle, ShamirSecretSharing};
use crate::identity::IdentityKeys;
use crate::interfaces::StaticStateKeyProvider;
use crate::proto::{GroupKeyPackage, OneTimePreKey, PreKeyBundle, SecureEnvelope};
use crate::protocol::group::{self, GroupSecurityPolicy, GroupSession};
use crate::protocol::{HandshakeInitiator, HandshakeResponder, Session};

pub struct DecryptResult {
    pub plaintext: Vec<u8>,
    pub metadata: Vec<u8>,
}

pub struct SessionIdentity {
    pub ed25519_public: Vec<u8>,
    pub x25519_public: Vec<u8>,
}

pub struct EcliptixSession(Session);

impl EcliptixSession {
    pub fn encrypt(
        &mut self,
        plaintext: &[u8],
        envelope_type: i32,
        id: u32,
        correlation_id: Option<&str>,
    ) -> Result<Vec<u8>, ProtocolError> {
        let envelope = self
            .0
            .encrypt(plaintext, envelope_type, id, correlation_id)?;
        let mut buf = Vec::new();
        envelope
            .encode(&mut buf)
            .map_err(|e| ProtocolError::encode(format!("Failed to encode SecureEnvelope: {e}")))?;
        Ok(buf)
    }

    pub fn decrypt(&mut self, envelope_bytes: &[u8]) -> Result<DecryptResult, ProtocolError> {
        let envelope = SecureEnvelope::decode(envelope_bytes)
            .map_err(|e| ProtocolError::decode(format!("Failed to decode SecureEnvelope: {e}")))?;
        let result = self.0.decrypt(&envelope)?;
        let mut meta_buf = Vec::new();
        result
            .metadata
            .encode(&mut meta_buf)
            .map_err(|e| ProtocolError::encode(format!("Failed to encode metadata: {e}")))?;
        Ok(DecryptResult {
            plaintext: result.plaintext,
            metadata: meta_buf,
        })
    }

    pub fn serialize(&self, key: &[u8], external_counter: u64) -> Result<Vec<u8>, ProtocolError> {
        let provider = StaticStateKeyProvider::new(key.to_vec())?;
        self.0.export_sealed_state(&provider, external_counter)
    }

    pub fn deserialize(
        data: &[u8],
        key: &[u8],
        min_external_counter: u64,
    ) -> Result<(Self, u64), ProtocolError> {
        let external_counter = Session::sealed_state_external_counter(data)?;
        let provider = StaticStateKeyProvider::new(key.to_vec())?;
        let session = Session::from_sealed_state(data, &provider, min_external_counter)?;
        Ok((Self(session), external_counter))
    }

    pub fn sealed_external_counter(data: &[u8]) -> Result<u64, ProtocolError> {
        Session::sealed_state_external_counter(data)
    }

    pub fn nonce_remaining(&self) -> Result<u64, ProtocolError> {
        self.0.nonce_remaining()
    }

    pub fn session_id(&self) -> Vec<u8> {
        self.0.get_session_id()
    }

    pub fn peer_identity(&self) -> SessionIdentity {
        let peer = self.0.get_peer_identity();
        SessionIdentity {
            ed25519_public: peer.ed25519_public.clone(),
            x25519_public: peer.x25519_public.clone(),
        }
    }

    pub fn local_identity(&self) -> SessionIdentity {
        let local = self.0.get_local_identity();
        SessionIdentity {
            ed25519_public: local.ed25519_public.clone(),
            x25519_public: local.x25519_public.clone(),
        }
    }

    pub fn identity_binding_hash(&self) -> Vec<u8> {
        self.0.get_identity_binding_hash()
    }
}

pub struct EcliptixInitiator(HandshakeInitiator);

impl EcliptixInitiator {
    pub fn complete(self, ack_bytes: &[u8]) -> Result<EcliptixSession, ProtocolError> {
        let session = self.0.finish(ack_bytes)?;
        Ok(EcliptixSession(session))
    }
}

pub struct EcliptixResponder(HandshakeResponder);

impl EcliptixResponder {
    pub fn complete(self) -> Result<EcliptixSession, ProtocolError> {
        let session = self.0.finish()?;
        Ok(EcliptixSession(session))
    }
}

pub struct EcliptixProtocol {
    identity: IdentityKeys,
    max_messages: u32,
}

impl EcliptixProtocol {
    pub fn new(opk_count: u32) -> Result<Self, ProtocolError> {
        let identity = IdentityKeys::create(opk_count)?;
        #[allow(clippy::cast_possible_truncation)]
        let max_messages = DEFAULT_MESSAGES_PER_CHAIN as u32;
        Ok(Self {
            identity,
            max_messages,
        })
    }

    pub fn from_seed(
        seed: &[u8],
        membership_id: &str,
        opk_count: u32,
    ) -> Result<Self, ProtocolError> {
        let identity = IdentityKeys::create_from_master_key(seed, membership_id, opk_count)?;
        #[allow(clippy::cast_possible_truncation)]
        let max_messages = DEFAULT_MESSAGES_PER_CHAIN as u32;
        Ok(Self {
            identity,
            max_messages,
        })
    }

    pub fn get_identity_ed25519_private_key_copy(
        &self,
    ) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
        self.identity.get_identity_ed25519_private_key_copy()
    }

    pub fn identity_ed25519_public(&self) -> Vec<u8> {
        self.identity.get_identity_ed25519_public()
    }

    pub fn identity_x25519_public(&self) -> Vec<u8> {
        self.identity.get_identity_x25519_public()
    }

    pub fn pre_key_bundle(&self) -> Result<Vec<u8>, ProtocolError> {
        let bundle = self.identity.create_public_bundle()?;

        let opks: Vec<OneTimePreKey> = bundle
            .one_time_pre_keys()
            .iter()
            .map(|opk| OneTimePreKey {
                one_time_pre_key_id: opk.id(),
                public_key: opk.public_key_vec(),
            })
            .collect();

        let proto_bundle = PreKeyBundle {
            version: PROTOCOL_VERSION,
            identity_ed25519_public: bundle.identity_ed25519_public().to_vec(),
            identity_x25519_public: bundle.identity_x25519_public().to_vec(),
            identity_x25519_signature: bundle.identity_x25519_signature().to_vec(),
            signed_pre_key_id: bundle.signed_pre_key_id(),
            signed_pre_key_public: bundle.signed_pre_key_public().to_vec(),
            signed_pre_key_signature: bundle.signed_pre_key_signature().to_vec(),
            one_time_pre_keys: opks,
            kyber_public: bundle.kyber_public().unwrap_or(&[]).to_vec(),
        };

        let mut buf = Vec::new();
        proto_bundle
            .encode(&mut buf)
            .map_err(|e| ProtocolError::encode(format!("Failed to encode PreKeyBundle: {e}")))?;
        Ok(buf)
    }

    pub fn begin_session(
        &mut self,
        peer_bundle_bytes: &[u8],
    ) -> Result<(EcliptixInitiator, Vec<u8>), ProtocolError> {
        let peer_bundle = PreKeyBundle::decode(peer_bundle_bytes).map_err(|e| {
            ProtocolError::decode(format!("Failed to decode peer PreKeyBundle: {e}"))
        })?;

        let initiator =
            HandshakeInitiator::start(&mut self.identity, &peer_bundle, self.max_messages)?;
        let init_bytes = initiator.encoded_message().to_vec();

        Ok((EcliptixInitiator(initiator), init_bytes))
    }

    pub fn accept_session(
        &mut self,
        init_bytes: &[u8],
    ) -> Result<(EcliptixResponder, Vec<u8>), ProtocolError> {
        let local_bundle_bytes = self.pre_key_bundle()?;
        let local_bundle = PreKeyBundle::decode(local_bundle_bytes.as_slice()).map_err(|e| {
            ProtocolError::decode(format!("Failed to decode local PreKeyBundle: {e}"))
        })?;

        let responder = HandshakeResponder::process(
            &mut self.identity,
            &local_bundle,
            init_bytes,
            self.max_messages,
        )?;
        let ack_bytes = responder.encoded_ack().to_vec();

        Ok((EcliptixResponder(responder), ack_bytes))
    }

    pub fn generate_key_package(
        &self,
        credential: Vec<u8>,
    ) -> Result<(Vec<u8>, SecureMemoryHandle, SecureMemoryHandle), ProtocolError> {
        let (kp, x25519_priv, kyber_sec) =
            group::key_package::create_key_package(&self.identity, credential)?;
        let mut buf = Vec::new();
        kp.encode(&mut buf)
            .map_err(|e| ProtocolError::encode(format!("KeyPackage encode: {e}")))?;
        Ok((buf, x25519_priv, kyber_sec))
    }

    pub fn create_group(&self, credential: Vec<u8>) -> Result<EcliptixGroupSession, ProtocolError> {
        let session = GroupSession::create(&self.identity, credential)?;
        Ok(EcliptixGroupSession(session))
    }

    pub fn create_shielded_group(
        &self,
        credential: Vec<u8>,
    ) -> Result<EcliptixGroupSession, ProtocolError> {
        let session = GroupSession::create_with_policy(
            &self.identity,
            credential,
            GroupSecurityPolicy::shield(),
        )?;
        Ok(EcliptixGroupSession(session))
    }

    pub fn create_group_with_policy(
        &self,
        credential: Vec<u8>,
        policy: GroupSecurityPolicy,
    ) -> Result<EcliptixGroupSession, ProtocolError> {
        let session = GroupSession::create_with_policy(&self.identity, credential, policy)?;
        Ok(EcliptixGroupSession(session))
    }

    pub fn join_group(
        &self,
        welcome_bytes: &[u8],
        x25519_private: SecureMemoryHandle,
        kyber_secret: SecureMemoryHandle,
    ) -> Result<EcliptixGroupSession, ProtocolError> {
        let ed25519_secret = self.identity.get_identity_ed25519_private_key_copy()?;
        let session = GroupSession::from_welcome(
            welcome_bytes,
            x25519_private,
            kyber_secret,
            &self.identity.get_identity_ed25519_public(),
            &self.identity.get_identity_x25519_public(),
            ed25519_secret,
        )?;
        Ok(EcliptixGroupSession(session))
    }

    pub fn join_group_external(
        &self,
        public_state_bytes: &[u8],
        authorization_bytes: &[u8],
        credential: Vec<u8>,
    ) -> Result<(EcliptixGroupSession, Vec<u8>), ProtocolError> {
        let (session, commit_bytes) = GroupSession::from_external_join(
            public_state_bytes,
            authorization_bytes,
            &self.identity,
            credential,
        )?;
        Ok((EcliptixGroupSession(session), commit_bytes))
    }

    pub fn validate_envelope(envelope_bytes: &[u8]) -> Result<(), ProtocolError> {
        if envelope_bytes.len() > MAX_ENVELOPE_MESSAGE_SIZE {
            return Err(ProtocolError::invalid_input("Message too large"));
        }
        let envelope = SecureEnvelope::decode(envelope_bytes)
            .map_err(|e| ProtocolError::decode(format!("Failed to parse envelope: {e}")))?;
        if envelope.version != PROTOCOL_VERSION {
            return Err(ProtocolError::invalid_input("Invalid envelope version"));
        }
        if envelope.encrypted_metadata.len() <= AES_GCM_TAG_BYTES {
            return Err(ProtocolError::invalid_input("Encrypted metadata too small"));
        }
        if envelope.encrypted_payload.len() < AES_GCM_TAG_BYTES {
            return Err(ProtocolError::invalid_input("Encrypted payload too small"));
        }
        if envelope.header_nonce.len() != AES_GCM_NONCE_BYTES {
            return Err(ProtocolError::invalid_input("Invalid header nonce size"));
        }
        if envelope.header_nonce.iter().all(|&b| b == 0) {
            return Err(ProtocolError::invalid_input(
                "Header nonce must not be all zeros",
            ));
        }
        Ok(())
    }

    pub fn derive_root_key(
        opaque_session_key: &[u8],
        user_context: &[u8],
        output_length: usize,
    ) -> Result<Vec<u8>, ProtocolError> {
        if opaque_session_key.len() != OPAQUE_SESSION_KEY_BYTES {
            return Err(ProtocolError::invalid_input(
                "OPAQUE session key must be 32 bytes",
            ));
        }
        if user_context.is_empty() || user_context.len() > MAX_BUFFER_SIZE {
            return Err(ProtocolError::invalid_input(
                "OPAQUE user context length invalid",
            ));
        }
        if output_length == 0 || output_length > 64 {
            return Err(ProtocolError::invalid_input(
                "OPAQUE output length must be in the range 1..=64",
            ));
        }
        let key = HkdfSha256::derive_key_bytes(
            opaque_session_key,
            output_length,
            user_context,
            OPAQUE_ROOT_INFO,
        )?;
        Ok(key.to_vec())
    }

    pub fn shamir_split(
        secret: &[u8],
        threshold: u8,
        share_count: u8,
        auth_key: &[u8],
    ) -> Result<Vec<Vec<u8>>, ProtocolError> {
        ShamirSecretSharing::split(secret, threshold, share_count, auth_key)
    }

    pub fn shamir_reconstruct(
        shares: &[Vec<u8>],
        auth_key: &[u8],
        threshold: usize,
    ) -> Result<Vec<u8>, ProtocolError> {
        ShamirSecretSharing::reconstruct(shares, auth_key, threshold)
    }

    pub fn secure_wipe(data: &mut [u8]) {
        CryptoInterop::secure_wipe(data);
    }
}

pub struct EcliptixGroupSession(GroupSession);

impl EcliptixGroupSession {
    pub fn add_member(
        &self,
        key_package_bytes: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), ProtocolError> {
        let kp = GroupKeyPackage::decode(key_package_bytes)
            .map_err(|e| ProtocolError::decode(format!("KeyPackage decode: {e}")))?;
        self.0.add_member(&kp)
    }

    pub fn remove_member(&self, leaf_index: u32) -> Result<Vec<u8>, ProtocolError> {
        self.0.remove_member(leaf_index)
    }

    pub fn update(&self) -> Result<Vec<u8>, ProtocolError> {
        self.0.update()
    }

    pub fn process_commit(&self, commit_bytes: &[u8]) -> Result<(), ProtocolError> {
        self.0.process_commit(commit_bytes)
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, ProtocolError> {
        self.0.encrypt(plaintext)
    }

    pub fn decrypt(
        &self,
        message_bytes: &[u8],
    ) -> Result<group::GroupDecryptResult, ProtocolError> {
        self.0.decrypt(message_bytes)
    }

    pub fn group_id(&self) -> Result<Vec<u8>, ProtocolError> {
        self.0.group_id()
    }

    pub fn epoch(&self) -> Result<u64, ProtocolError> {
        self.0.epoch()
    }

    pub fn my_leaf_index(&self) -> Result<u32, ProtocolError> {
        self.0.my_leaf_index()
    }

    pub fn member_count(&self) -> Result<u32, ProtocolError> {
        self.0.member_count()
    }

    pub fn member_leaf_indices(&self) -> Result<Vec<u32>, ProtocolError> {
        self.0.member_leaf_indices()
    }

    pub fn export_public_state(&self) -> Result<Vec<u8>, ProtocolError> {
        self.0.export_public_state()
    }

    pub fn authorize_external_join(
        &self,
        joiner_identity_ed25519_public: &[u8],
        joiner_identity_x25519_public: &[u8],
        joiner_credential: &[u8],
    ) -> Result<Vec<u8>, ProtocolError> {
        self.0.authorize_external_join(
            joiner_identity_ed25519_public,
            joiner_identity_x25519_public,
            joiner_credential,
        )
    }

    pub fn set_psk_resolver(
        &self,
        resolver: Box<dyn group::PskResolver>,
    ) -> Result<(), ProtocolError> {
        self.0.set_psk_resolver(resolver)
    }

    pub fn pending_reinit(&self) -> Result<Option<group::ReInitInfo>, ProtocolError> {
        self.0.pending_reinit()
    }

    pub fn encrypt_sealed(&self, plaintext: &[u8], hint: &[u8]) -> Result<Vec<u8>, ProtocolError> {
        self.0.encrypt_sealed(plaintext, hint)
    }

    pub fn encrypt_disappearing(
        &self,
        plaintext: &[u8],
        ttl_seconds: u32,
    ) -> Result<Vec<u8>, ProtocolError> {
        self.0.encrypt_disappearing(plaintext, ttl_seconds)
    }

    pub fn encrypt_frankable(&self, plaintext: &[u8]) -> Result<Vec<u8>, ProtocolError> {
        self.0.encrypt_frankable(plaintext)
    }

    pub fn encrypt_with_policy(
        &self,
        plaintext: &[u8],
        policy: &group::MessagePolicy,
    ) -> Result<Vec<u8>, ProtocolError> {
        self.0.encrypt_with_policy(plaintext, policy)
    }

    pub fn encrypt_edit(
        &self,
        new_content: &[u8],
        target_message_id: &[u8],
    ) -> Result<Vec<u8>, ProtocolError> {
        self.0.encrypt_edit(new_content, target_message_id)
    }

    pub fn encrypt_delete(&self, target_message_id: &[u8]) -> Result<Vec<u8>, ProtocolError> {
        self.0.encrypt_delete(target_message_id)
    }

    pub fn compute_message_id(
        group_id: &[u8],
        epoch: u64,
        sender_leaf: u32,
        generation: u32,
    ) -> Vec<u8> {
        group::compute_message_id(group_id, epoch, sender_leaf, generation)
    }

    pub fn reveal_sealed(sealed: &group::SealedPayload) -> Result<Vec<u8>, ProtocolError> {
        GroupSession::reveal_sealed(sealed)
    }

    pub fn verify_franking(data: &group::FrankingData) -> Result<bool, ProtocolError> {
        GroupSession::verify_franking(data)
    }

    pub fn serialize(&self, key: &[u8], external_counter: u64) -> Result<Vec<u8>, ProtocolError> {
        self.0.export_sealed_state(key, external_counter)
    }

    pub fn deserialize(
        data: &[u8],
        key: &[u8],
        ed25519_secret: Zeroizing<Vec<u8>>,
        min_external_counter: u64,
    ) -> Result<(Self, u64), ProtocolError> {
        let external_counter = GroupSession::sealed_state_external_counter(data)?;
        let session =
            GroupSession::from_sealed_state(data, key, ed25519_secret, min_external_counter)?;
        Ok((Self(session), external_counter))
    }

    pub fn sealed_external_counter(data: &[u8]) -> Result<u64, ProtocolError> {
        GroupSession::sealed_state_external_counter(data)
    }

    pub fn is_shielded(&self) -> Result<bool, ProtocolError> {
        self.0.is_shielded()
    }

    pub fn security_policy(&self) -> Result<GroupSecurityPolicy, ProtocolError> {
        self.0.security_policy()
    }
}

// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

use prost::Message;

use crate::core::constants::*;
use crate::core::errors::ProtocolError;
use crate::proto::e2e::{CryptoEnvelope, CryptoPayloadType};
use crate::proto::{GroupCommit, GroupKeyPackage, GroupMessage, GroupWelcome};
use crate::protocol::group::key_package;

#[derive(Debug, Clone)]
pub struct GroupMemberRecord {
    pub leaf_index: u32,
    pub identity_ed25519_public: Vec<u8>,
    pub identity_x25519_public: Vec<u8>,
    pub credential: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct GroupRoster {
    pub group_id: Vec<u8>,
    pub epoch: u64,
    pub members: Vec<GroupMemberRecord>,
}

impl GroupRoster {
    pub fn new(group_id: Vec<u8>, creator: GroupMemberRecord) -> Self {
        Self {
            group_id,
            epoch: 0,
            members: vec![creator],
        }
    }

    pub fn find_member(&self, leaf_index: u32) -> Option<&GroupMemberRecord> {
        self.members.iter().find(|m| m.leaf_index == leaf_index)
    }

    pub fn find_member_by_identity(&self, identity_ed25519: &[u8]) -> Option<&GroupMemberRecord> {
        self.members
            .iter()
            .find(|m| m.identity_ed25519_public == identity_ed25519)
    }

    pub fn leaf_indices(&self) -> Vec<u32> {
        self.members.iter().map(|m| m.leaf_index).collect()
    }

    pub fn member_count(&self) -> usize {
        self.members.len()
    }
}

pub fn validate_commit_for_relay(
    commit_bytes: &[u8],
    roster: &GroupRoster,
) -> Result<RelayCommitInfo, ProtocolError> {
    if commit_bytes.len() > MAX_GROUP_MESSAGE_SIZE {
        return Err(ProtocolError::invalid_input("Commit too large"));
    }

    let commit = GroupCommit::decode(commit_bytes)
        .map_err(|e| ProtocolError::decode(format!("Commit decode: {e}")))?;

    if commit.epoch != roster.epoch + 1 {
        return Err(ProtocolError::group_protocol(format!(
            "Commit epoch mismatch: expected {}, got {}",
            roster.epoch + 1,
            commit.epoch
        )));
    }

    if roster.find_member(commit.committer_leaf_index).is_none() {
        return Err(ProtocolError::group_membership(format!(
            "Committer leaf {} is not a group member",
            commit.committer_leaf_index
        )));
    }

    if commit.group_id != roster.group_id {
        return Err(ProtocolError::group_protocol("Commit group_id mismatch"));
    }

    if commit.update_path.is_none() {
        return Err(ProtocolError::group_protocol("Commit missing update_path"));
    }

    let mut added_identities = Vec::new();
    let mut removed_leaves = Vec::new();

    for proposal in &commit.proposals {
        match &proposal.proposal {
            Some(crate::proto::group_proposal::Proposal::Add(add)) => {
                let kp = add.key_package.as_ref().ok_or_else(|| {
                    ProtocolError::group_membership("Add proposal missing key package")
                })?;
                if kp.identity_ed25519_public.len() != ED25519_PUBLIC_KEY_BYTES {
                    return Err(ProtocolError::invalid_input(
                        "Invalid Ed25519 key size in Add",
                    ));
                }
                added_identities.push(kp.identity_ed25519_public.clone());
            }
            Some(crate::proto::group_proposal::Proposal::Remove(remove)) => {
                if roster.find_member(remove.removed_leaf_index).is_none() {
                    return Err(ProtocolError::group_membership(format!(
                        "Remove: leaf {} is not a member",
                        remove.removed_leaf_index
                    )));
                }
                if remove.removed_leaf_index == commit.committer_leaf_index {
                    return Err(ProtocolError::group_membership(
                        "Cannot remove the committer",
                    ));
                }
                removed_leaves.push(remove.removed_leaf_index);
            }
            Some(
                crate::proto::group_proposal::Proposal::Update(_)
                | crate::proto::group_proposal::Proposal::ExternalInit(_)
                | crate::proto::group_proposal::Proposal::Psk(_)
                | crate::proto::group_proposal::Proposal::ReInit(_),
            ) => {}
            None => {
                return Err(ProtocolError::group_membership("Empty proposal"));
            }
        }
    }

    Ok(RelayCommitInfo {
        committer_leaf_index: commit.committer_leaf_index,
        new_epoch: commit.epoch,
        added_identities,
        removed_leaves,
    })
}

pub fn validate_group_message_for_relay(
    message_bytes: &[u8],
    roster: &GroupRoster,
) -> Result<(), ProtocolError> {
    if message_bytes.len() > MAX_GROUP_MESSAGE_SIZE {
        return Err(ProtocolError::invalid_input("GroupMessage too large"));
    }

    let msg = GroupMessage::decode(message_bytes)
        .map_err(|e| ProtocolError::decode(format!("GroupMessage decode: {e}")))?;

    if msg.group_id != roster.group_id {
        return Err(ProtocolError::group_protocol(
            "GroupMessage group_id mismatch",
        ));
    }

    if msg.epoch != roster.epoch {
        return Err(ProtocolError::group_protocol(format!(
            "GroupMessage epoch mismatch: expected {}, got {}",
            roster.epoch, msg.epoch
        )));
    }

    match &msg.content {
        Some(crate::proto::group_message::Content::Application(_)) => Ok(()),
        _ => Err(ProtocolError::group_protocol(
            "Expected application message content",
        )),
    }
}

pub fn validate_key_package_for_storage(
    key_package_bytes: &[u8],
) -> Result<GroupKeyPackage, ProtocolError> {
    let kp = GroupKeyPackage::decode(key_package_bytes)
        .map_err(|e| ProtocolError::decode(format!("KeyPackage decode: {e}")))?;
    key_package::validate_key_package(&kp)?;
    Ok(kp)
}

#[derive(Debug)]
pub struct RelayCommitInfo {
    pub committer_leaf_index: u32,
    pub new_epoch: u64,
    pub added_identities: Vec<Vec<u8>>,
    pub removed_leaves: Vec<u32>,
}

pub fn commit_recipients(roster: &GroupRoster, committer_leaf_index: u32) -> Vec<u32> {
    roster
        .members
        .iter()
        .filter(|m| m.leaf_index != committer_leaf_index)
        .map(|m| m.leaf_index)
        .collect()
}

pub fn message_recipients(roster: &GroupRoster) -> Vec<u32> {
    roster.leaf_indices()
}

pub fn apply_commit_to_roster(
    roster: &mut GroupRoster,
    info: &RelayCommitInfo,
    added_members: Vec<GroupMemberRecord>,
) -> Result<(), ProtocolError> {
    for &leaf_idx in &info.removed_leaves {
        roster.members.retain(|m| m.leaf_index != leaf_idx);
    }

    for member in added_members {
        roster.members.push(member);
    }

    roster.epoch = info.new_epoch;

    Ok(())
}

pub fn extract_welcome_target(welcome_bytes: &[u8]) -> Result<(Vec<u8>, u64, u32), ProtocolError> {
    let welcome = GroupWelcome::decode(welcome_bytes)
        .map_err(|e| ProtocolError::decode(format!("Welcome decode: {e}")))?;

    Ok((welcome.group_id, welcome.epoch, welcome.target_leaf_index))
}

const MAX_DEVICE_ID_BYTES: usize = 16;
const MAX_CRYPTO_ENVELOPE_SIZE: usize = MAX_GROUP_MESSAGE_SIZE + 256;

pub fn validate_crypto_envelope(envelope_bytes: &[u8]) -> Result<CryptoEnvelope, ProtocolError> {
    if envelope_bytes.len() > MAX_CRYPTO_ENVELOPE_SIZE {
        return Err(ProtocolError::invalid_input("CryptoEnvelope too large"));
    }

    let envelope = CryptoEnvelope::decode(envelope_bytes)
        .map_err(|e| ProtocolError::decode(format!("CryptoEnvelope decode: {e}")))?;

    if envelope.sender_device_id.is_empty() || envelope.sender_device_id.len() > MAX_DEVICE_ID_BYTES
    {
        return Err(ProtocolError::invalid_input(
            "Invalid sender_device_id size",
        ));
    }

    if envelope.payload_type == CryptoPayloadType::CryptoPayloadUnspecified as i32 {
        return Err(ProtocolError::invalid_input(
            "CryptoPayloadType must be specified",
        ));
    }

    if envelope.encrypted_payload.is_empty() {
        return Err(ProtocolError::invalid_input("encrypted_payload is empty"));
    }

    if envelope.encrypted_payload.len() > MAX_GROUP_MESSAGE_SIZE {
        return Err(ProtocolError::invalid_input("encrypted_payload too large"));
    }

    let payload_type = envelope.payload_type;
    let needs_group_id = payload_type == CryptoPayloadType::CryptoPayloadGroupMessage as i32
        || payload_type == CryptoPayloadType::CryptoPayloadGroupCommit as i32;

    if needs_group_id && envelope.group_id.is_empty() {
        return Err(ProtocolError::invalid_input(
            "group_id required for group message/commit",
        ));
    }

    Ok(envelope)
}

pub fn route_crypto_envelope(
    envelope: &CryptoEnvelope,
    roster: &GroupRoster,
) -> Result<Vec<u8>, ProtocolError> {
    if envelope.group_id.is_empty() {
        return Err(ProtocolError::invalid_input(
            "group_id required for routing",
        ));
    }

    if envelope.group_id != roster.group_id {
        return Err(ProtocolError::group_protocol(
            "group_id mismatch with roster",
        ));
    }

    Ok(envelope.group_id.clone())
}

pub fn crypto_envelope_recipients(envelope: &CryptoEnvelope, roster: &GroupRoster) -> Vec<u32> {
    if !envelope.recipient_device_id.is_empty() {
        return vec![];
    }
    roster
        .members
        .iter()
        .filter(|m| m.credential != envelope.sender_device_id)
        .map(|m| m.leaf_index)
        .collect()
}

pub trait PendingEventStore: Send + Sync {
    fn store_event(
        &self,
        device_id: &[u8],
        event_id: &str,
        server_timestamp: u64,
        envelope_bytes: &[u8],
    ) -> Result<(), ProtocolError>;

    fn fetch_events(
        &self,
        device_id: &[u8],
        after_event_id: &str,
        max_events: u32,
    ) -> Result<Vec<StoredPendingEvent>, ProtocolError>;

    fn ack_events(&self, device_id: &[u8], event_ids: &[String]) -> Result<u64, ProtocolError>;
}

#[derive(Debug, Clone)]
pub struct StoredPendingEvent {
    pub event_id: String,
    pub server_timestamp: u64,
    pub envelope_bytes: Vec<u8>,
}

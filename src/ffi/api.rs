// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

#![allow(clippy::too_many_arguments, unsafe_code)]
// # FFI Safety Contract
//
// All `pub unsafe extern "C"` functions in this module share these preconditions:
//   - `out_error` (when present) must be either null or point to a valid `EppError`.
//   - `out_buf` / `out_*` output pointers must be either null or point to writable memory.
//   - `handle` pointers must originate from the corresponding `_create` / `_start` function.
//   - `(data, length)` pairs must form valid, readable slices (or `data` must be null when
//     `length == 0`).
//   - Handle pointers passed to `_destroy` must not be used after the call.
//
// All functions use `ffi_catch_panic!` to convert Rust panics into error codes, preventing
// unwinding across the FFI boundary.

use prost::Message;
use std::ffi::CString;
use std::mem::size_of;
use std::os::raw::c_char;

use crate::core::constants::{
    AES_GCM_NONCE_BYTES, AES_KEY_BYTES, DEFAULT_ONE_TIME_KEY_COUNT,
    ED25519_PUBLIC_KEY_BYTES, HMAC_BYTES, KYBER_PUBLIC_KEY_BYTES, MAX_BUFFER_SIZE,
    MAX_ENVELOPE_MESSAGE_SIZE, MAX_GROUP_MESSAGE_SIZE, MAX_HANDSHAKE_MESSAGE_SIZE,
    MESSAGE_ID_BYTES, PROTOCOL_VERSION, PSK_BYTES, ROOT_KEY_BYTES,
    X25519_PUBLIC_KEY_BYTES,
};
use crate::core::errors::ProtocolError;
use crate::crypto::SecureMemoryHandle;
use crate::crypto::{CryptoInterop, KyberInterop};
use crate::identity::IdentityKeys;
use crate::interfaces::{IGroupEventHandler, IIdentityEventHandler, IProtocolEventHandler};
use crate::proto::{OneTimePreKey, PreKeyBundle, SecureEnvelope};
use crate::protocol::group::{GroupSecurityPolicy, GroupSession};
use crate::protocol::{HandshakeInitiator, HandshakeResponder, Session};
use std::os::raw::c_void;

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EppErrorCode {
    EppSuccess = 0,
    EppErrorGeneric = 1,
    EppErrorInvalidInput = 2,
    EppErrorKeyGeneration = 3,
    EppErrorDeriveKey = 4,
    EppErrorHandshake = 5,
    EppErrorEncryption = 6,
    EppErrorDecryption = 7,
    EppErrorDecode = 8,
    EppErrorEncode = 9,
    EppErrorBufferTooSmall = 10,
    EppErrorObjectDisposed = 11,
    EppErrorPrepareLocal = 12,
    EppErrorOutOfMemory = 13,
    EppErrorCryptoFailure = 14,
    EppErrorNullPointer = 15,
    EppErrorInvalidState = 16,
    EppErrorReplayAttack = 17,
    EppErrorSessionExpired = 18,
    EppErrorPqMissing = 19,
    EppErrorGroupProtocol = 20,
    EppErrorGroupMembership = 21,
    EppErrorTreeIntegrity = 22,
    EppErrorWelcome = 23,
    EppErrorMessageExpired = 24,
    EppErrorFranking = 25,
}

#[repr(C)]
pub struct EppBuffer {
    pub data: *mut u8,
    pub length: usize,
}

#[repr(C)]
pub struct EppError {
    pub code: EppErrorCode,
    pub message: *mut c_char,
}

#[repr(C)]
pub struct EppSessionConfig {
    pub max_messages_per_chain: u32,
}

#[repr(C)]
pub enum EppEnvelopeType {
    EppEnvelopeRequest = 0,
    EppEnvelopeResponse = 1,
    EppEnvelopeNotification = 2,
    EppEnvelopeHeartbeat = 3,
    EppEnvelopeErrorResponse = 4,
}

pub struct EppIdentityHandle(pub Option<IdentityKeys>);
pub struct EppSessionHandle(pub Option<Session>);
pub struct EppHandshakeInitiatorHandle(pub Option<HandshakeInitiator>);
pub struct EppHandshakeResponderHandle(pub Option<HandshakeResponder>);
pub struct EppGroupSessionHandle(pub Option<GroupSession>);

pub struct EppKeyPackageSecretsHandle {
    pub x25519_private: SecureMemoryHandle,
    pub kyber_secret: SecureMemoryHandle,
}

#[repr(C)]
pub struct EppGroupSecurityPolicy {
    pub max_messages_per_epoch: u32,
    pub max_skipped_keys_per_sender: u32,
    pub block_external_join: u8,
    pub enhanced_key_schedule: u8,
    pub mandatory_franking: u8,
}

macro_rules! ffi_catch_panic {
    ($out_error:expr, $body:expr) => {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| $body)) {
            Ok(result) => result,
            Err(_) => {
                unsafe {
                    write_error(
                        $out_error,
                        EppErrorCode::EppErrorGeneric,
                        "Internal panic caught at FFI boundary",
                    );
                }
                EppErrorCode::EppErrorGeneric
            }
        }
    };
}

macro_rules! ffi_catch_panic_value {
    ($default:expr, $body:expr) => {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| $body)) {
            Ok(result) => result,
            Err(_) => $default,
        }
    };
}

const fn error_code_from_protocol(e: &ProtocolError) -> EppErrorCode {
    match e {
        ProtocolError::Generic(_) => EppErrorCode::EppErrorGeneric,
        ProtocolError::KeyGeneration(_) => EppErrorCode::EppErrorKeyGeneration,
        ProtocolError::DeriveKey(_) => EppErrorCode::EppErrorDeriveKey,
        ProtocolError::InvalidInput(_) | ProtocolError::PeerPubKey(_) => {
            EppErrorCode::EppErrorInvalidInput
        }
        ProtocolError::PrepareLocal(_) => EppErrorCode::EppErrorPrepareLocal,
        ProtocolError::Handshake(_) => EppErrorCode::EppErrorHandshake,
        ProtocolError::Decode(_) => EppErrorCode::EppErrorDecode,
        ProtocolError::Encode(_) => EppErrorCode::EppErrorEncode,
        ProtocolError::BufferTooSmall(_) => EppErrorCode::EppErrorBufferTooSmall,
        ProtocolError::ObjectDisposed => EppErrorCode::EppErrorObjectDisposed,
        ProtocolError::ReplayAttack(_) => EppErrorCode::EppErrorReplayAttack,
        ProtocolError::InvalidState(_) => EppErrorCode::EppErrorInvalidState,
        ProtocolError::NullPointer => EppErrorCode::EppErrorNullPointer,
        ProtocolError::Crypto(_) => EppErrorCode::EppErrorCryptoFailure,
        ProtocolError::GroupProtocol(_) => EppErrorCode::EppErrorGroupProtocol,
        ProtocolError::GroupMembership(_) => EppErrorCode::EppErrorGroupMembership,
        ProtocolError::TreeIntegrity(_) => EppErrorCode::EppErrorTreeIntegrity,
        ProtocolError::WelcomeError(_) => EppErrorCode::EppErrorWelcome,
        ProtocolError::MessageExpired(_) => EppErrorCode::EppErrorMessageExpired,
        ProtocolError::FrankingFailed(_) => EppErrorCode::EppErrorFranking,
    }
}

/// # Safety
/// `out_error` must be null or point to a valid, writable `EppError`.  If `(*out_error).message`
/// is non-null it must have been allocated by `CString::into_raw`.
unsafe fn write_error(out_error: *mut EppError, code: EppErrorCode, msg: &str) {
    if out_error.is_null() {
        return;
    }
    if !(*out_error).message.is_null() {
        drop(CString::from_raw((*out_error).message));
        (*out_error).message = std::ptr::null_mut();
    }
    let c_msg = CString::new(msg).unwrap_or_else(|_| c"error".to_owned());
    (*out_error).code = code;
    (*out_error).message = c_msg.into_raw();
}

/// # Safety
/// Same preconditions as [`write_error`].
unsafe fn write_protocol_error(out_error: *mut EppError, e: &ProtocolError) -> EppErrorCode {
    let code = error_code_from_protocol(e);
    write_error(out_error, code, &e.to_string());
    code
}

/// # Safety
/// `out` must be null or point to a valid, writable `EppBuffer`.
unsafe fn write_buffer(out: *mut EppBuffer, bytes: Vec<u8>) {
    if out.is_null() {
        return;
    }
    if bytes.is_empty() {
        (*out).data = std::ptr::null_mut();
        (*out).length = 0;
        return;
    }
    let len = bytes.len();
    let boxed: Box<[u8]> = bytes.into_boxed_slice();
    (*out).data = Box::into_raw(boxed).cast::<u8>();
    (*out).length = len;
}

/// # Safety
/// `handle` must be null or point to a live `EppIdentityHandle` created by `epp_identity_create*`.
unsafe fn require_identity_ref<'a>(
    handle: *const EppIdentityHandle,
    out_error: *mut EppError,
) -> Result<&'a IdentityKeys, EppErrorCode> {
    if handle.is_null() {
        write_error(
            out_error,
            EppErrorCode::EppErrorNullPointer,
            "handle is null",
        );
        return Err(EppErrorCode::EppErrorNullPointer);
    }
    (*handle).0.as_ref().ok_or_else(|| {
        write_error(
            out_error,
            EppErrorCode::EppErrorObjectDisposed,
            "handle already destroyed",
        );
        EppErrorCode::EppErrorObjectDisposed
    })
}

/// # Safety
/// `handle` must be null or point to a live, exclusively-owned `EppIdentityHandle`.
unsafe fn require_identity_mut<'a>(
    handle: *mut EppIdentityHandle,
    out_error: *mut EppError,
) -> Result<&'a mut IdentityKeys, EppErrorCode> {
    if handle.is_null() {
        write_error(
            out_error,
            EppErrorCode::EppErrorNullPointer,
            "handle is null",
        );
        return Err(EppErrorCode::EppErrorNullPointer);
    }
    (*handle).0.as_mut().ok_or_else(|| {
        write_error(
            out_error,
            EppErrorCode::EppErrorObjectDisposed,
            "handle already destroyed",
        );
        EppErrorCode::EppErrorObjectDisposed
    })
}

/// # Safety
/// `handle` must be null or point to a live, exclusively-owned `EppSessionHandle`.
unsafe fn require_session_mut<'a>(
    handle: *mut EppSessionHandle,
    out_error: *mut EppError,
) -> Result<&'a mut Session, EppErrorCode> {
    if handle.is_null() {
        write_error(
            out_error,
            EppErrorCode::EppErrorNullPointer,
            "handle is null",
        );
        return Err(EppErrorCode::EppErrorNullPointer);
    }
    (*handle).0.as_mut().ok_or_else(|| {
        write_error(
            out_error,
            EppErrorCode::EppErrorObjectDisposed,
            "handle already destroyed",
        );
        EppErrorCode::EppErrorObjectDisposed
    })
}

/// # Safety
/// `handle` must be null or point to a live, exclusively-owned `EppGroupSessionHandle`.
unsafe fn require_group_mut<'a>(
    handle: *mut EppGroupSessionHandle,
    out_error: *mut EppError,
) -> Result<&'a mut GroupSession, EppErrorCode> {
    if handle.is_null() {
        write_error(
            out_error,
            EppErrorCode::EppErrorNullPointer,
            "handle is null",
        );
        return Err(EppErrorCode::EppErrorNullPointer);
    }
    (*handle).0.as_mut().ok_or_else(|| {
        write_error(
            out_error,
            EppErrorCode::EppErrorObjectDisposed,
            "handle already destroyed",
        );
        EppErrorCode::EppErrorObjectDisposed
    })
}

/// # Safety
/// `handle` must be null or point to a live `EppGroupSessionHandle`.
const unsafe fn group_ref_or_none<'a>(
    handle: *const EppGroupSessionHandle,
) -> Option<&'a GroupSession> {
    if handle.is_null() {
        return None;
    }
    (*handle).0.as_ref()
}

#[no_mangle]
pub extern "C" fn epp_version() -> *const c_char {
    static VERSION: &[u8] = b"1.0.0\0";
    VERSION.as_ptr().cast::<c_char>()
}

#[no_mangle]
pub extern "C" fn epp_init() -> EppErrorCode {
    ffi_catch_panic_value!(EppErrorCode::EppErrorCryptoFailure, {
        let _ = CryptoInterop::initialize();
        KyberInterop::install_rng();
        EppErrorCode::EppSuccess
    })
}

#[no_mangle]
pub const extern "C" fn epp_shutdown() {}

/// # Safety
/// See module-level FFI safety contract.  `out_handle` must point to writable `*mut EppIdentityHandle`.
#[no_mangle]
pub unsafe extern "C" fn epp_identity_create(
    out_handle: *mut *mut EppIdentityHandle,
    out_error: *mut EppError,
) -> EppErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if out_handle.is_null() {
            write_error(
                out_error,
                EppErrorCode::EppErrorNullPointer,
                "out_handle is null",
            );
            return EppErrorCode::EppErrorNullPointer;
        }
        match IdentityKeys::create(DEFAULT_ONE_TIME_KEY_COUNT) {
            Ok(keys) => {
                *out_handle = Box::into_raw(Box::new(EppIdentityHandle(Some(keys))));
                EppErrorCode::EppSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// # Safety
/// See module-level FFI safety contract.  `(seed, seed_length)` must form a valid readable slice.
/// `out_handle` must point to writable `*mut EppIdentityHandle`.
#[no_mangle]
pub unsafe extern "C" fn epp_identity_create_from_seed(
    seed: *const u8,
    seed_length: usize,
    out_handle: *mut *mut EppIdentityHandle,
    out_error: *mut EppError,
) -> EppErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if seed.is_null() || seed_length == 0 {
            write_error(
                out_error,
                EppErrorCode::EppErrorNullPointer,
                "seed is null or empty",
            );
            return EppErrorCode::EppErrorNullPointer;
        }
        if seed_length > MAX_BUFFER_SIZE {
            write_error(
                out_error,
                EppErrorCode::EppErrorInvalidInput,
                "input too large",
            );
            return EppErrorCode::EppErrorInvalidInput;
        }
        if out_handle.is_null() {
            write_error(
                out_error,
                EppErrorCode::EppErrorNullPointer,
                "out_handle is null",
            );
            return EppErrorCode::EppErrorNullPointer;
        }
        let seed_slice = std::slice::from_raw_parts(seed, seed_length);
        match IdentityKeys::create_from_master_key(
            seed_slice,
            crate::core::constants::DEFAULT_MEMBERSHIP_ID,
            DEFAULT_ONE_TIME_KEY_COUNT,
        ) {
            Ok(keys) => {
                *out_handle = Box::into_raw(Box::new(EppIdentityHandle(Some(keys))));
                EppErrorCode::EppSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// # Safety
/// See module-level FFI safety contract.  `(seed, seed_length)` and `(membership_id, membership_id_length)`
/// must form valid readable slices.  `out_handle` must point to writable `*mut EppIdentityHandle`.
#[no_mangle]
pub unsafe extern "C" fn epp_identity_create_with_context(
    seed: *const u8,
    seed_length: usize,
    membership_id: *const c_char,
    membership_id_length: usize,
    out_handle: *mut *mut EppIdentityHandle,
    out_error: *mut EppError,
) -> EppErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if seed.is_null() || seed_length == 0 {
            write_error(
                out_error,
                EppErrorCode::EppErrorNullPointer,
                "seed is null or empty",
            );
            return EppErrorCode::EppErrorNullPointer;
        }
        if seed_length > MAX_BUFFER_SIZE {
            write_error(
                out_error,
                EppErrorCode::EppErrorInvalidInput,
                "input too large",
            );
            return EppErrorCode::EppErrorInvalidInput;
        }
        if membership_id.is_null() || membership_id_length == 0 {
            write_error(
                out_error,
                EppErrorCode::EppErrorNullPointer,
                "membership_id is null or empty",
            );
            return EppErrorCode::EppErrorNullPointer;
        }
        if membership_id_length > MAX_BUFFER_SIZE {
            write_error(
                out_error,
                EppErrorCode::EppErrorInvalidInput,
                "input too large",
            );
            return EppErrorCode::EppErrorInvalidInput;
        }
        if out_handle.is_null() {
            write_error(
                out_error,
                EppErrorCode::EppErrorNullPointer,
                "out_handle is null",
            );
            return EppErrorCode::EppErrorNullPointer;
        }

        let seed_slice = std::slice::from_raw_parts(seed, seed_length);
        let mid_bytes =
            std::slice::from_raw_parts(membership_id.cast::<u8>(), membership_id_length);
        let Ok(mid_str) = std::str::from_utf8(mid_bytes) else {
            write_error(
                out_error,
                EppErrorCode::EppErrorInvalidInput,
                "membership_id is not valid UTF-8",
            );
            return EppErrorCode::EppErrorInvalidInput;
        };

        match IdentityKeys::create_from_master_key(seed_slice, mid_str, DEFAULT_ONE_TIME_KEY_COUNT)
        {
            Ok(keys) => {
                *out_handle = Box::into_raw(Box::new(EppIdentityHandle(Some(keys))));
                EppErrorCode::EppSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// # Safety
/// See module-level FFI safety contract.
#[no_mangle]
pub unsafe extern "C" fn epp_identity_get_x25519_public(
    handle: *const EppIdentityHandle,
    out_key: *mut u8,
    out_key_length: usize,
    out_error: *mut EppError,
) -> EppErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if out_key.is_null() {
            write_error(
                out_error,
                EppErrorCode::EppErrorNullPointer,
                "out_key is null",
            );
            return EppErrorCode::EppErrorNullPointer;
        }
        if out_key_length < X25519_PUBLIC_KEY_BYTES {
            write_error(
                out_error,
                EppErrorCode::EppErrorBufferTooSmall,
                "Buffer too small for X25519 public key",
            );
            return EppErrorCode::EppErrorBufferTooSmall;
        }
        let identity = match require_identity_ref(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let pk = identity.get_identity_x25519_public();
        std::ptr::copy_nonoverlapping(pk.as_ptr(), out_key, pk.len());
        EppErrorCode::EppSuccess
    })
}

/// # Safety
/// See module-level FFI safety contract.
#[no_mangle]
pub unsafe extern "C" fn epp_identity_get_ed25519_public(
    handle: *const EppIdentityHandle,
    out_key: *mut u8,
    out_key_length: usize,
    out_error: *mut EppError,
) -> EppErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if out_key.is_null() {
            write_error(
                out_error,
                EppErrorCode::EppErrorNullPointer,
                "out_key is null",
            );
            return EppErrorCode::EppErrorNullPointer;
        }
        if out_key_length < ED25519_PUBLIC_KEY_BYTES {
            write_error(
                out_error,
                EppErrorCode::EppErrorBufferTooSmall,
                "Buffer too small for Ed25519 public key",
            );
            return EppErrorCode::EppErrorBufferTooSmall;
        }
        let identity = match require_identity_ref(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let pk = identity.get_identity_ed25519_public();
        std::ptr::copy_nonoverlapping(pk.as_ptr(), out_key, pk.len());
        EppErrorCode::EppSuccess
    })
}

/// # Safety
/// See module-level FFI safety contract.
#[no_mangle]
pub unsafe extern "C" fn epp_identity_get_kyber_public(
    handle: *const EppIdentityHandle,
    out_key: *mut u8,
    out_key_length: usize,
    out_error: *mut EppError,
) -> EppErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if out_key.is_null() {
            write_error(
                out_error,
                EppErrorCode::EppErrorNullPointer,
                "out_key is null",
            );
            return EppErrorCode::EppErrorNullPointer;
        }
        if out_key_length < KYBER_PUBLIC_KEY_BYTES {
            write_error(
                out_error,
                EppErrorCode::EppErrorBufferTooSmall,
                "Buffer too small for Kyber public key",
            );
            return EppErrorCode::EppErrorBufferTooSmall;
        }
        let identity = match require_identity_ref(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let pk = identity.get_kyber_public();
        std::ptr::copy_nonoverlapping(pk.as_ptr(), out_key, pk.len());
        EppErrorCode::EppSuccess
    })
}

/// # Safety
/// See module-level FFI safety contract.  `handle_ptr` must point to a handle from `epp_identity_create`,
/// or be null.  The handle must not be used after this call.
#[no_mangle]
pub unsafe extern "C" fn epp_identity_destroy(handle_ptr: *mut *mut EppIdentityHandle) {
    ffi_catch_panic_value!((), unsafe {
        if handle_ptr.is_null() {
            return;
        }
        let handle = std::ptr::replace(handle_ptr, std::ptr::null_mut());
        if !handle.is_null() {
            drop(Box::from_raw(handle));
        }
    });
}

/// # Safety
/// See module-level FFI safety contract.
#[no_mangle]
pub unsafe extern "C" fn epp_prekey_bundle_create(
    identity_keys: *const EppIdentityHandle,
    out_bundle: *mut EppBuffer,
    out_error: *mut EppError,
) -> EppErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if out_bundle.is_null() {
            write_error(
                out_error,
                EppErrorCode::EppErrorNullPointer,
                "out_bundle is null",
            );
            return EppErrorCode::EppErrorNullPointer;
        }
        let identity = match require_identity_ref(identity_keys, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };

        let bundle = match identity.create_public_bundle() {
            Ok(b) => b,
            Err(e) => return write_protocol_error(out_error, &e),
        };

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
        if let Err(e) = proto_bundle.encode(&mut buf) {
            write_error(
                out_error,
                EppErrorCode::EppErrorEncode,
                &format!("Failed to encode PreKeyBundle: {e}"),
            );
            return EppErrorCode::EppErrorEncode;
        }

        write_buffer(out_bundle, buf);
        EppErrorCode::EppSuccess
    })
}

/// # Safety
/// See module-level FFI safety contract.  `(peer_prekey_bundle, peer_prekey_bundle_length)` must form
/// a valid readable slice.  `out_handle` must point to writable `*mut EppHandshakeInitiatorHandle`.
#[no_mangle]
pub unsafe extern "C" fn epp_handshake_initiator_start(
    identity_keys: *mut EppIdentityHandle,
    peer_prekey_bundle: *const u8,
    peer_prekey_bundle_length: usize,
    config: *const EppSessionConfig,
    out_handle: *mut *mut EppHandshakeInitiatorHandle,
    out_handshake_init: *mut EppBuffer,
    out_error: *mut EppError,
) -> EppErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if peer_prekey_bundle.is_null() || out_handle.is_null() || out_handshake_init.is_null() {
            write_error(
                out_error,
                EppErrorCode::EppErrorNullPointer,
                "A required pointer is null",
            );
            return EppErrorCode::EppErrorNullPointer;
        }
        if peer_prekey_bundle_length > MAX_HANDSHAKE_MESSAGE_SIZE {
            write_error(
                out_error,
                EppErrorCode::EppErrorInvalidInput,
                "peer_prekey_bundle too large",
            );
            return EppErrorCode::EppErrorInvalidInput;
        }

        let bundle_bytes =
            std::slice::from_raw_parts(peer_prekey_bundle, peer_prekey_bundle_length);
        let peer_bundle = match PreKeyBundle::decode(bundle_bytes) {
            Ok(b) => b,
            Err(e) => {
                write_error(
                    out_error,
                    EppErrorCode::EppErrorDecode,
                    &format!("Failed to decode PreKeyBundle: {e}"),
                );
                return EppErrorCode::EppErrorDecode;
            }
        };

        let max_msgs = if config.is_null() {
            #[allow(clippy::cast_possible_truncation)]
            {
                crate::core::constants::DEFAULT_MESSAGES_PER_CHAIN as u32
            }
        } else {
            (*config).max_messages_per_chain
        };

        let ik = match require_identity_mut(identity_keys, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        match HandshakeInitiator::start(ik, &peer_bundle, max_msgs) {
            Ok(initiator) => {
                write_buffer(out_handshake_init, initiator.encoded_message().to_vec());
                *out_handle = Box::into_raw(Box::new(EppHandshakeInitiatorHandle(Some(initiator))));
                EppErrorCode::EppSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// # Safety
/// See module-level FFI safety contract.  `(handshake_ack, handshake_ack_length)` must form a valid
/// readable slice.  `out_session` must point to writable `*mut EppSessionHandle`.
#[no_mangle]
pub unsafe extern "C" fn epp_handshake_initiator_finish(
    handle: *mut EppHandshakeInitiatorHandle,
    handshake_ack: *const u8,
    handshake_ack_length: usize,
    out_session: *mut *mut EppSessionHandle,
    out_error: *mut EppError,
) -> EppErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if handle.is_null() {
            write_error(
                out_error,
                EppErrorCode::EppErrorNullPointer,
                "handle is null",
            );
            return EppErrorCode::EppErrorNullPointer;
        }
        if handshake_ack.is_null() || out_session.is_null() {
            write_error(
                out_error,
                EppErrorCode::EppErrorNullPointer,
                "A required pointer is null",
            );
            return EppErrorCode::EppErrorNullPointer;
        }
        if handshake_ack_length > MAX_HANDSHAKE_MESSAGE_SIZE {
            write_error(
                out_error,
                EppErrorCode::EppErrorInvalidInput,
                "handshake_ack too large",
            );
            return EppErrorCode::EppErrorInvalidInput;
        }

        let handle_ref = &mut *handle;
        let Some(initiator) = handle_ref.0.take() else {
            write_error(
                out_error,
                EppErrorCode::EppErrorObjectDisposed,
                "handle already consumed",
            );
            return EppErrorCode::EppErrorObjectDisposed;
        };

        let ack_bytes = std::slice::from_raw_parts(handshake_ack, handshake_ack_length);
        match initiator.finish(ack_bytes) {
            Ok(session) => {
                *out_session = Box::into_raw(Box::new(EppSessionHandle(Some(session))));
                EppErrorCode::EppSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// # Safety
/// See module-level FFI safety contract.  `handle_ptr` must point to a handle from
/// `epp_handshake_initiator_start`, or be null.  The handle must not be used after this call.
#[no_mangle]
pub unsafe extern "C" fn epp_handshake_initiator_destroy(
    handle_ptr: *mut *mut EppHandshakeInitiatorHandle,
) {
    ffi_catch_panic_value!((), unsafe {
        if handle_ptr.is_null() {
            return;
        }
        let handle = std::ptr::replace(handle_ptr, std::ptr::null_mut());
        if !handle.is_null() {
            drop(Box::from_raw(handle));
        }
    });
}

/// # Safety
/// See module-level FFI safety contract.  `(local_prekey_bundle, local_prekey_bundle_length)` and
/// `(handshake_init, handshake_init_length)` must form valid readable slices.
/// `out_handle` must point to writable `*mut EppHandshakeResponderHandle`.
#[no_mangle]
pub unsafe extern "C" fn epp_handshake_responder_start(
    identity_keys: *mut EppIdentityHandle,
    local_prekey_bundle: *const u8,
    local_prekey_bundle_length: usize,
    handshake_init: *const u8,
    handshake_init_length: usize,
    config: *const EppSessionConfig,
    out_handle: *mut *mut EppHandshakeResponderHandle,
    out_handshake_ack: *mut EppBuffer,
    out_error: *mut EppError,
) -> EppErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if local_prekey_bundle.is_null()
            || handshake_init.is_null()
            || out_handle.is_null()
            || out_handshake_ack.is_null()
        {
            write_error(
                out_error,
                EppErrorCode::EppErrorNullPointer,
                "A required pointer is null",
            );
            return EppErrorCode::EppErrorNullPointer;
        }
        if local_prekey_bundle_length > MAX_HANDSHAKE_MESSAGE_SIZE
            || handshake_init_length > MAX_HANDSHAKE_MESSAGE_SIZE
        {
            write_error(
                out_error,
                EppErrorCode::EppErrorInvalidInput,
                "Message too large",
            );
            return EppErrorCode::EppErrorInvalidInput;
        }

        let bundle_bytes =
            std::slice::from_raw_parts(local_prekey_bundle, local_prekey_bundle_length);
        let local_bundle = match PreKeyBundle::decode(bundle_bytes) {
            Ok(b) => b,
            Err(e) => {
                write_error(
                    out_error,
                    EppErrorCode::EppErrorDecode,
                    &format!("Failed to decode local PreKeyBundle: {e}"),
                );
                return EppErrorCode::EppErrorDecode;
            }
        };

        let init_bytes = std::slice::from_raw_parts(handshake_init, handshake_init_length);
        let max_msgs = if config.is_null() {
            #[allow(clippy::cast_possible_truncation)]
            {
                crate::core::constants::DEFAULT_MESSAGES_PER_CHAIN as u32
            }
        } else {
            (*config).max_messages_per_chain
        };

        let ik = match require_identity_mut(identity_keys, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        match HandshakeResponder::process(ik, &local_bundle, init_bytes, max_msgs) {
            Ok(responder) => {
                write_buffer(out_handshake_ack, responder.encoded_ack().to_vec());
                *out_handle = Box::into_raw(Box::new(EppHandshakeResponderHandle(Some(responder))));
                EppErrorCode::EppSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// # Safety
/// See module-level FFI safety contract.  `out_session` must point to writable `*mut EppSessionHandle`.
#[no_mangle]
pub unsafe extern "C" fn epp_handshake_responder_finish(
    handle: *mut EppHandshakeResponderHandle,
    out_session: *mut *mut EppSessionHandle,
    out_error: *mut EppError,
) -> EppErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if handle.is_null() || out_session.is_null() {
            write_error(
                out_error,
                EppErrorCode::EppErrorNullPointer,
                "A required pointer is null",
            );
            return EppErrorCode::EppErrorNullPointer;
        }
        let handle_ref = &mut *handle;
        let Some(responder) = handle_ref.0.take() else {
            write_error(
                out_error,
                EppErrorCode::EppErrorObjectDisposed,
                "handle already consumed",
            );
            return EppErrorCode::EppErrorObjectDisposed;
        };

        match responder.finish() {
            Ok(session) => {
                *out_session = Box::into_raw(Box::new(EppSessionHandle(Some(session))));
                EppErrorCode::EppSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// # Safety
/// See module-level FFI safety contract.  `handle_ptr` must point to a handle from
/// `epp_handshake_responder_start`, or be null.  The handle must not be used after this call.
#[no_mangle]
pub unsafe extern "C" fn epp_handshake_responder_destroy(
    handle_ptr: *mut *mut EppHandshakeResponderHandle,
) {
    ffi_catch_panic_value!((), unsafe {
        if handle_ptr.is_null() {
            return;
        }
        let handle = std::ptr::replace(handle_ptr, std::ptr::null_mut());
        if !handle.is_null() {
            drop(Box::from_raw(handle));
        }
    });
}

/// # Safety
/// See module-level FFI safety contract.  `(plaintext, plaintext_length)` and
/// `(correlation_id, correlation_id_length)` must form valid readable slices.
#[no_mangle]
pub unsafe extern "C" fn epp_session_encrypt(
    handle: *mut EppSessionHandle,
    plaintext: *const u8,
    plaintext_length: usize,
    envelope_type: EppEnvelopeType,
    envelope_id: u32,
    correlation_id: *const c_char,
    correlation_id_length: usize,
    out_encrypted_envelope: *mut EppBuffer,
    out_error: *mut EppError,
) -> EppErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if plaintext.is_null() || out_encrypted_envelope.is_null() {
            write_error(
                out_error,
                EppErrorCode::EppErrorNullPointer,
                "A required pointer is null",
            );
            return EppErrorCode::EppErrorNullPointer;
        }
        if plaintext_length > MAX_ENVELOPE_MESSAGE_SIZE {
            write_error(
                out_error,
                EppErrorCode::EppErrorInvalidInput,
                "plaintext too large",
            );
            return EppErrorCode::EppErrorInvalidInput;
        }

        let payload = std::slice::from_raw_parts(plaintext, plaintext_length);

        if correlation_id_length > MAX_BUFFER_SIZE {
            write_error(
                out_error,
                EppErrorCode::EppErrorInvalidInput,
                "correlation_id too large",
            );
            return EppErrorCode::EppErrorInvalidInput;
        }

        let corr_id: Option<&str> = if !correlation_id.is_null() && correlation_id_length > 0 {
            let bytes =
                std::slice::from_raw_parts(correlation_id.cast::<u8>(), correlation_id_length);
            if let Ok(s) = std::str::from_utf8(bytes) {
                Some(s)
            } else {
                write_error(
                    out_error,
                    EppErrorCode::EppErrorInvalidInput,
                    "correlation_id is not valid UTF-8",
                );
                return EppErrorCode::EppErrorInvalidInput;
            }
        } else {
            None
        };

        let env_type_i32 = envelope_type as i32;

        let session = match require_session_mut(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let envelope = match session.encrypt(payload, env_type_i32, envelope_id, corr_id) {
            Ok(e) => e,
            Err(e) => return write_protocol_error(out_error, &e),
        };

        let mut buf = Vec::new();
        if let Err(e) = envelope.encode(&mut buf) {
            write_error(
                out_error,
                EppErrorCode::EppErrorEncode,
                &format!("Failed to encode SecureEnvelope: {e}"),
            );
            return EppErrorCode::EppErrorEncode;
        }

        write_buffer(out_encrypted_envelope, buf);
        EppErrorCode::EppSuccess
    })
}

/// # Safety
/// See module-level FFI safety contract.  `(encrypted_envelope, encrypted_envelope_length)` must
/// form a valid readable slice.
#[no_mangle]
pub unsafe extern "C" fn epp_session_decrypt(
    handle: *mut EppSessionHandle,
    encrypted_envelope: *const u8,
    encrypted_envelope_length: usize,
    out_plaintext: *mut EppBuffer,
    out_metadata: *mut EppBuffer,
    out_error: *mut EppError,
) -> EppErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if encrypted_envelope.is_null() || out_plaintext.is_null() || out_metadata.is_null() {
            write_error(
                out_error,
                EppErrorCode::EppErrorNullPointer,
                "A required pointer is null",
            );
            return EppErrorCode::EppErrorNullPointer;
        }
        if encrypted_envelope_length > MAX_ENVELOPE_MESSAGE_SIZE {
            write_error(
                out_error,
                EppErrorCode::EppErrorInvalidInput,
                "Envelope too large",
            );
            return EppErrorCode::EppErrorInvalidInput;
        }
        let session = match require_session_mut(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };

        let env_bytes = std::slice::from_raw_parts(encrypted_envelope, encrypted_envelope_length);
        let envelope = match SecureEnvelope::decode(env_bytes) {
            Ok(e) => e,
            Err(e) => {
                write_error(
                    out_error,
                    EppErrorCode::EppErrorDecode,
                    &format!("Failed to decode SecureEnvelope: {e}"),
                );
                return EppErrorCode::EppErrorDecode;
            }
        };
        let result = match session.decrypt(&envelope) {
            Ok(r) => r,
            Err(e) => return write_protocol_error(out_error, &e),
        };

        let mut meta_buf = Vec::new();
        if let Err(e) = result.metadata.encode(&mut meta_buf) {
            write_error(
                out_error,
                EppErrorCode::EppErrorEncode,
                &format!("Failed to encode EnvelopeMetadata: {e}"),
            );
            return EppErrorCode::EppErrorEncode;
        }

        write_buffer(out_plaintext, result.plaintext);
        write_buffer(out_metadata, meta_buf);
        EppErrorCode::EppSuccess
    })
}

/// # Safety
/// See module-level FFI safety contract.
#[no_mangle]
pub unsafe extern "C" fn epp_session_nonce_remaining(
    handle: *mut EppSessionHandle,
    out_remaining: *mut u64,
    out_error: *mut EppError,
) -> EppErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if out_remaining.is_null() {
            write_error(
                out_error,
                EppErrorCode::EppErrorNullPointer,
                "out_remaining is null",
            );
            return EppErrorCode::EppErrorNullPointer;
        }
        let session = match require_session_mut(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        match session.nonce_remaining() {
            Ok(remaining) => {
                std::ptr::write(out_remaining, remaining);
                EppErrorCode::EppSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// # Safety
/// See module-level FFI safety contract.  `handle_ptr` must point to a handle from
/// `epp_handshake_*_finish`, or be null.  The handle must not be used after this call.
#[no_mangle]
pub unsafe extern "C" fn epp_session_destroy(handle_ptr: *mut *mut EppSessionHandle) {
    ffi_catch_panic_value!((), unsafe {
        if handle_ptr.is_null() {
            return;
        }
        let handle = std::ptr::replace(handle_ptr, std::ptr::null_mut());
        if !handle.is_null() {
            drop(Box::from_raw(handle));
        }
    });
}

/// # Safety
/// See module-level FFI safety contract.  `(encrypted_envelope, encrypted_envelope_length)` must
/// form a valid readable slice.
#[no_mangle]
pub unsafe extern "C" fn epp_envelope_validate(
    encrypted_envelope: *const u8,
    encrypted_envelope_length: usize,
    out_error: *mut EppError,
) -> EppErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if encrypted_envelope.is_null() {
            write_error(
                out_error,
                EppErrorCode::EppErrorNullPointer,
                "encrypted_envelope is null",
            );
            return EppErrorCode::EppErrorNullPointer;
        }
        let bytes = std::slice::from_raw_parts(encrypted_envelope, encrypted_envelope_length);
        match crate::api::EcliptixProtocol::validate_envelope(bytes) {
            Ok(()) => EppErrorCode::EppSuccess,
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// # Safety
/// See module-level FFI safety contract.  `(opaque_session_key, opaque_session_key_length)` and
/// `(user_context, user_context_length)` must form valid readable slices.
/// `(out_root_key, out_root_key_length)` must form a valid writable slice.
#[no_mangle]
pub unsafe extern "C" fn epp_derive_root_key(
    opaque_session_key: *const u8,
    opaque_session_key_length: usize,
    user_context: *const u8,
    user_context_length: usize,
    out_root_key: *mut u8,
    out_root_key_length: usize,
    out_error: *mut EppError,
) -> EppErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if opaque_session_key.is_null() || user_context.is_null() || out_root_key.is_null() {
            write_error(
                out_error,
                EppErrorCode::EppErrorNullPointer,
                "A required pointer is null",
            );
            return EppErrorCode::EppErrorNullPointer;
        }
        if out_root_key_length < ROOT_KEY_BYTES {
            write_error(
                out_error,
                EppErrorCode::EppErrorBufferTooSmall,
                "Output buffer too small for derived root key",
            );
            return EppErrorCode::EppErrorBufferTooSmall;
        }

        let ikm = std::slice::from_raw_parts(opaque_session_key, opaque_session_key_length);
        let ctx = std::slice::from_raw_parts(user_context, user_context_length);

        match crate::api::EcliptixProtocol::derive_root_key(ikm, ctx) {
            Ok(key) => {
                std::ptr::copy_nonoverlapping(key.as_ptr(), out_root_key, ROOT_KEY_BYTES);
                EppErrorCode::EppSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// # Safety
/// See module-level FFI safety contract.  `(secret, secret_length)` and `(auth_key, auth_key_length)`
/// must form valid readable slices.
#[no_mangle]
pub unsafe extern "C" fn epp_shamir_split(
    secret: *const u8,
    secret_length: usize,
    threshold: u8,
    share_count: u8,
    auth_key: *const u8,
    auth_key_length: usize,
    out_shares: *mut EppBuffer,
    out_share_length: *mut usize,
    out_error: *mut EppError,
) -> EppErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if secret.is_null() || out_shares.is_null() || out_share_length.is_null() {
            write_error(
                out_error,
                EppErrorCode::EppErrorNullPointer,
                "A required pointer is null",
            );
            return EppErrorCode::EppErrorNullPointer;
        }
        if secret_length == 0 || secret_length > MAX_BUFFER_SIZE {
            write_error(
                out_error,
                EppErrorCode::EppErrorInvalidInput,
                "Secret length invalid",
            );
            return EppErrorCode::EppErrorInvalidInput;
        }

        if auth_key.is_null() || auth_key_length != HMAC_BYTES {
            write_error(
                out_error,
                EppErrorCode::EppErrorInvalidInput,
                "auth_key must be 32 bytes",
            );
            return EppErrorCode::EppErrorInvalidInput;
        }

        let secret_slice = std::slice::from_raw_parts(secret, secret_length);
        let auth_key_slice = std::slice::from_raw_parts(auth_key, auth_key_length);

        let shares = match crate::api::EcliptixProtocol::shamir_split(
            secret_slice,
            threshold,
            share_count,
            auth_key_slice,
        ) {
            Ok(s) => s,
            Err(e) => return write_protocol_error(out_error, &e),
        };

        let data_share_count = shares.len() - 1;
        if data_share_count == 0 {
            write_error(
                out_error,
                EppErrorCode::EppErrorGeneric,
                "No shares generated",
            );
            return EppErrorCode::EppErrorGeneric;
        }

        let data_share_len = shares[0].len();

        let Some(auth_tag) = shares.last() else {
            write_error(out_error, EppErrorCode::EppErrorGeneric, "Empty shares");
            return EppErrorCode::EppErrorGeneric;
        };
        let Some(total_len) = data_share_count
            .checked_mul(data_share_len)
            .and_then(|v| v.checked_add(auth_tag.len()))
        else {
            write_error(
                out_error,
                EppErrorCode::EppErrorInvalidInput,
                "Share size overflow",
            );
            return EppErrorCode::EppErrorInvalidInput;
        };
        let mut flat = Vec::with_capacity(total_len);
        for ds in &shares[..data_share_count] {
            flat.extend_from_slice(ds);
        }
        flat.extend_from_slice(auth_tag);
        *out_share_length = data_share_len;
        write_buffer(out_shares, flat);

        EppErrorCode::EppSuccess
    })
}

/// # Safety
/// See module-level FFI safety contract.  `(shares, shares_length)` and `(auth_key, auth_key_length)`
/// must form valid readable slices.
#[no_mangle]
pub unsafe extern "C" fn epp_shamir_reconstruct(
    shares: *const u8,
    shares_length: usize,
    share_length: usize,
    share_count: usize,
    auth_key: *const u8,
    auth_key_length: usize,
    out_secret: *mut EppBuffer,
    out_error: *mut EppError,
) -> EppErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if shares.is_null() || out_secret.is_null() {
            write_error(
                out_error,
                EppErrorCode::EppErrorNullPointer,
                "shares or out_secret is null",
            );
            return EppErrorCode::EppErrorNullPointer;
        }
        if share_length == 0 || share_count == 0 {
            write_error(
                out_error,
                EppErrorCode::EppErrorInvalidInput,
                "share_length and share_count must be > 0",
            );
            return EppErrorCode::EppErrorInvalidInput;
        }

        if auth_key.is_null() || auth_key_length != HMAC_BYTES {
            write_error(
                out_error,
                EppErrorCode::EppErrorInvalidInput,
                "auth_key must be 32 bytes",
            );
            return EppErrorCode::EppErrorInvalidInput;
        }

        let expected_len = share_count
            .saturating_mul(share_length)
            .saturating_add(HMAC_BYTES);
        if shares_length != expected_len {
            write_error(
                out_error,
                EppErrorCode::EppErrorInvalidInput,
                "shares_length must equal share_count * share_length + 32",
            );
            return EppErrorCode::EppErrorInvalidInput;
        }

        let flat_slice = std::slice::from_raw_parts(shares, shares_length);
        let auth_key_slice = std::slice::from_raw_parts(auth_key, auth_key_length);

        let data_bytes = &flat_slice[..share_count * share_length];
        let auth_tag = &flat_slice[share_count * share_length..];

        let mut all_shares: Vec<Vec<u8>> = (0..share_count)
            .map(|i| data_bytes[i * share_length..(i + 1) * share_length].to_vec())
            .collect();
        all_shares.push(auth_tag.to_vec());

        match crate::api::EcliptixProtocol::shamir_reconstruct(&all_shares, auth_key_slice, share_count) {
            Ok(secret) => {
                write_buffer(out_secret, secret);
                EppErrorCode::EppSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// # Safety
/// `buffer` must be null or point to a value previously written by this FFI layer.
#[no_mangle]
pub unsafe extern "C" fn epp_buffer_release(buffer: *mut EppBuffer) {
    if buffer.is_null() {
        return;
    }
    let buf = &mut *buffer;
    if !buf.data.is_null() && buf.length > 0 {
        std::ptr::write_bytes(buf.data, 0, buf.length);
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
        let slice = std::slice::from_raw_parts_mut(buf.data, buf.length);
        drop(Box::from_raw(std::ptr::from_mut::<[u8]>(slice)));
        buf.data = std::ptr::null_mut();
        buf.length = 0;
    }
}

#[no_mangle]
pub extern "C" fn epp_buffer_alloc(capacity: usize) -> *mut EppBuffer {
    if capacity == 0 {
        return std::ptr::null_mut();
    }
    let data: Box<[u8]> = vec![0u8; capacity].into_boxed_slice();
    let ptr = Box::into_raw(data).cast::<u8>();
    let buf = Box::new(EppBuffer {
        data: ptr,
        length: capacity,
    });
    Box::into_raw(buf)
}

/// # Safety
/// `buffer` must be null or point to a value previously written by this FFI layer.
#[no_mangle]
pub unsafe extern "C" fn epp_buffer_free(buffer: *mut EppBuffer) {
    if buffer.is_null() {
        return;
    }
    let buf = Box::from_raw(buffer);
    if !buf.data.is_null() && buf.length > 0 {
        std::ptr::write_bytes(buf.data, 0, buf.length);
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
        let slice = std::slice::from_raw_parts_mut(buf.data, buf.length);
        drop(Box::from_raw(std::ptr::from_mut::<[u8]>(slice)));
    }
}

/// # Safety
/// `error` must be null or point to a value previously written by this FFI layer.
#[no_mangle]
pub unsafe extern "C" fn epp_error_free(error: *mut EppError) {
    if error.is_null() {
        return;
    }
    let e = &mut *error;
    if !e.message.is_null() {
        drop(CString::from_raw(e.message));
        e.message = std::ptr::null_mut();
    }
}

#[no_mangle]
pub const extern "C" fn epp_error_string(code: EppErrorCode) -> *const c_char {
    let s: &'static [u8] = match code {
        EppErrorCode::EppSuccess => b"Success\0",
        EppErrorCode::EppErrorGeneric => b"Generic error\0",
        EppErrorCode::EppErrorInvalidInput => b"Invalid input\0",
        EppErrorCode::EppErrorKeyGeneration => b"Key generation failed\0",
        EppErrorCode::EppErrorDeriveKey => b"Key derivation failed\0",
        EppErrorCode::EppErrorHandshake => b"Handshake failed\0",
        EppErrorCode::EppErrorEncryption => b"Encryption failed\0",
        EppErrorCode::EppErrorDecryption => b"Decryption failed\0",
        EppErrorCode::EppErrorDecode => b"Decode failed\0",
        EppErrorCode::EppErrorEncode => b"Encode failed\0",
        EppErrorCode::EppErrorBufferTooSmall => b"Buffer too small\0",
        EppErrorCode::EppErrorObjectDisposed => b"Object disposed\0",
        EppErrorCode::EppErrorPrepareLocal => b"Prepare local failed\0",
        EppErrorCode::EppErrorOutOfMemory => b"Out of memory\0",
        EppErrorCode::EppErrorCryptoFailure => b"Crypto failure\0",
        EppErrorCode::EppErrorNullPointer => b"Null pointer\0",
        EppErrorCode::EppErrorInvalidState => b"Invalid state\0",
        EppErrorCode::EppErrorReplayAttack => b"Replay attack detected\0",
        EppErrorCode::EppErrorSessionExpired => b"Session expired\0",
        EppErrorCode::EppErrorPqMissing => b"Post-quantum material missing\0",
        EppErrorCode::EppErrorGroupProtocol => b"Group protocol error\0",
        EppErrorCode::EppErrorGroupMembership => b"Group membership error\0",
        EppErrorCode::EppErrorTreeIntegrity => b"Tree integrity error\0",
        EppErrorCode::EppErrorWelcome => b"Welcome processing error\0",
        EppErrorCode::EppErrorMessageExpired => b"Message expired\0",
        EppErrorCode::EppErrorFranking => b"Franking verification failed\0",
    };
    s.as_ptr().cast::<c_char>()
}

/// # Safety
/// `(data, length)` must form a valid, writable byte slice.
#[no_mangle]
pub unsafe extern "C" fn epp_secure_wipe(data: *mut u8, length: usize) -> EppErrorCode {
    ffi_catch_panic!(std::ptr::null_mut(), unsafe {
        if data.is_null() {
            return EppErrorCode::EppErrorNullPointer;
        }
        if length == 0 {
            return EppErrorCode::EppSuccess;
        }
        if length > MAX_BUFFER_SIZE {
            return EppErrorCode::EppErrorInvalidInput;
        }
        let slice = std::slice::from_raw_parts_mut(data, length);
        crate::api::EcliptixProtocol::secure_wipe(slice);
        EppErrorCode::EppSuccess
    })
}

/// # Safety
/// See module-level FFI safety contract.  `(credential, credential_length)` must form a valid
/// readable slice.  `out_secrets` must point to writable `*mut EppKeyPackageSecretsHandle`.
#[no_mangle]
pub unsafe extern "C" fn epp_group_generate_key_package(
    identity_handle: *mut EppIdentityHandle,
    credential: *const u8,
    credential_length: usize,
    out_key_package: *mut EppBuffer,
    out_secrets: *mut *mut EppKeyPackageSecretsHandle,
    out_error: *mut EppError,
) -> EppErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if out_key_package.is_null() || out_secrets.is_null() {
            write_error(
                out_error,
                EppErrorCode::EppErrorNullPointer,
                "A required pointer is null",
            );
            return EppErrorCode::EppErrorNullPointer;
        }
        if credential_length > MAX_BUFFER_SIZE {
            write_error(
                out_error,
                EppErrorCode::EppErrorInvalidInput,
                "Credential too large",
            );
            return EppErrorCode::EppErrorInvalidInput;
        }
        let cred = if credential.is_null() || credential_length == 0 {
            vec![]
        } else {
            std::slice::from_raw_parts(credential, credential_length).to_vec()
        };

        let identity = match require_identity_ref(identity_handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        use crate::protocol::group::key_package;
        match key_package::create_key_package(identity, cred) {
            Ok((kp, x25519_priv, kyber_sec)) => {
                let mut buf = Vec::new();
                if let Err(e) = kp.encode(&mut buf) {
                    write_error(
                        out_error,
                        EppErrorCode::EppErrorEncode,
                        &format!("KeyPackage encode: {e}"),
                    );
                    return EppErrorCode::EppErrorEncode;
                }
                write_buffer(out_key_package, buf);
                *out_secrets = Box::into_raw(Box::new(EppKeyPackageSecretsHandle {
                    x25519_private: x25519_priv,
                    kyber_secret: kyber_sec,
                }));
                EppErrorCode::EppSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// # Safety
/// See module-level FFI safety contract.  `handle_ptr` must point to a handle from
/// `epp_group_generate_key_package`, or be null.  The handle must not be used after this call.
#[no_mangle]
pub unsafe extern "C" fn epp_group_key_package_secrets_destroy(
    handle_ptr: *mut *mut EppKeyPackageSecretsHandle,
) {
    ffi_catch_panic_value!((), unsafe {
        if handle_ptr.is_null() {
            return;
        }
        let handle = std::ptr::replace(handle_ptr, std::ptr::null_mut());
        if !handle.is_null() {
            drop(Box::from_raw(handle));
        }
    });
}

/// # Safety
/// See module-level FFI safety contract.  `(credential, credential_length)` must form a valid
/// readable slice.  `out_handle` must point to writable `*mut EppGroupSessionHandle`.
#[no_mangle]
pub unsafe extern "C" fn epp_group_create(
    identity_handle: *mut EppIdentityHandle,
    credential: *const u8,
    credential_length: usize,
    out_handle: *mut *mut EppGroupSessionHandle,
    out_error: *mut EppError,
) -> EppErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if out_handle.is_null() {
            write_error(
                out_error,
                EppErrorCode::EppErrorNullPointer,
                "A required pointer is null",
            );
            return EppErrorCode::EppErrorNullPointer;
        }
        let cred = if credential.is_null() || credential_length == 0 {
            vec![]
        } else {
            std::slice::from_raw_parts(credential, credential_length).to_vec()
        };

        let identity = match require_identity_ref(identity_handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        match GroupSession::create(identity, cred) {
            Ok(session) => {
                *out_handle = Box::into_raw(Box::new(EppGroupSessionHandle(Some(session))));
                EppErrorCode::EppSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// # Safety
/// See module-level FFI safety contract.
#[no_mangle]
pub unsafe extern "C" fn epp_group_create_shielded(
    identity_handle: *mut EppIdentityHandle,
    credential: *const u8,
    credential_length: usize,
    out_handle: *mut *mut EppGroupSessionHandle,
    out_error: *mut EppError,
) -> EppErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if out_handle.is_null() {
            write_error(
                out_error,
                EppErrorCode::EppErrorNullPointer,
                "A required pointer is null",
            );
            return EppErrorCode::EppErrorNullPointer;
        }
        let cred = if credential.is_null() || credential_length == 0 {
            vec![]
        } else {
            std::slice::from_raw_parts(credential, credential_length).to_vec()
        };

        let identity = match require_identity_ref(identity_handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        match GroupSession::create_with_policy(identity, cred, GroupSecurityPolicy::shield()) {
            Ok(session) => {
                *out_handle = Box::into_raw(Box::new(EppGroupSessionHandle(Some(session))));
                EppErrorCode::EppSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// # Safety
/// See module-level FFI safety contract.
#[no_mangle]
pub unsafe extern "C" fn epp_group_is_shielded(
    handle: *mut EppGroupSessionHandle,
    out_shielded: *mut u8,
    out_error: *mut EppError,
) -> EppErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if out_shielded.is_null() {
            write_error(
                out_error,
                EppErrorCode::EppErrorNullPointer,
                "out_shielded is null",
            );
            return EppErrorCode::EppErrorNullPointer;
        }
        let session = match require_group_mut(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        match session.is_shielded() {
            Ok(shielded) => {
                *out_shielded = u8::from(shielded);
                EppErrorCode::EppSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// # Safety
/// See module-level FFI safety contract.  Each field of `policy` must be populated by the
/// caller.  Invalid policy values (e.g. `max_messages_per_epoch < 10`) return an error.
#[no_mangle]
pub unsafe extern "C" fn epp_group_create_with_policy(
    identity_handle: *mut EppIdentityHandle,
    credential: *const u8,
    credential_length: usize,
    policy: *const EppGroupSecurityPolicy,
    out_handle: *mut *mut EppGroupSessionHandle,
    out_error: *mut EppError,
) -> EppErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if out_handle.is_null() || policy.is_null() {
            write_error(
                out_error,
                EppErrorCode::EppErrorNullPointer,
                "A required pointer is null",
            );
            return EppErrorCode::EppErrorNullPointer;
        }
        let cred = if credential.is_null() || credential_length == 0 {
            vec![]
        } else {
            std::slice::from_raw_parts(credential, credential_length).to_vec()
        };
        let p = &*policy;
        let rust_policy = GroupSecurityPolicy {
            max_messages_per_epoch: p.max_messages_per_epoch,
            max_skipped_keys_per_sender: p.max_skipped_keys_per_sender,
            block_external_join: p.block_external_join != 0,
            enhanced_key_schedule: p.enhanced_key_schedule != 0,
            mandatory_franking: p.mandatory_franking != 0,
        };
        let identity = match require_identity_ref(identity_handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        match GroupSession::create_with_policy(identity, cred, rust_policy) {
            Ok(session) => {
                *out_handle = Box::into_raw(Box::new(EppGroupSessionHandle(Some(session))));
                EppErrorCode::EppSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// # Safety
/// See module-level FFI safety contract.  `out_policy` must point to a writable
/// `EppGroupSecurityPolicy`.
#[no_mangle]
pub unsafe extern "C" fn epp_group_get_security_policy(
    handle: *mut EppGroupSessionHandle,
    out_policy: *mut EppGroupSecurityPolicy,
    out_error: *mut EppError,
) -> EppErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if out_policy.is_null() {
            write_error(
                out_error,
                EppErrorCode::EppErrorNullPointer,
                "out_policy is null",
            );
            return EppErrorCode::EppErrorNullPointer;
        }
        let session = match require_group_mut(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        match session.security_policy() {
            Ok(p) => {
                (*out_policy).max_messages_per_epoch = p.max_messages_per_epoch;
                (*out_policy).max_skipped_keys_per_sender = p.max_skipped_keys_per_sender;
                (*out_policy).block_external_join = u8::from(p.block_external_join);
                (*out_policy).enhanced_key_schedule = u8::from(p.enhanced_key_schedule);
                (*out_policy).mandatory_franking = u8::from(p.mandatory_franking);
                EppErrorCode::EppSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// # Safety
/// See module-level FFI safety contract.  `(welcome_bytes, welcome_length)` must form a valid
/// readable slice.  `out_group_handle` must point to writable `*mut EppGroupSessionHandle`.
#[no_mangle]
pub unsafe extern "C" fn epp_group_join(
    identity_handle: *mut EppIdentityHandle,
    welcome_bytes: *const u8,
    welcome_length: usize,
    secrets_handle: *mut EppKeyPackageSecretsHandle,
    out_group_handle: *mut *mut EppGroupSessionHandle,
    out_error: *mut EppError,
) -> EppErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if welcome_bytes.is_null() || secrets_handle.is_null() || out_group_handle.is_null() {
            write_error(
                out_error,
                EppErrorCode::EppErrorNullPointer,
                "A required pointer is null",
            );
            return EppErrorCode::EppErrorNullPointer;
        }
        if welcome_length > MAX_GROUP_MESSAGE_SIZE {
            write_error(
                out_error,
                EppErrorCode::EppErrorInvalidInput,
                "Welcome message too large",
            );
            return EppErrorCode::EppErrorInvalidInput;
        }

        let welcome_slice = std::slice::from_raw_parts(welcome_bytes, welcome_length);

        let identity = match require_identity_ref(identity_handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let ed25519_secret = match identity.get_identity_ed25519_private_key_copy() {
            Ok(sk) => sk,
            Err(e) => return write_protocol_error(out_error, &e),
        };

        let secrets = &*secrets_handle;
        let x25519_private = match secrets.x25519_private.try_clone() {
            Ok(h) => h,
            Err(e) => {
                write_error(
                    out_error,
                    EppErrorCode::EppErrorOutOfMemory,
                    &format!("x25519 key clone failed: {e}"),
                );
                return EppErrorCode::EppErrorOutOfMemory;
            }
        };
        let kyber_secret = match secrets.kyber_secret.try_clone() {
            Ok(h) => h,
            Err(e) => {
                write_error(
                    out_error,
                    EppErrorCode::EppErrorOutOfMemory,
                    &format!("kyber key clone failed: {e}"),
                );
                return EppErrorCode::EppErrorOutOfMemory;
            }
        };
        match GroupSession::from_welcome(
            welcome_slice,
            x25519_private,
            kyber_secret,
            &identity.get_identity_ed25519_public(),
            &identity.get_identity_x25519_public(),
            ed25519_secret,
        ) {
            Ok(session) => {
                *out_group_handle = Box::into_raw(Box::new(EppGroupSessionHandle(Some(session))));
                EppErrorCode::EppSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// # Safety
/// See module-level FFI safety contract.  `(key_package_bytes, key_package_length)` must form a
/// valid readable slice.
#[no_mangle]
pub unsafe extern "C" fn epp_group_add_member(
    handle: *mut EppGroupSessionHandle,
    key_package_bytes: *const u8,
    key_package_length: usize,
    out_commit: *mut EppBuffer,
    out_welcome: *mut EppBuffer,
    out_error: *mut EppError,
) -> EppErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if key_package_bytes.is_null() || out_commit.is_null() || out_welcome.is_null() {
            write_error(
                out_error,
                EppErrorCode::EppErrorNullPointer,
                "A required pointer is null",
            );
            return EppErrorCode::EppErrorNullPointer;
        }
        if key_package_length > MAX_GROUP_MESSAGE_SIZE {
            write_error(
                out_error,
                EppErrorCode::EppErrorInvalidInput,
                "KeyPackage too large",
            );
            return EppErrorCode::EppErrorInvalidInput;
        }

        let kp_slice = std::slice::from_raw_parts(key_package_bytes, key_package_length);
        let kp = match crate::proto::GroupKeyPackage::decode(kp_slice) {
            Ok(kp) => kp,
            Err(e) => {
                write_error(
                    out_error,
                    EppErrorCode::EppErrorDecode,
                    &format!("KeyPackage decode: {e}"),
                );
                return EppErrorCode::EppErrorDecode;
            }
        };

        let session = match require_group_mut(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        match session.add_member(&kp) {
            Ok((commit_bytes, welcome_bytes)) => {
                write_buffer(out_commit, commit_bytes);
                write_buffer(out_welcome, welcome_bytes);
                EppErrorCode::EppSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// # Safety
/// See module-level FFI safety contract.
#[no_mangle]
pub unsafe extern "C" fn epp_group_remove_member(
    handle: *mut EppGroupSessionHandle,
    leaf_index: u32,
    out_commit: *mut EppBuffer,
    out_error: *mut EppError,
) -> EppErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if out_commit.is_null() {
            write_error(
                out_error,
                EppErrorCode::EppErrorNullPointer,
                "A required pointer is null",
            );
            return EppErrorCode::EppErrorNullPointer;
        }

        let session = match require_group_mut(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        match session.remove_member(leaf_index) {
            Ok(commit_bytes) => {
                write_buffer(out_commit, commit_bytes);
                EppErrorCode::EppSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// # Safety
/// See module-level FFI safety contract.
#[no_mangle]
pub unsafe extern "C" fn epp_group_update(
    handle: *mut EppGroupSessionHandle,
    out_commit: *mut EppBuffer,
    out_error: *mut EppError,
) -> EppErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if out_commit.is_null() {
            write_error(
                out_error,
                EppErrorCode::EppErrorNullPointer,
                "A required pointer is null",
            );
            return EppErrorCode::EppErrorNullPointer;
        }

        let session = match require_group_mut(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        match session.update() {
            Ok(commit_bytes) => {
                write_buffer(out_commit, commit_bytes);
                EppErrorCode::EppSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// # Safety
/// See module-level FFI safety contract.  `(commit_bytes, commit_length)` must form a valid
/// readable slice.
#[no_mangle]
pub unsafe extern "C" fn epp_group_process_commit(
    handle: *mut EppGroupSessionHandle,
    commit_bytes: *const u8,
    commit_length: usize,
    out_error: *mut EppError,
) -> EppErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if commit_bytes.is_null() {
            write_error(
                out_error,
                EppErrorCode::EppErrorNullPointer,
                "A required pointer is null",
            );
            return EppErrorCode::EppErrorNullPointer;
        }
        if commit_length > MAX_GROUP_MESSAGE_SIZE {
            write_error(
                out_error,
                EppErrorCode::EppErrorInvalidInput,
                "Commit too large",
            );
            return EppErrorCode::EppErrorInvalidInput;
        }

        let slice = std::slice::from_raw_parts(commit_bytes, commit_length);
        let session = match require_group_mut(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        match session.process_commit(slice) {
            Ok(()) => EppErrorCode::EppSuccess,
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// # Safety
/// See module-level FFI safety contract.  `(plaintext, plaintext_length)` must form a valid
/// readable slice.
#[no_mangle]
pub unsafe extern "C" fn epp_group_encrypt(
    handle: *mut EppGroupSessionHandle,
    plaintext: *const u8,
    plaintext_length: usize,
    out_ciphertext: *mut EppBuffer,
    out_error: *mut EppError,
) -> EppErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if plaintext.is_null() || out_ciphertext.is_null() {
            write_error(
                out_error,
                EppErrorCode::EppErrorNullPointer,
                "A required pointer is null",
            );
            return EppErrorCode::EppErrorNullPointer;
        }
        if plaintext_length > MAX_ENVELOPE_MESSAGE_SIZE {
            write_error(
                out_error,
                EppErrorCode::EppErrorInvalidInput,
                "Plaintext too large",
            );
            return EppErrorCode::EppErrorInvalidInput;
        }

        let pt = std::slice::from_raw_parts(plaintext, plaintext_length);
        let session = match require_group_mut(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        match session.encrypt(pt) {
            Ok(ct_bytes) => {
                write_buffer(out_ciphertext, ct_bytes);
                EppErrorCode::EppSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// # Safety
/// See module-level FFI safety contract.  `(ciphertext, ciphertext_length)` must form a valid
/// readable slice.
#[no_mangle]
pub unsafe extern "C" fn epp_group_decrypt(
    handle: *mut EppGroupSessionHandle,
    ciphertext: *const u8,
    ciphertext_length: usize,
    out_plaintext: *mut EppBuffer,
    out_sender_leaf: *mut u32,
    out_generation: *mut u32,
    out_error: *mut EppError,
) -> EppErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if ciphertext.is_null()
            || out_plaintext.is_null()
            || out_sender_leaf.is_null()
            || out_generation.is_null()
        {
            write_error(
                out_error,
                EppErrorCode::EppErrorNullPointer,
                "A required pointer is null",
            );
            return EppErrorCode::EppErrorNullPointer;
        }
        if ciphertext_length > MAX_GROUP_MESSAGE_SIZE {
            write_error(
                out_error,
                EppErrorCode::EppErrorInvalidInput,
                "Ciphertext too large",
            );
            return EppErrorCode::EppErrorInvalidInput;
        }

        let ct = std::slice::from_raw_parts(ciphertext, ciphertext_length);
        let session = match require_group_mut(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        match session.decrypt(ct) {
            Ok(result) => {
                write_buffer(out_plaintext, result.plaintext);
                *out_sender_leaf = result.sender_leaf_index;
                *out_generation = result.generation;
                EppErrorCode::EppSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// # Safety
/// See module-level FFI safety contract.
#[no_mangle]
pub unsafe extern "C" fn epp_group_get_id(
    handle: *mut EppGroupSessionHandle,
    out_group_id: *mut EppBuffer,
    out_error: *mut EppError,
) -> EppErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if out_group_id.is_null() {
            write_error(
                out_error,
                EppErrorCode::EppErrorNullPointer,
                "A required pointer is null",
            );
            return EppErrorCode::EppErrorNullPointer;
        }
        let session = match require_group_mut(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        match session.group_id() {
            Ok(group_id) => {
                write_buffer(out_group_id, group_id);
                EppErrorCode::EppSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// # Safety
/// See module-level FFI safety contract.
#[no_mangle]
pub unsafe extern "C" fn epp_group_get_epoch(handle: *mut EppGroupSessionHandle) -> u64 {
    ffi_catch_panic_value!(0u64, unsafe {
        group_ref_or_none(handle.cast_const())
            .and_then(|s| s.epoch().ok())
            .unwrap_or(0)
    })
}

/// # Safety
/// See module-level FFI safety contract.
#[no_mangle]
pub unsafe extern "C" fn epp_group_get_my_leaf_index(handle: *mut EppGroupSessionHandle) -> u32 {
    ffi_catch_panic_value!(u32::MAX, unsafe {
        group_ref_or_none(handle.cast_const())
            .and_then(|s| s.my_leaf_index().ok())
            .unwrap_or(u32::MAX)
    })
}

/// # Safety
/// See module-level FFI safety contract.
#[no_mangle]
pub unsafe extern "C" fn epp_group_get_member_count(handle: *mut EppGroupSessionHandle) -> u32 {
    ffi_catch_panic_value!(0u32, unsafe {
        group_ref_or_none(handle.cast_const())
            .and_then(|s| s.member_count().ok())
            .unwrap_or(0)
    })
}

/// # Safety
/// See module-level FFI safety contract.  `(key, key_length)` must form a valid readable slice.
#[no_mangle]
pub unsafe extern "C" fn epp_group_serialize(
    handle: *mut EppGroupSessionHandle,
    key: *const u8,
    key_length: usize,
    external_counter: u64,
    out_state: *mut EppBuffer,
    out_error: *mut EppError,
) -> EppErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if key.is_null() || out_state.is_null() {
            write_error(
                out_error,
                EppErrorCode::EppErrorNullPointer,
                "A required pointer is null",
            );
            return EppErrorCode::EppErrorNullPointer;
        }
        if key_length != AES_KEY_BYTES {
            write_error(
                out_error,
                EppErrorCode::EppErrorInvalidInput,
                "Key must be exactly 32 bytes",
            );
            return EppErrorCode::EppErrorInvalidInput;
        }
        if external_counter == 0 {
            write_error(
                out_error,
                EppErrorCode::EppErrorInvalidInput,
                "external_counter must be > 0",
            );
            return EppErrorCode::EppErrorInvalidInput;
        }

        let key_slice = std::slice::from_raw_parts(key, key_length);
        let session = match require_group_mut(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        match session.export_sealed_state(key_slice, external_counter) {
            Ok(bytes) => {
                write_buffer(out_state, bytes);
                EppErrorCode::EppSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// # Safety
/// See module-level FFI safety contract.  `(state_bytes, state_length)` and `(key, key_length)` must
/// form valid readable slices.  `out_handle` must point to writable `*mut EppGroupSessionHandle`.
#[no_mangle]
pub unsafe extern "C" fn epp_group_deserialize(
    state_bytes: *const u8,
    state_length: usize,
    key: *const u8,
    key_length: usize,
    min_external_counter: u64,
    out_external_counter: *mut u64,
    identity_handle: *mut EppIdentityHandle,
    out_handle: *mut *mut EppGroupSessionHandle,
    out_error: *mut EppError,
) -> EppErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if state_bytes.is_null()
            || key.is_null()
            || out_handle.is_null()
            || out_external_counter.is_null()
        {
            write_error(
                out_error,
                EppErrorCode::EppErrorNullPointer,
                "A required pointer is null",
            );
            return EppErrorCode::EppErrorNullPointer;
        }
        if state_length > MAX_GROUP_MESSAGE_SIZE {
            write_error(
                out_error,
                EppErrorCode::EppErrorInvalidInput,
                "State blob too large",
            );
            return EppErrorCode::EppErrorInvalidInput;
        }
        if key_length != AES_KEY_BYTES {
            write_error(
                out_error,
                EppErrorCode::EppErrorInvalidInput,
                "Key must be exactly 32 bytes",
            );
            return EppErrorCode::EppErrorInvalidInput;
        }

        let state_slice = std::slice::from_raw_parts(state_bytes, state_length);
        let key_slice = std::slice::from_raw_parts(key, key_length);
        let external_counter = match GroupSession::sealed_state_external_counter(state_slice) {
            Ok(c) => c,
            Err(e) => return write_protocol_error(out_error, &e),
        };
        *out_external_counter = external_counter;

        let identity = match require_identity_ref(identity_handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let ed25519_secret = match identity.get_identity_ed25519_private_key_copy() {
            Ok(sk) => sk,
            Err(e) => return write_protocol_error(out_error, &e),
        };

        match GroupSession::from_sealed_state(
            state_slice,
            key_slice,
            ed25519_secret,
            min_external_counter,
        ) {
            Ok(session) => {
                *out_handle = Box::into_raw(Box::new(EppGroupSessionHandle(Some(session))));
                EppErrorCode::EppSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// # Safety
/// See module-level FFI safety contract.
#[no_mangle]
pub unsafe extern "C" fn epp_group_export_public_state(
    handle: *mut EppGroupSessionHandle,
    out_public_state: *mut EppBuffer,
    out_error: *mut EppError,
) -> EppErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if out_public_state.is_null() {
            write_error(
                out_error,
                EppErrorCode::EppErrorNullPointer,
                "A required pointer is null",
            );
            return EppErrorCode::EppErrorNullPointer;
        }

        let session = match require_group_mut(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        match session.export_public_state() {
            Ok(bytes) => {
                write_buffer(out_public_state, bytes);
                EppErrorCode::EppSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// # Safety
/// See module-level FFI safety contract.  `(public_state, public_state_length)` and
/// `(credential, credential_length)` must form valid readable slices.
/// `out_group_handle` must point to writable `*mut EppGroupSessionHandle`.
#[no_mangle]
pub unsafe extern "C" fn epp_group_join_external(
    identity_handle: *mut EppIdentityHandle,
    public_state: *const u8,
    public_state_length: usize,
    credential: *const u8,
    credential_length: usize,
    out_group_handle: *mut *mut EppGroupSessionHandle,
    out_commit: *mut EppBuffer,
    out_error: *mut EppError,
) -> EppErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if public_state.is_null() || out_group_handle.is_null() || out_commit.is_null() {
            write_error(
                out_error,
                EppErrorCode::EppErrorNullPointer,
                "A required pointer is null",
            );
            return EppErrorCode::EppErrorNullPointer;
        }
        if public_state_length > MAX_GROUP_MESSAGE_SIZE {
            write_error(
                out_error,
                EppErrorCode::EppErrorInvalidInput,
                "Public state too large",
            );
            return EppErrorCode::EppErrorInvalidInput;
        }
        if credential_length > MAX_BUFFER_SIZE {
            write_error(
                out_error,
                EppErrorCode::EppErrorInvalidInput,
                "Credential too large",
            );
            return EppErrorCode::EppErrorInvalidInput;
        }

        let state_slice = std::slice::from_raw_parts(public_state, public_state_length);
        let cred = if credential.is_null() || credential_length == 0 {
            vec![]
        } else {
            std::slice::from_raw_parts(credential, credential_length).to_vec()
        };

        let identity = match require_identity_ref(identity_handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        match GroupSession::from_external_join(state_slice, identity, cred) {
            Ok((session, commit_bytes)) => {
                *out_group_handle = Box::into_raw(Box::new(EppGroupSessionHandle(Some(session))));
                write_buffer(out_commit, commit_bytes);
                EppErrorCode::EppSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

struct FfiPskResolver {
    psk_id: Vec<u8>,
    psk: Vec<u8>,
}

impl crate::protocol::group::PskResolver for FfiPskResolver {
    fn resolve(&self, psk_id: &[u8]) -> Option<Vec<u8>> {
        if psk_id == self.psk_id {
            Some(self.psk.clone())
        } else {
            None
        }
    }
}

/// # Safety
/// See module-level FFI safety contract.  `(psk_id, psk_id_length)` and `(psk, psk_length)` must
/// form valid readable slices.
#[no_mangle]
pub unsafe extern "C" fn epp_group_set_psk(
    handle: *mut EppGroupSessionHandle,
    psk_id: *const u8,
    psk_id_length: usize,
    psk: *const u8,
    psk_length: usize,
    out_error: *mut EppError,
) -> EppErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if handle.is_null() || psk_id.is_null() || psk.is_null() {
            write_error(
                out_error,
                EppErrorCode::EppErrorNullPointer,
                "A required pointer is null",
            );
            return EppErrorCode::EppErrorNullPointer;
        }
        if psk_id_length == 0 || psk_length < PSK_BYTES {
            write_error(
                out_error,
                EppErrorCode::EppErrorInvalidInput,
                "PSK id and value are required",
            );
            return EppErrorCode::EppErrorInvalidInput;
        }
        let id_slice = std::slice::from_raw_parts(psk_id, psk_id_length);
        let psk_slice = std::slice::from_raw_parts(psk, psk_length);
        let resolver = Box::new(FfiPskResolver {
            psk_id: id_slice.to_vec(),
            psk: psk_slice.to_vec(),
        });
        let session = match require_group_mut(handle, out_error) {
            Ok(s) => s,
            Err(code) => return code,
        };
        match session.set_psk_resolver(resolver) {
            Ok(()) => EppErrorCode::EppSuccess,
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// # Safety
/// See module-level FFI safety contract.
#[no_mangle]
pub unsafe extern "C" fn epp_group_get_member_leaf_indices(
    handle: *mut EppGroupSessionHandle,
    out_indices: *mut EppBuffer,
    out_error: *mut EppError,
) -> EppErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if out_indices.is_null() {
            write_error(
                out_error,
                EppErrorCode::EppErrorNullPointer,
                "A required pointer is null",
            );
            return EppErrorCode::EppErrorNullPointer;
        }
        let session = match require_group_mut(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let indices = match session.member_leaf_indices() {
            Ok(v) => v,
            Err(e) => return write_protocol_error(out_error, &e),
        };
        let mut buf = Vec::with_capacity(indices.len() * size_of::<u32>());
        for idx in &indices {
            buf.extend_from_slice(&idx.to_le_bytes());
        }
        write_buffer(out_indices, buf);
        EppErrorCode::EppSuccess
    })
}

/// # Safety
/// See module-level FFI safety contract.  `handle_ptr` must point to a handle from `epp_group_create`,
/// or be null.  The handle must not be used after this call.
#[no_mangle]
pub unsafe extern "C" fn epp_group_destroy(handle_ptr: *mut *mut EppGroupSessionHandle) {
    ffi_catch_panic_value!((), unsafe {
        if handle_ptr.is_null() {
            return;
        }
        let handle = std::ptr::replace(handle_ptr, std::ptr::null_mut());
        if !handle.is_null() {
            drop(Box::from_raw(handle));
        }
    });
}

struct FfiStateKeyProvider {
    handle: SecureMemoryHandle,
}

impl crate::interfaces::IStateKeyProvider for FfiStateKeyProvider {
    fn get_state_encryption_key(&self) -> Result<SecureMemoryHandle, ProtocolError> {
        let size = self.handle.size();
        let mut out = SecureMemoryHandle::allocate(size)
            .map_err(|e| ProtocolError::generic(format!("Allocate failed: {e}")))?;
        let bytes = self
            .handle
            .read_bytes(size)
            .map_err(ProtocolError::from_crypto)?;
        out.write(&bytes).map_err(ProtocolError::from_crypto)?;
        Ok(out)
    }
}

/// # Safety
/// See module-level FFI safety contract.  `(key, key_length)` must form a valid readable slice.
#[no_mangle]
pub unsafe extern "C" fn epp_session_serialize_sealed(
    handle: *mut EppSessionHandle,
    key: *const u8,
    key_length: usize,
    external_counter: u64,
    out_state: *mut EppBuffer,
    out_error: *mut EppError,
) -> EppErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if key.is_null() || out_state.is_null() {
            write_error(
                out_error,
                EppErrorCode::EppErrorNullPointer,
                "A required pointer is null",
            );
            return EppErrorCode::EppErrorNullPointer;
        }
        if key_length != AES_KEY_BYTES {
            write_error(
                out_error,
                EppErrorCode::EppErrorInvalidInput,
                "Key must be exactly 32 bytes",
            );
            return EppErrorCode::EppErrorInvalidInput;
        }
        if external_counter == 0 {
            write_error(
                out_error,
                EppErrorCode::EppErrorInvalidInput,
                "external_counter must be > 0",
            );
            return EppErrorCode::EppErrorInvalidInput;
        }

        let key_slice = std::slice::from_raw_parts(key, key_length);
        let mut smh = match SecureMemoryHandle::allocate(AES_KEY_BYTES) {
            Ok(h) => h,
            Err(e) => {
                write_error(
                    out_error,
                    EppErrorCode::EppErrorOutOfMemory,
                    &format!("Allocate: {e}"),
                );
                return EppErrorCode::EppErrorOutOfMemory;
            }
        };
        if let Err(e) = smh.write(key_slice) {
            write_error(
                out_error,
                EppErrorCode::EppErrorGeneric,
                &format!("Write: {e}"),
            );
            return EppErrorCode::EppErrorGeneric;
        }

        let provider = FfiStateKeyProvider { handle: smh };
        let session = match require_session_mut(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        match session.export_sealed_state(&provider, external_counter) {
            Ok(bytes) => {
                write_buffer(out_state, bytes);
                EppErrorCode::EppSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// # Safety
/// See module-level FFI safety contract.  `(state_bytes, state_length)` and `(key, key_length)` must
/// form valid readable slices.  `out_handle` must point to writable `*mut EppSessionHandle`.
#[no_mangle]
pub unsafe extern "C" fn epp_session_deserialize_sealed(
    state_bytes: *const u8,
    state_length: usize,
    key: *const u8,
    key_length: usize,
    min_external_counter: u64,
    out_external_counter: *mut u64,
    out_handle: *mut *mut EppSessionHandle,
    out_error: *mut EppError,
) -> EppErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if state_bytes.is_null()
            || key.is_null()
            || out_external_counter.is_null()
            || out_handle.is_null()
        {
            write_error(
                out_error,
                EppErrorCode::EppErrorNullPointer,
                "A required pointer is null",
            );
            return EppErrorCode::EppErrorNullPointer;
        }
        if key_length != AES_KEY_BYTES {
            write_error(
                out_error,
                EppErrorCode::EppErrorInvalidInput,
                "Key must be exactly 32 bytes",
            );
            return EppErrorCode::EppErrorInvalidInput;
        }
        if state_length > MAX_BUFFER_SIZE {
            write_error(
                out_error,
                EppErrorCode::EppErrorInvalidInput,
                "Sealed state too large",
            );
            return EppErrorCode::EppErrorInvalidInput;
        }

        let state_slice = std::slice::from_raw_parts(state_bytes, state_length);
        let key_slice = std::slice::from_raw_parts(key, key_length);
        let external_counter = match Session::sealed_state_external_counter(state_slice) {
            Ok(c) => c,
            Err(e) => return write_protocol_error(out_error, &e),
        };
        *out_external_counter = external_counter;
        let mut smh = match SecureMemoryHandle::allocate(AES_KEY_BYTES) {
            Ok(h) => h,
            Err(e) => {
                write_error(
                    out_error,
                    EppErrorCode::EppErrorOutOfMemory,
                    &format!("Allocate: {e}"),
                );
                return EppErrorCode::EppErrorOutOfMemory;
            }
        };
        if let Err(e) = smh.write(key_slice) {
            write_error(
                out_error,
                EppErrorCode::EppErrorGeneric,
                &format!("Write: {e}"),
            );
            return EppErrorCode::EppErrorGeneric;
        }

        let provider = FfiStateKeyProvider { handle: smh };
        match Session::from_sealed_state(state_slice, &provider, min_external_counter) {
            Ok(session) => {
                *out_handle = Box::into_raw(Box::new(EppSessionHandle(Some(session))));
                EppErrorCode::EppSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// # Safety
/// See module-level FFI safety contract.  `(plaintext, plaintext_length)` and
/// `(hint, hint_length)` must form valid readable slices.
#[no_mangle]
pub unsafe extern "C" fn epp_group_encrypt_sealed(
    handle: *mut EppGroupSessionHandle,
    plaintext: *const u8,
    plaintext_length: usize,
    hint: *const u8,
    hint_length: usize,
    out_ciphertext: *mut EppBuffer,
    out_error: *mut EppError,
) -> EppErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if plaintext.is_null() || out_ciphertext.is_null() {
            write_error(
                out_error,
                EppErrorCode::EppErrorNullPointer,
                "A required pointer is null",
            );
            return EppErrorCode::EppErrorNullPointer;
        }
        if plaintext_length > MAX_ENVELOPE_MESSAGE_SIZE {
            write_error(
                out_error,
                EppErrorCode::EppErrorInvalidInput,
                "Plaintext too large",
            );
            return EppErrorCode::EppErrorInvalidInput;
        }

        let pt = std::slice::from_raw_parts(plaintext, plaintext_length);

        if hint_length > MAX_BUFFER_SIZE {
            write_error(
                out_error,
                EppErrorCode::EppErrorInvalidInput,
                "hint too large",
            );
            return EppErrorCode::EppErrorInvalidInput;
        }

        let hint_slice = if hint.is_null() || hint_length == 0 {
            &[]
        } else {
            std::slice::from_raw_parts(hint, hint_length)
        };

        let session = match require_group_mut(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        match session.encrypt_sealed(pt, hint_slice) {
            Ok(ct_bytes) => {
                write_buffer(out_ciphertext, ct_bytes);
                EppErrorCode::EppSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// # Safety
/// See module-level FFI safety contract.  `(plaintext, plaintext_length)` must form a valid
/// readable slice.
#[no_mangle]
pub unsafe extern "C" fn epp_group_encrypt_disappearing(
    handle: *mut EppGroupSessionHandle,
    plaintext: *const u8,
    plaintext_length: usize,
    ttl_seconds: u32,
    out_ciphertext: *mut EppBuffer,
    out_error: *mut EppError,
) -> EppErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if plaintext.is_null() || out_ciphertext.is_null() {
            write_error(
                out_error,
                EppErrorCode::EppErrorNullPointer,
                "A required pointer is null",
            );
            return EppErrorCode::EppErrorNullPointer;
        }
        if plaintext_length > MAX_ENVELOPE_MESSAGE_SIZE {
            write_error(
                out_error,
                EppErrorCode::EppErrorInvalidInput,
                "Plaintext too large",
            );
            return EppErrorCode::EppErrorInvalidInput;
        }

        let pt = std::slice::from_raw_parts(plaintext, plaintext_length);
        let session = match require_group_mut(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        match session.encrypt_disappearing(pt, ttl_seconds) {
            Ok(ct_bytes) => {
                write_buffer(out_ciphertext, ct_bytes);
                EppErrorCode::EppSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// # Safety
/// See module-level FFI safety contract.  `(plaintext, plaintext_length)` must form a valid
/// readable slice.
#[no_mangle]
pub unsafe extern "C" fn epp_group_encrypt_frankable(
    handle: *mut EppGroupSessionHandle,
    plaintext: *const u8,
    plaintext_length: usize,
    out_ciphertext: *mut EppBuffer,
    out_error: *mut EppError,
) -> EppErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if plaintext.is_null() || out_ciphertext.is_null() {
            write_error(
                out_error,
                EppErrorCode::EppErrorNullPointer,
                "A required pointer is null",
            );
            return EppErrorCode::EppErrorNullPointer;
        }
        if plaintext_length > MAX_ENVELOPE_MESSAGE_SIZE {
            write_error(
                out_error,
                EppErrorCode::EppErrorInvalidInput,
                "Plaintext too large",
            );
            return EppErrorCode::EppErrorInvalidInput;
        }

        let pt = std::slice::from_raw_parts(plaintext, plaintext_length);
        let session = match require_group_mut(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        match session.encrypt_frankable(pt) {
            Ok(ct_bytes) => {
                write_buffer(out_ciphertext, ct_bytes);
                EppErrorCode::EppSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// # Safety
/// See module-level FFI safety contract.  `(new_content, new_content_length)` and
/// `(target_message_id, target_message_id_length)` must form valid readable slices.
#[no_mangle]
pub unsafe extern "C" fn epp_group_encrypt_edit(
    handle: *mut EppGroupSessionHandle,
    new_content: *const u8,
    new_content_length: usize,
    target_message_id: *const u8,
    target_message_id_length: usize,
    out_ciphertext: *mut EppBuffer,
    out_error: *mut EppError,
) -> EppErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if new_content.is_null() || target_message_id.is_null() || out_ciphertext.is_null() {
            write_error(
                out_error,
                EppErrorCode::EppErrorNullPointer,
                "A required pointer is null",
            );
            return EppErrorCode::EppErrorNullPointer;
        }
        if new_content_length > MAX_ENVELOPE_MESSAGE_SIZE {
            write_error(
                out_error,
                EppErrorCode::EppErrorInvalidInput,
                "Content too large",
            );
            return EppErrorCode::EppErrorInvalidInput;
        }
        if target_message_id_length != MESSAGE_ID_BYTES {
            write_error(
                out_error,
                EppErrorCode::EppErrorInvalidInput,
                "target_message_id must be 32 bytes",
            );
            return EppErrorCode::EppErrorInvalidInput;
        }

        let content = std::slice::from_raw_parts(new_content, new_content_length);
        let target_id = std::slice::from_raw_parts(target_message_id, target_message_id_length);
        let session = match require_group_mut(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        match session.encrypt_edit(content, target_id) {
            Ok(ct_bytes) => {
                write_buffer(out_ciphertext, ct_bytes);
                EppErrorCode::EppSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// # Safety
/// See module-level FFI safety contract.  `(target_message_id, target_message_id_length)` must form
/// a valid readable slice.
#[no_mangle]
pub unsafe extern "C" fn epp_group_encrypt_delete(
    handle: *mut EppGroupSessionHandle,
    target_message_id: *const u8,
    target_message_id_length: usize,
    out_ciphertext: *mut EppBuffer,
    out_error: *mut EppError,
) -> EppErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if target_message_id.is_null() || out_ciphertext.is_null() {
            write_error(
                out_error,
                EppErrorCode::EppErrorNullPointer,
                "A required pointer is null",
            );
            return EppErrorCode::EppErrorNullPointer;
        }
        if target_message_id_length != MESSAGE_ID_BYTES {
            write_error(
                out_error,
                EppErrorCode::EppErrorInvalidInput,
                "target_message_id must be 32 bytes",
            );
            return EppErrorCode::EppErrorInvalidInput;
        }

        let target_id = std::slice::from_raw_parts(target_message_id, target_message_id_length);
        let session = match require_group_mut(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        match session.encrypt_delete(target_id) {
            Ok(ct_bytes) => {
                write_buffer(out_ciphertext, ct_bytes);
                EppErrorCode::EppSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

#[repr(C)]
pub struct EppGroupDecryptResult {
    pub plaintext: EppBuffer,
    pub sender_leaf_index: u32,
    pub generation: u32,
    pub content_type: u32,
    pub ttl_seconds: u32,
    pub sent_timestamp: u64,
    pub message_id: EppBuffer,
    pub referenced_message_id: EppBuffer,
    pub has_sealed_payload: u8,
    pub has_franking_data: u8,
}

/// # Safety
/// `result` must be null or point to a value previously written by this FFI layer.
#[no_mangle]
pub unsafe extern "C" fn epp_group_decrypt_result_free(result: *mut EppGroupDecryptResult) {
    if result.is_null() {
        return;
    }
    epp_buffer_release(std::ptr::addr_of_mut!((*result).plaintext));
    epp_buffer_release(std::ptr::addr_of_mut!((*result).message_id));
    epp_buffer_release(std::ptr::addr_of_mut!((*result).referenced_message_id));
}

/// # Safety
/// See module-level FFI safety contract.  `(ciphertext, ciphertext_length)` must form a valid
/// readable slice.
#[no_mangle]
pub unsafe extern "C" fn epp_group_decrypt_ex(
    handle: *mut EppGroupSessionHandle,
    ciphertext: *const u8,
    ciphertext_length: usize,
    out_result: *mut EppGroupDecryptResult,
    out_error: *mut EppError,
) -> EppErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if ciphertext.is_null() || out_result.is_null() {
            write_error(
                out_error,
                EppErrorCode::EppErrorNullPointer,
                "A required pointer is null",
            );
            return EppErrorCode::EppErrorNullPointer;
        }
        if ciphertext_length > MAX_GROUP_MESSAGE_SIZE {
            write_error(
                out_error,
                EppErrorCode::EppErrorInvalidInput,
                "Ciphertext too large",
            );
            return EppErrorCode::EppErrorInvalidInput;
        }

        let ct = std::slice::from_raw_parts(ciphertext, ciphertext_length);
        let session = match require_group_mut(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        match session.decrypt(ct) {
            Ok(r) => {
                write_buffer(std::ptr::addr_of_mut!((*out_result).plaintext), r.plaintext);
                (*out_result).sender_leaf_index = r.sender_leaf_index;
                (*out_result).generation = r.generation;
                (*out_result).content_type = r.content_type.to_u32();
                (*out_result).ttl_seconds = r.ttl_seconds;
                (*out_result).sent_timestamp = r.sent_timestamp;
                write_buffer(std::ptr::addr_of_mut!((*out_result).message_id), r.message_id);
                write_buffer(
                    std::ptr::addr_of_mut!((*out_result).referenced_message_id),
                    r.referenced_message_id,
                );
                (*out_result).has_sealed_payload = u8::from(r.sealed_payload.is_some());
                (*out_result).has_franking_data = u8::from(r.franking_data.is_some());
                EppErrorCode::EppSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// # Safety
/// See module-level FFI safety contract.  `(group_id, group_id_length)` must form a valid
/// readable slice.
#[no_mangle]
pub unsafe extern "C" fn epp_group_compute_message_id(
    group_id: *const u8,
    group_id_length: usize,
    epoch: u64,
    sender_leaf_index: u32,
    generation: u32,
    out_message_id: *mut EppBuffer,
    out_error: *mut EppError,
) -> EppErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if group_id.is_null() || out_message_id.is_null() {
            write_error(
                out_error,
                EppErrorCode::EppErrorNullPointer,
                "A required pointer is null",
            );
            return EppErrorCode::EppErrorNullPointer;
        }

        let gid = std::slice::from_raw_parts(group_id, group_id_length);
        let id = crate::protocol::group::compute_message_id(
            gid,
            epoch,
            sender_leaf_index,
            generation,
        );
        write_buffer(out_message_id, id);
        EppErrorCode::EppSuccess
    })
}

/// # Safety
/// See module-level FFI safety contract.  `(hint, hint_length)`, `(encrypted_content, encrypted_content_length)`,
/// `(nonce, nonce_length)`, and `(seal_key, seal_key_length)` must form valid readable slices.
#[no_mangle]
pub unsafe extern "C" fn epp_group_reveal_sealed(
    hint: *const u8,
    hint_length: usize,
    encrypted_content: *const u8,
    encrypted_content_length: usize,
    nonce: *const u8,
    nonce_length: usize,
    seal_key: *const u8,
    seal_key_length: usize,
    out_plaintext: *mut EppBuffer,
    out_error: *mut EppError,
) -> EppErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if encrypted_content.is_null()
            || nonce.is_null()
            || seal_key.is_null()
            || out_plaintext.is_null()
        {
            write_error(
                out_error,
                EppErrorCode::EppErrorNullPointer,
                "A required pointer is null",
            );
            return EppErrorCode::EppErrorNullPointer;
        }
        if nonce_length != AES_GCM_NONCE_BYTES {
            write_error(
                out_error,
                EppErrorCode::EppErrorInvalidInput,
                "Nonce must be 12 bytes",
            );
            return EppErrorCode::EppErrorInvalidInput;
        }
        if seal_key_length != AES_KEY_BYTES {
            write_error(
                out_error,
                EppErrorCode::EppErrorInvalidInput,
                "Seal key must be 32 bytes",
            );
            return EppErrorCode::EppErrorInvalidInput;
        }
        if encrypted_content_length > MAX_GROUP_MESSAGE_SIZE {
            write_error(
                out_error,
                EppErrorCode::EppErrorInvalidInput,
                "Encrypted content too large",
            );
            return EppErrorCode::EppErrorInvalidInput;
        }

        if hint_length > MAX_BUFFER_SIZE {
            write_error(
                out_error,
                EppErrorCode::EppErrorInvalidInput,
                "hint too large",
            );
            return EppErrorCode::EppErrorInvalidInput;
        }

        let _ = if hint.is_null() || hint_length == 0 {
            &[] as &[u8]
        } else {
            std::slice::from_raw_parts(hint, hint_length)
        };
        let ec = std::slice::from_raw_parts(encrypted_content, encrypted_content_length);
        let n = std::slice::from_raw_parts(nonce, nonce_length);
        let sk = std::slice::from_raw_parts(seal_key, seal_key_length);

        use crate::protocol::group::{GroupSession, SealedPayload};
        let payload = SealedPayload {
            hint: vec![],
            encrypted_content: ec.to_vec(),
            nonce: n.to_vec(),
            seal_key: sk.to_vec(),
        };
        match GroupSession::reveal_sealed(&payload) {
            Ok(pt) => {
                write_buffer(out_plaintext, pt);
                EppErrorCode::EppSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// # Safety
/// See module-level FFI safety contract.  `(franking_tag, franking_tag_length)`,
/// `(franking_key, franking_key_length)`, `(content, content_length)`, and
/// `(sealed_content, sealed_content_length)` must form valid readable slices.
#[no_mangle]
pub unsafe extern "C" fn epp_group_verify_franking(
    franking_tag: *const u8,
    franking_tag_length: usize,
    franking_key: *const u8,
    franking_key_length: usize,
    content: *const u8,
    content_length: usize,
    sealed_content: *const u8,
    sealed_content_length: usize,
    out_valid: *mut u8,
    out_error: *mut EppError,
) -> EppErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if franking_tag.is_null()
            || franking_key.is_null()
            || content.is_null()
            || out_valid.is_null()
        {
            write_error(
                out_error,
                EppErrorCode::EppErrorNullPointer,
                "A required pointer is null",
            );
            return EppErrorCode::EppErrorNullPointer;
        }
        if franking_tag_length != HMAC_BYTES {
            write_error(
                out_error,
                EppErrorCode::EppErrorInvalidInput,
                "Franking tag must be 32 bytes",
            );
            return EppErrorCode::EppErrorInvalidInput;
        }
        if franking_key_length != AES_KEY_BYTES {
            write_error(
                out_error,
                EppErrorCode::EppErrorInvalidInput,
                "Franking key must be 32 bytes",
            );
            return EppErrorCode::EppErrorInvalidInput;
        }
        if content_length > MAX_GROUP_MESSAGE_SIZE {
            write_error(
                out_error,
                EppErrorCode::EppErrorInvalidInput,
                "Content too large",
            );
            return EppErrorCode::EppErrorInvalidInput;
        }
        if sealed_content_length > MAX_GROUP_MESSAGE_SIZE {
            write_error(
                out_error,
                EppErrorCode::EppErrorInvalidInput,
                "Sealed content too large",
            );
            return EppErrorCode::EppErrorInvalidInput;
        }

        use crate::protocol::group::{FrankingData, GroupSession};
        let sc = if sealed_content.is_null() || sealed_content_length == 0 {
            vec![]
        } else {
            std::slice::from_raw_parts(sealed_content, sealed_content_length).to_vec()
        };
        let data = FrankingData {
            franking_tag: std::slice::from_raw_parts(franking_tag, franking_tag_length).to_vec(),
            franking_key: std::slice::from_raw_parts(franking_key, franking_key_length).to_vec(),
            content: std::slice::from_raw_parts(content, content_length).to_vec(),
            sealed_content: sc,
        };
        match GroupSession::verify_franking(&data) {
            Ok(valid) => {
                *out_valid = u8::from(valid);
                EppErrorCode::EppSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// # Safety
/// See module-level FFI safety contract.
#[no_mangle]
pub unsafe extern "C" fn epp_group_get_pending_reinit(
    handle: *mut EppGroupSessionHandle,
    out_new_group_id: *mut EppBuffer,
    out_new_version: *mut u32,
    out_error: *mut EppError,
) -> EppErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if out_new_group_id.is_null() || out_new_version.is_null() {
            write_error(
                out_error,
                EppErrorCode::EppErrorNullPointer,
                "A required pointer is null",
            );
            return EppErrorCode::EppErrorNullPointer;
        }

        let session = match require_group_mut(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        match session.pending_reinit() {
            Ok(Some(info)) => {
                write_buffer(out_new_group_id, info.new_group_id);
                *out_new_version = info.new_version;
            }
            Ok(None) => {
                write_buffer(out_new_group_id, vec![]);
                *out_new_version = 0;
            }
            Err(e) => return write_protocol_error(out_error, &e),
        }
        EppErrorCode::EppSuccess
    })
}

// ─── Session identity / ID getters ─────────────────────────────────────────

/// Fixed-size struct for returning a peer's or local identity public keys.
/// Both fields are 32-byte raw public keys; no heap allocation.
#[repr(C)]
pub struct EppSessionPeerIdentity {
    pub ed25519_public: [u8; ED25519_PUBLIC_KEY_BYTES],
    pub x25519_public: [u8; X25519_PUBLIC_KEY_BYTES],
}

/// # Safety
/// See module-level FFI safety contract.
#[no_mangle]
pub unsafe extern "C" fn epp_session_get_id(
    handle: *mut EppSessionHandle,
    out_session_id: *mut EppBuffer,
    out_error: *mut EppError,
) -> EppErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if out_session_id.is_null() {
            write_error(
                out_error,
                EppErrorCode::EppErrorNullPointer,
                "out_session_id is null",
            );
            return EppErrorCode::EppErrorNullPointer;
        }
        let session = match require_session_mut(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        write_buffer(out_session_id, session.get_session_id());
        EppErrorCode::EppSuccess
    })
}

/// # Safety
/// See module-level FFI safety contract.
#[no_mangle]
pub unsafe extern "C" fn epp_session_get_peer_identity(
    handle: *mut EppSessionHandle,
    out_identity: *mut EppSessionPeerIdentity,
    out_error: *mut EppError,
) -> EppErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if out_identity.is_null() {
            write_error(
                out_error,
                EppErrorCode::EppErrorNullPointer,
                "out_identity is null",
            );
            return EppErrorCode::EppErrorNullPointer;
        }
        let session = match require_session_mut(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let peer = session.get_peer_identity();
        if peer.ed25519_public.len() != ED25519_PUBLIC_KEY_BYTES
            || peer.x25519_public.len() != X25519_PUBLIC_KEY_BYTES
        {
            write_error(
                out_error,
                EppErrorCode::EppErrorInvalidState,
                "Peer identity keys have unexpected length",
            );
            return EppErrorCode::EppErrorInvalidState;
        }
        let mut result = EppSessionPeerIdentity {
            ed25519_public: [0u8; ED25519_PUBLIC_KEY_BYTES],
            x25519_public: [0u8; X25519_PUBLIC_KEY_BYTES],
        };
        result.ed25519_public.copy_from_slice(&peer.ed25519_public);
        result.x25519_public.copy_from_slice(&peer.x25519_public);
        *out_identity = result;
        EppErrorCode::EppSuccess
    })
}

/// # Safety
/// See module-level FFI safety contract.
#[no_mangle]
pub unsafe extern "C" fn epp_session_get_local_identity(
    handle: *mut EppSessionHandle,
    out_identity: *mut EppSessionPeerIdentity,
    out_error: *mut EppError,
) -> EppErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if out_identity.is_null() {
            write_error(
                out_error,
                EppErrorCode::EppErrorNullPointer,
                "out_identity is null",
            );
            return EppErrorCode::EppErrorNullPointer;
        }
        let session = match require_session_mut(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let local = session.get_local_identity();
        if local.ed25519_public.len() != ED25519_PUBLIC_KEY_BYTES
            || local.x25519_public.len() != X25519_PUBLIC_KEY_BYTES
        {
            write_error(
                out_error,
                EppErrorCode::EppErrorInvalidState,
                "Local identity keys have unexpected length",
            );
            return EppErrorCode::EppErrorInvalidState;
        }
        let mut result = EppSessionPeerIdentity {
            ed25519_public: [0u8; ED25519_PUBLIC_KEY_BYTES],
            x25519_public: [0u8; X25519_PUBLIC_KEY_BYTES],
        };
        result.ed25519_public.copy_from_slice(&local.ed25519_public);
        result.x25519_public.copy_from_slice(&local.x25519_public);
        *out_identity = result;
        EppErrorCode::EppSuccess
    })
}

// ─── OTK replenishment ─────────────────────────────────────────────────────

/// Generates `count` fresh OTKs, adds them to the identity's local pool, and
/// returns a partial PreKeyBundle proto (only one_time_pre_keys populated)
/// suitable for uploading to the key server.  Release with epp_buffer_release.
///
/// # Safety
/// See module-level FFI safety contract.
#[no_mangle]
pub unsafe extern "C" fn epp_prekey_bundle_replenish(
    identity_handle: *mut EppIdentityHandle,
    count: u32,
    out_keys: *mut EppBuffer,
    out_error: *mut EppError,
) -> EppErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if out_keys.is_null() {
            write_error(
                out_error,
                EppErrorCode::EppErrorNullPointer,
                "out_keys is null",
            );
            return EppErrorCode::EppErrorNullPointer;
        }
        if count == 0 {
            write_error(
                out_error,
                EppErrorCode::EppErrorInvalidInput,
                "count must be > 0",
            );
            return EppErrorCode::EppErrorInvalidInput;
        }
        let identity = match require_identity_mut(identity_handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let pairs = match identity.replenish_one_time_pre_keys(count) {
            Ok(p) => p,
            Err(e) => return write_protocol_error(out_error, &e),
        };
        let proto_opks: Vec<OneTimePreKey> = pairs
            .into_iter()
            .map(|(id, pk)| OneTimePreKey {
                one_time_pre_key_id: id,
                public_key: pk,
            })
            .collect();
        let partial_bundle = PreKeyBundle {
            version: PROTOCOL_VERSION,
            one_time_pre_keys: proto_opks,
            ..Default::default()
        };
        let mut buf = Vec::new();
        if let Err(e) = partial_bundle.encode(&mut buf) {
            write_error(
                out_error,
                EppErrorCode::EppErrorEncode,
                &format!("Failed to encode replenished OTKs: {e}"),
            );
            return EppErrorCode::EppErrorEncode;
        }
        write_buffer(out_keys, buf);
        EppErrorCode::EppSuccess
    })
}

// ─── EnvelopeMetadata parsing ──────────────────────────────────────────────

/// Parsed envelope metadata; correlation_id is heap-allocated (may be NULL).
/// Free the contents with epp_envelope_metadata_free() after use.
/// Do NOT free the struct itself — it is caller-allocated.
#[repr(C)]
pub struct EppEnvelopeMetadata {
    pub envelope_type: EppEnvelopeType,
    pub envelope_id: u32,
    pub message_index: u64,
    pub correlation_id: *mut c_char,
    pub correlation_id_length: usize,
}

/// # Safety
/// `(metadata_bytes, metadata_length)` must form a valid readable slice.
/// `out_meta` must point to writable EppEnvelopeMetadata.
#[no_mangle]
pub unsafe extern "C" fn epp_envelope_metadata_parse(
    metadata_bytes: *const u8,
    metadata_length: usize,
    out_meta: *mut EppEnvelopeMetadata,
    out_error: *mut EppError,
) -> EppErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if metadata_bytes.is_null() || out_meta.is_null() {
            write_error(
                out_error,
                EppErrorCode::EppErrorNullPointer,
                "A required pointer is null",
            );
            return EppErrorCode::EppErrorNullPointer;
        }
        let slice = std::slice::from_raw_parts(metadata_bytes, metadata_length);
        let proto = match crate::proto::EnvelopeMetadata::decode(slice) {
            Ok(m) => m,
            Err(e) => {
                write_error(
                    out_error,
                    EppErrorCode::EppErrorDecode,
                    &format!("Failed to decode EnvelopeMetadata: {e}"),
                );
                return EppErrorCode::EppErrorDecode;
            }
        };
        let envelope_type = match proto.envelope_type {
            0 => EppEnvelopeType::EppEnvelopeRequest,
            1 => EppEnvelopeType::EppEnvelopeResponse,
            2 => EppEnvelopeType::EppEnvelopeNotification,
            3 => EppEnvelopeType::EppEnvelopeHeartbeat,
            4 => EppEnvelopeType::EppEnvelopeErrorResponse,
            _ => EppEnvelopeType::EppEnvelopeRequest,
        };
        let (correlation_id_ptr, correlation_id_length) =
            if let Some(ref cid) = proto.correlation_id {
                let cstr = CString::new(cid.as_str()).unwrap_or_default();
                let len = cstr.as_bytes().len();
                (cstr.into_raw(), len)
            } else {
                (std::ptr::null_mut(), 0)
            };
        *out_meta = EppEnvelopeMetadata {
            envelope_type,
            envelope_id: proto.envelope_id,
            message_index: proto.message_index,
            correlation_id: correlation_id_ptr,
            correlation_id_length,
        };
        EppErrorCode::EppSuccess
    })
}

/// # Safety
/// `meta` must point to an EppEnvelopeMetadata populated by
/// epp_envelope_metadata_parse().  Frees correlation_id if non-null.
/// Does NOT free the meta struct itself (caller-allocated).
#[no_mangle]
pub unsafe extern "C" fn epp_envelope_metadata_free(meta: *mut EppEnvelopeMetadata) {
    if meta.is_null() {
        return;
    }
    unsafe {
        if !(*meta).correlation_id.is_null() {
            drop(CString::from_raw((*meta).correlation_id));
            (*meta).correlation_id = std::ptr::null_mut();
            (*meta).correlation_id_length = 0;
        }
    }
}

// ─── C event callbacks — 1-to-1 session ────────────────────────────────────

/// Called when the handshake is complete and the session is established.
/// `session_id` / `session_id_len` are the 16-byte session identifier.
pub type EppOnHandshakeCompleted = Option<
    unsafe extern "C" fn(session_id: *const u8, session_id_len: usize, user_data: *mut c_void),
>;

/// Called every time the DH ratchet rotates (a new ratchet epoch begins).
pub type EppOnRatchetRotated =
    Option<unsafe extern "C" fn(epoch: u64, user_data: *mut c_void)>;

/// Called on an internal protocol error (non-fatal; logged for diagnostics).
/// `code` is the error category; `message` is a null-terminated description.
pub type EppOnSessionError = Option<
    unsafe extern "C" fn(code: EppErrorCode, message: *const c_char, user_data: *mut c_void),
>;

/// Called when fewer than ~20 % of the nonce budget remains for the current
/// chain.  The app should send or receive a message to trigger a ratchet step.
pub type EppOnNonceExhaustionWarning = Option<
    unsafe extern "C" fn(remaining: u64, max_capacity: u64, user_data: *mut c_void),
>;

/// Called when many messages have been sent without a DH ratchet step
/// (the peer may be offline).  Consider forcing a ratchet reset.
pub type EppOnRatchetStallingWarning =
    Option<unsafe extern "C" fn(messages_since_ratchet: u64, user_data: *mut c_void)>;

/// Set of C function-pointer callbacks for a 1-to-1 session.
/// Any slot may be NULL to ignore that event.
/// `user_data` is passed unchanged to every callback.
#[repr(C)]
pub struct EppSessionEventCallbacks {
    pub on_handshake_completed: EppOnHandshakeCompleted,
    pub on_ratchet_rotated: EppOnRatchetRotated,
    pub on_error: EppOnSessionError,
    pub on_nonce_exhaustion_warning: EppOnNonceExhaustionWarning,
    pub on_ratchet_stalling_warning: EppOnRatchetStallingWarning,
    /// Arbitrary pointer passed verbatim to every callback.  May be NULL.
    /// The library never reads or writes through this pointer.
    pub user_data: *mut c_void,
}

/// Internal Rust bridge: holds the C callback vtable and implements the
/// `IProtocolEventHandler` trait so the session can fire events.
struct CFfiSessionEventHandler {
    callbacks: EppSessionEventCallbacks,
}

// Safety: C function pointers and *mut c_void are safe to move across threads
// when the caller guarantees thread-safe user_data access.
unsafe impl Send for CFfiSessionEventHandler {}
unsafe impl Sync for CFfiSessionEventHandler {}

impl IProtocolEventHandler for CFfiSessionEventHandler {
    fn on_handshake_completed(&self, session_id: &[u8]) {
        if let Some(cb) = self.callbacks.on_handshake_completed {
            unsafe { cb(session_id.as_ptr(), session_id.len(), self.callbacks.user_data) };
        }
    }

    fn on_ratchet_rotated(&self, epoch: u64) {
        if let Some(cb) = self.callbacks.on_ratchet_rotated {
            unsafe { cb(epoch, self.callbacks.user_data) };
        }
    }

    fn on_error(&self, error: &ProtocolError) {
        if let Some(cb) = self.callbacks.on_error {
            let code = error_code_from_protocol(error);
            let msg = CString::new(error.to_string()).unwrap_or_default();
            unsafe { cb(code, msg.as_ptr(), self.callbacks.user_data) };
        }
    }

    fn on_nonce_exhaustion_warning(&self, remaining: u64, max_capacity: u64) {
        if let Some(cb) = self.callbacks.on_nonce_exhaustion_warning {
            unsafe { cb(remaining, max_capacity, self.callbacks.user_data) };
        }
    }

    fn on_ratchet_stalling_warning(&self, messages_since_ratchet: u64) {
        if let Some(cb) = self.callbacks.on_ratchet_stalling_warning {
            unsafe { cb(messages_since_ratchet, self.callbacks.user_data) };
        }
    }
}

/// Register C event callbacks on a 1-to-1 session.
///
/// # Safety
/// See module-level FFI safety contract.
/// `callbacks` is copied by value; user_data must remain valid until the session
/// is destroyed or a new handler replaces this one.
#[no_mangle]
pub unsafe extern "C" fn epp_session_set_event_handler(
    handle: *mut EppSessionHandle,
    callbacks: *const EppSessionEventCallbacks,
    out_error: *mut EppError,
) -> EppErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if callbacks.is_null() {
            write_error(
                out_error,
                EppErrorCode::EppErrorNullPointer,
                "callbacks is null",
            );
            return EppErrorCode::EppErrorNullPointer;
        }
        let session = match require_session_mut(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        // Safety: callbacks points to a valid EppSessionEventCallbacks for the
        // duration of this call; we immediately copy all fields.
        let cbs = std::ptr::read(callbacks);
        let handler = Arc::new(CFfiSessionEventHandler { callbacks: cbs });
        session.set_event_handler(handler);
        EppErrorCode::EppSuccess
    })
}

// ─── C event callbacks — group session ─────────────────────────────────────

/// Called when a new member is added to the group via a Commit.
/// `identity_ed25519` / `identity_ed25519_len` are the new member's 32-byte
/// Ed25519 public key.
pub type EppOnMemberAdded = Option<
    unsafe extern "C" fn(
        leaf_index: u32,
        identity_ed25519: *const u8,
        identity_ed25519_len: usize,
        user_data: *mut c_void,
    ),
>;

/// Called when a member is removed from the group via a Commit.
pub type EppOnMemberRemoved =
    Option<unsafe extern "C" fn(leaf_index: u32, user_data: *mut c_void)>;

/// Called every time a Commit is applied and the epoch number advances.
pub type EppOnEpochAdvanced = Option<
    unsafe extern "C" fn(new_epoch: u64, member_count: u32, user_data: *mut c_void),
>;

/// Called when the sender-key generation counter for this member is running
/// low (approaching max_messages_per_epoch).  Trigger an Update commit soon.
pub type EppOnSenderKeyExhaustionWarning = Option<
    unsafe extern "C" fn(remaining: u32, max_capacity: u32, user_data: *mut c_void),
>;

/// Called when a ReInit proposal is applied in a Commit.
/// The group is now deprecated; migrate to `new_group_id` at `new_version`.
/// `new_group_id` / `new_group_id_len` are valid only for the duration of
/// the callback.
pub type EppOnReInitProposed = Option<
    unsafe extern "C" fn(
        new_group_id: *const u8,
        new_group_id_len: usize,
        new_version: u32,
        user_data: *mut c_void,
    ),
>;

/// Set of C function-pointer callbacks for a group session.
/// Any slot may be NULL to ignore that event.
/// `user_data` is passed unchanged to every callback.
#[repr(C)]
pub struct EppGroupEventCallbacks {
    pub on_member_added: EppOnMemberAdded,
    pub on_member_removed: EppOnMemberRemoved,
    pub on_epoch_advanced: EppOnEpochAdvanced,
    pub on_sender_key_exhaustion_warning: EppOnSenderKeyExhaustionWarning,
    pub on_reinit_proposed: EppOnReInitProposed,
    /// Arbitrary pointer passed verbatim to every callback.  May be NULL.
    pub user_data: *mut c_void,
}

struct CFfiGroupEventHandler {
    callbacks: EppGroupEventCallbacks,
}

unsafe impl Send for CFfiGroupEventHandler {}
unsafe impl Sync for CFfiGroupEventHandler {}

impl IGroupEventHandler for CFfiGroupEventHandler {
    fn on_member_added(&self, leaf_index: u32, identity_ed25519: &[u8]) {
        if let Some(cb) = self.callbacks.on_member_added {
            unsafe {
                cb(
                    leaf_index,
                    identity_ed25519.as_ptr(),
                    identity_ed25519.len(),
                    self.callbacks.user_data,
                )
            };
        }
    }

    fn on_member_removed(&self, leaf_index: u32) {
        if let Some(cb) = self.callbacks.on_member_removed {
            unsafe { cb(leaf_index, self.callbacks.user_data) };
        }
    }

    fn on_epoch_advanced(&self, new_epoch: u64, member_count: u32) {
        if let Some(cb) = self.callbacks.on_epoch_advanced {
            unsafe { cb(new_epoch, member_count, self.callbacks.user_data) };
        }
    }

    fn on_sender_key_exhaustion_warning(&self, remaining: u32, max_capacity: u32) {
        if let Some(cb) = self.callbacks.on_sender_key_exhaustion_warning {
            unsafe { cb(remaining, max_capacity, self.callbacks.user_data) };
        }
    }

    fn on_reinit_proposed(&self, new_group_id: &[u8], new_version: u32) {
        if let Some(cb) = self.callbacks.on_reinit_proposed {
            unsafe {
                cb(
                    new_group_id.as_ptr(),
                    new_group_id.len(),
                    new_version,
                    self.callbacks.user_data,
                )
            };
        }
    }
}

/// Register C event callbacks on a group session.
///
/// # Safety
/// See module-level FFI safety contract.
/// `callbacks` is copied by value; user_data must remain valid until the session
/// is destroyed or a new handler replaces this one.
#[no_mangle]
pub unsafe extern "C" fn epp_group_set_event_handler(
    handle: *mut EppGroupSessionHandle,
    callbacks: *const EppGroupEventCallbacks,
    out_error: *mut EppError,
) -> EppErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if callbacks.is_null() {
            write_error(
                out_error,
                EppErrorCode::EppErrorNullPointer,
                "callbacks is null",
            );
            return EppErrorCode::EppErrorNullPointer;
        }
        let session = match require_group_mut(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let cbs = std::ptr::read(callbacks);
        let handler = Arc::new(CFfiGroupEventHandler { callbacks: cbs });
        session.set_event_handler(handler);
        EppErrorCode::EppSuccess
    })
}

// ─── C event callbacks — identity ──────────────────────────────────────────

/// Called after an OTK is consumed and the remaining pool has dropped below
/// the exhaustion-warning threshold (default: ≤ 10 % of max_capacity).
/// Upload fresh OTKs via `epp_prekey_bundle_replenish` before supply runs out.
pub type EppOnOtkExhaustionWarning = Option<
    unsafe extern "C" fn(remaining: u32, max_capacity: u32, user_data: *mut c_void),
>;

/// Set of C function-pointer callbacks for an identity handle.
/// Any slot may be NULL to ignore that event.
/// `user_data` is passed unchanged to every callback.
#[repr(C)]
pub struct EppIdentityEventCallbacks {
    pub on_otk_exhaustion_warning: EppOnOtkExhaustionWarning,
    /// Arbitrary pointer passed verbatim to every callback.  May be NULL.
    /// The library never reads or writes through this pointer.
    pub user_data: *mut c_void,
}

struct CFfiIdentityEventHandler {
    callbacks: EppIdentityEventCallbacks,
}

unsafe impl Send for CFfiIdentityEventHandler {}
unsafe impl Sync for CFfiIdentityEventHandler {}

impl IIdentityEventHandler for CFfiIdentityEventHandler {
    fn on_otk_exhaustion_warning(&self, remaining: u32, max_capacity: u32) {
        if let Some(cb) = self.callbacks.on_otk_exhaustion_warning {
            unsafe { cb(remaining, max_capacity, self.callbacks.user_data) };
        }
    }
}

/// Register C event callbacks on an identity handle.
///
/// # Safety
/// See module-level FFI safety contract.
/// `callbacks` is copied by value; `user_data` must remain valid until the
/// identity is destroyed or a new handler replaces this one.
#[no_mangle]
pub unsafe extern "C" fn epp_identity_set_event_handler(
    handle: *mut EppIdentityHandle,
    callbacks: *const EppIdentityEventCallbacks,
    out_error: *mut EppError,
) -> EppErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if callbacks.is_null() {
            write_error(
                out_error,
                EppErrorCode::EppErrorNullPointer,
                "callbacks is null",
            );
            return EppErrorCode::EppErrorNullPointer;
        }
        let identity = match require_identity_mut(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let cbs = std::ptr::read(callbacks);
        let handler = Arc::new(CFfiIdentityEventHandler { callbacks: cbs });
        identity.set_event_handler(handler);
        EppErrorCode::EppSuccess
    })
}

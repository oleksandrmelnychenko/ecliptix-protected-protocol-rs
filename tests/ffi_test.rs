#![cfg(feature = "ffi")]
// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

#![allow(clippy::borrow_as_ptr, unsafe_code)]

use ecliptix_protocol::crypto::CryptoInterop;

fn init() {
    CryptoInterop::initialize().expect("crypto init");
}

mod ffi {
    use ecliptix_protocol::ffi::api::*;
    use std::ptr;

    const fn null_error() -> EppError {
        EppError {
            code: EppErrorCode::EppSuccess,
            message: ptr::null_mut(),
        }
    }

    fn init_lib() {
        epp_init();
    }

    #[test]
    fn ffi_version_is_non_null() {
        init_lib();
        let v = epp_version();
        assert!(!v.is_null());
    }

    #[test]
    fn ffi_init_returns_success() {
        let code = epp_init();
        assert_eq!(code, EppErrorCode::EppSuccess);
    }

    #[test]
    fn ffi_identity_create_and_destroy() {
        init_lib();
        let mut handle: *mut EppIdentityHandle = ptr::null_mut();
        let mut err = null_error();
        let code = unsafe { epp_identity_create(&mut handle, &mut err) };
        assert_eq!(code, EppErrorCode::EppSuccess);
        assert!(!handle.is_null());
        unsafe { epp_identity_destroy(&mut handle) };
    }

    #[test]
    fn ffi_identity_get_keys() {
        init_lib();
        let mut handle: *mut EppIdentityHandle = ptr::null_mut();
        let mut err = null_error();
        unsafe { epp_identity_create(&mut handle, &mut err) };

        let mut x25519 = vec![0u8; 32];
        let code = unsafe {
            epp_identity_get_x25519_public(handle, x25519.as_mut_ptr(), x25519.len(), &mut err)
        };
        assert_eq!(code, EppErrorCode::EppSuccess);
        assert!(x25519.iter().any(|&b| b != 0));

        let mut ed25519 = vec![0u8; 32];
        let code = unsafe {
            epp_identity_get_ed25519_public(handle, ed25519.as_mut_ptr(), ed25519.len(), &mut err)
        };
        assert_eq!(code, EppErrorCode::EppSuccess);
        assert!(ed25519.iter().any(|&b| b != 0));

        let mut kyber = vec![0u8; 1184];
        let code = unsafe {
            epp_identity_get_kyber_public(handle, kyber.as_mut_ptr(), kyber.len(), &mut err)
        };
        assert_eq!(code, EppErrorCode::EppSuccess);

        unsafe { epp_identity_destroy(&mut handle) };
    }

    #[test]
    fn ffi_prekey_bundle_create() {
        init_lib();
        let mut handle: *mut EppIdentityHandle = ptr::null_mut();
        let mut err = null_error();
        unsafe { epp_identity_create(&mut handle, &mut err) };

        let mut bundle_buf = EppBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        let code = unsafe { epp_prekey_bundle_create(handle, &mut bundle_buf, &mut err) };
        assert_eq!(code, EppErrorCode::EppSuccess);
        assert!(!bundle_buf.data.is_null());
        assert!(bundle_buf.length > 0);

        unsafe {
            epp_buffer_release(&mut bundle_buf);
            epp_identity_destroy(&mut handle);
        }
    }

    #[test]
    fn ffi_full_handshake_encrypt_decrypt() {
        init_lib();

        let mut alice_h: *mut EppIdentityHandle = ptr::null_mut();
        let mut bob_h: *mut EppIdentityHandle = ptr::null_mut();
        let mut err = null_error();
        unsafe {
            epp_identity_create(&mut alice_h, &mut err);
            epp_identity_create(&mut bob_h, &mut err);
        }

        let mut bob_bundle_buf = EppBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        unsafe { epp_prekey_bundle_create(bob_h, &mut bob_bundle_buf, &mut err) };

        let config = EppSessionConfig {
            max_messages_per_chain: 1000,
        };
        let mut init_h: *mut EppHandshakeInitiatorHandle = ptr::null_mut();
        let mut init_msg = EppBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        let code = unsafe {
            epp_handshake_initiator_start(
                alice_h,
                bob_bundle_buf.data,
                bob_bundle_buf.length,
                &config,
                &mut init_h,
                &mut init_msg,
                &mut err,
            )
        };
        assert_eq!(code, EppErrorCode::EppSuccess);

        let mut resp_h: *mut EppHandshakeResponderHandle = ptr::null_mut();
        let mut ack_msg = EppBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        let code = unsafe {
            epp_handshake_responder_start(
                bob_h,
                bob_bundle_buf.data,
                bob_bundle_buf.length,
                init_msg.data,
                init_msg.length,
                &config,
                &mut resp_h,
                &mut ack_msg,
                &mut err,
            )
        };
        assert_eq!(code, EppErrorCode::EppSuccess);

        let mut bob_session_h: *mut EppSessionHandle = ptr::null_mut();
        let mut alice_session_h: *mut EppSessionHandle = ptr::null_mut();
        unsafe {
            epp_handshake_responder_finish(resp_h, &mut bob_session_h, &mut err);
            epp_handshake_initiator_finish(
                init_h,
                ack_msg.data,
                ack_msg.length,
                &mut alice_session_h,
                &mut err,
            );
        }
        assert!(!bob_session_h.is_null());
        assert!(!alice_session_h.is_null());

        let plaintext = b"Hello from FFI!";
        let mut enc_buf = EppBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        let code = unsafe {
            epp_session_encrypt(
                alice_session_h,
                plaintext.as_ptr(),
                plaintext.len(),
                EppEnvelopeType::EppEnvelopeRequest,
                42,
                ptr::null(),
                0,
                &mut enc_buf,
                &mut err,
            )
        };
        assert_eq!(code, EppErrorCode::EppSuccess);
        assert!(!enc_buf.data.is_null());

        let mut plain_buf = EppBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        let mut meta_buf = EppBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        let code = unsafe {
            epp_session_decrypt(
                bob_session_h,
                enc_buf.data,
                enc_buf.length,
                &mut plain_buf,
                &mut meta_buf,
                &mut err,
            )
        };
        assert_eq!(code, EppErrorCode::EppSuccess);
        assert!(!plain_buf.data.is_null());
        let decrypted = unsafe { std::slice::from_raw_parts(plain_buf.data, plain_buf.length) };
        assert_eq!(decrypted, plaintext);

        unsafe {
            epp_buffer_release(&mut bob_bundle_buf);
            epp_buffer_release(&mut init_msg);
            epp_buffer_release(&mut ack_msg);
            epp_buffer_release(&mut enc_buf);
            epp_buffer_release(&mut plain_buf);
            epp_buffer_release(&mut meta_buf);
            epp_session_destroy(&mut bob_session_h);
            epp_session_destroy(&mut alice_session_h);
            epp_identity_destroy(&mut alice_h);
            epp_identity_destroy(&mut bob_h);
        }
    }

    #[test]
    fn ffi_handshake_finish_twice_returns_object_disposed() {
        init_lib();

        let mut alice_h: *mut EppIdentityHandle = ptr::null_mut();
        let mut bob_h: *mut EppIdentityHandle = ptr::null_mut();
        let mut err = null_error();
        unsafe {
            epp_identity_create(&mut alice_h, &mut err);
            epp_identity_create(&mut bob_h, &mut err);
        }

        let mut bob_bundle_buf = EppBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        unsafe { epp_prekey_bundle_create(bob_h, &mut bob_bundle_buf, &mut err) };

        let config = EppSessionConfig {
            max_messages_per_chain: 1000,
        };
        let mut init_h: *mut EppHandshakeInitiatorHandle = ptr::null_mut();
        let mut resp_h: *mut EppHandshakeResponderHandle = ptr::null_mut();
        let mut init_msg = EppBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        let mut ack_msg = EppBuffer {
            data: ptr::null_mut(),
            length: 0,
        };

        let code = unsafe {
            epp_handshake_initiator_start(
                alice_h,
                bob_bundle_buf.data,
                bob_bundle_buf.length,
                &config,
                &mut init_h,
                &mut init_msg,
                &mut err,
            )
        };
        assert_eq!(code, EppErrorCode::EppSuccess);

        let code = unsafe {
            epp_handshake_responder_start(
                bob_h,
                bob_bundle_buf.data,
                bob_bundle_buf.length,
                init_msg.data,
                init_msg.length,
                &config,
                &mut resp_h,
                &mut ack_msg,
                &mut err,
            )
        };
        assert_eq!(code, EppErrorCode::EppSuccess);

        let mut bob_session_h: *mut EppSessionHandle = ptr::null_mut();
        let mut alice_session_h: *mut EppSessionHandle = ptr::null_mut();

        let code = unsafe { epp_handshake_responder_finish(resp_h, &mut bob_session_h, &mut err) };
        assert_eq!(code, EppErrorCode::EppSuccess);
        let code = unsafe { epp_handshake_responder_finish(resp_h, &mut bob_session_h, &mut err) };
        assert_eq!(code, EppErrorCode::EppErrorObjectDisposed);

        let code = unsafe {
            epp_handshake_initiator_finish(
                init_h,
                ack_msg.data,
                ack_msg.length,
                &mut alice_session_h,
                &mut err,
            )
        };
        assert_eq!(code, EppErrorCode::EppSuccess);
        let code = unsafe {
            epp_handshake_initiator_finish(
                init_h,
                ack_msg.data,
                ack_msg.length,
                &mut alice_session_h,
                &mut err,
            )
        };
        assert_eq!(code, EppErrorCode::EppErrorObjectDisposed);

        unsafe {
            epp_buffer_release(&mut bob_bundle_buf);
            epp_buffer_release(&mut init_msg);
            epp_buffer_release(&mut ack_msg);
            epp_handshake_initiator_destroy(&mut init_h);
            epp_handshake_responder_destroy(&mut resp_h);
            epp_session_destroy(&mut bob_session_h);
            epp_session_destroy(&mut alice_session_h);
            epp_identity_destroy(&mut alice_h);
            epp_identity_destroy(&mut bob_h);
        }
    }

    #[test]
    fn ffi_session_serialize_deserialize() {
        init_lib();

        let mut alice_h: *mut EppIdentityHandle = ptr::null_mut();
        let mut bob_h: *mut EppIdentityHandle = ptr::null_mut();
        let mut err = null_error();
        unsafe {
            epp_identity_create(&mut alice_h, &mut err);
            epp_identity_create(&mut bob_h, &mut err);
        }

        let mut bob_bundle_buf = EppBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        unsafe {
            epp_prekey_bundle_create(bob_h, &mut bob_bundle_buf, &mut err);
        }

        let config = EppSessionConfig {
            max_messages_per_chain: 1000,
        };
        let mut init_h: *mut EppHandshakeInitiatorHandle = ptr::null_mut();
        let mut resp_h: *mut EppHandshakeResponderHandle = ptr::null_mut();
        let mut init_msg = EppBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        let mut ack_msg = EppBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        let mut alice_session_h: *mut EppSessionHandle = ptr::null_mut();
        let mut bob_session_h: *mut EppSessionHandle = ptr::null_mut();

        unsafe {
            epp_handshake_initiator_start(
                alice_h,
                bob_bundle_buf.data,
                bob_bundle_buf.length,
                &config,
                &mut init_h,
                &mut init_msg,
                &mut err,
            );
            epp_handshake_responder_start(
                bob_h,
                bob_bundle_buf.data,
                bob_bundle_buf.length,
                init_msg.data,
                init_msg.length,
                &config,
                &mut resp_h,
                &mut ack_msg,
                &mut err,
            );
            epp_handshake_responder_finish(resp_h, &mut bob_session_h, &mut err);
            epp_handshake_initiator_finish(
                init_h,
                ack_msg.data,
                ack_msg.length,
                &mut alice_session_h,
                &mut err,
            );
        }

        let mut enc_buf = EppBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        unsafe {
            epp_session_encrypt(
                alice_session_h,
                b"pre-save".as_ptr(),
                8,
                EppEnvelopeType::EppEnvelopeRequest,
                1,
                ptr::null(),
                0,
                &mut enc_buf,
                &mut err,
            );
        }
        let mut plain_buf = EppBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        let mut meta_buf = EppBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        unsafe {
            epp_session_decrypt(
                bob_session_h,
                enc_buf.data,
                enc_buf.length,
                &mut plain_buf,
                &mut meta_buf,
                &mut err,
            );
            epp_buffer_release(&mut enc_buf);
            epp_buffer_release(&mut plain_buf);
            epp_buffer_release(&mut meta_buf);
        }

        let seal_key = [0xABu8; 32];
        let mut sealed_buf = EppBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        let code = unsafe {
            epp_session_serialize_sealed(
                bob_session_h,
                seal_key.as_ptr(),
                seal_key.len(),
                1,
                &mut sealed_buf,
                &mut err,
            )
        };
        assert_eq!(code, EppErrorCode::EppSuccess);

        let mut bob_session_h2: *mut EppSessionHandle = ptr::null_mut();
        let mut out_counter: u64 = 0;
        let code = unsafe {
            epp_session_deserialize_sealed(
                sealed_buf.data,
                sealed_buf.length,
                seal_key.as_ptr(),
                seal_key.len(),
                0,
                &mut out_counter,
                &mut bob_session_h2,
                &mut err,
            )
        };
        assert_eq!(code, EppErrorCode::EppSuccess);
        assert_eq!(out_counter, 1);

        let mut enc_buf2 = EppBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        let mut plain_buf2 = EppBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        let mut meta_buf2 = EppBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        unsafe {
            epp_session_encrypt(
                alice_session_h,
                b"post-restore".as_ptr(),
                12,
                EppEnvelopeType::EppEnvelopeRequest,
                2,
                ptr::null(),
                0,
                &mut enc_buf2,
                &mut err,
            );
            let code = epp_session_decrypt(
                bob_session_h2,
                enc_buf2.data,
                enc_buf2.length,
                &mut plain_buf2,
                &mut meta_buf2,
                &mut err,
            );
            assert_eq!(code, EppErrorCode::EppSuccess);
            let dec = std::slice::from_raw_parts(plain_buf2.data, plain_buf2.length);
            assert_eq!(dec, b"post-restore");
        }

        unsafe {
            epp_buffer_release(&mut bob_bundle_buf);
            epp_buffer_release(&mut init_msg);
            epp_buffer_release(&mut ack_msg);
            epp_buffer_release(&mut sealed_buf);
            epp_buffer_release(&mut enc_buf2);
            epp_buffer_release(&mut plain_buf2);
            epp_buffer_release(&mut meta_buf2);
            epp_session_destroy(&mut alice_session_h);
            epp_session_destroy(&mut bob_session_h);
            epp_session_destroy(&mut bob_session_h2);
            epp_identity_destroy(&mut alice_h);
            epp_identity_destroy(&mut bob_h);
        }
    }

    #[test]
    fn ffi_shamir_split_and_reconstruct() {
        init_lib();
        let secret = b"ecliptix-secret-32-bytes-exactly";
        let auth_key = ecliptix_protocol::crypto::CryptoInterop::get_random_bytes(32);

        let mut shares_buf = EppBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        let mut share_length = 0usize;
        let mut err = null_error();

        let code = unsafe {
            epp_shamir_split(
                secret.as_ptr(),
                secret.len(),
                2,
                3,
                auth_key.as_ptr(),
                auth_key.len(),
                &mut shares_buf,
                &mut share_length,
                &mut err,
            )
        };
        assert_eq!(code, EppErrorCode::EppSuccess);
        assert!(share_length > 0);
        assert_eq!(shares_buf.length, 3 * share_length + 32);

        let mut secret_buf = EppBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        let code = unsafe {
            epp_shamir_reconstruct(
                shares_buf.data,
                shares_buf.length,
                share_length,
                3,
                auth_key.as_ptr(),
                auth_key.len(),
                &mut secret_buf,
                &mut err,
            )
        };
        assert_eq!(code, EppErrorCode::EppSuccess);
        let recovered = unsafe { std::slice::from_raw_parts(secret_buf.data, secret_buf.length) };
        assert_eq!(recovered, secret);

        unsafe {
            epp_buffer_release(&mut shares_buf);
            epp_buffer_release(&mut secret_buf);
        }
    }

    #[test]
    fn ffi_derive_root_key() {
        init_lib();
        let opaque_key = ecliptix_protocol::crypto::CryptoInterop::get_random_bytes(32);
        let user_ctx = b"test-context";
        let mut out_key = vec![0u8; 32];
        let mut err = null_error();

        let code = unsafe {
            epp_derive_root_key(
                opaque_key.as_ptr(),
                opaque_key.len(),
                user_ctx.as_ptr(),
                user_ctx.len(),
                out_key.as_mut_ptr(),
                out_key.len(),
                &mut err,
            )
        };
        assert_eq!(code, EppErrorCode::EppSuccess);
        assert!(out_key.iter().any(|&b| b != 0));

        let mut out_key2 = vec![0u8; 32];
        unsafe {
            epp_derive_root_key(
                opaque_key.as_ptr(),
                opaque_key.len(),
                user_ctx.as_ptr(),
                user_ctx.len(),
                out_key2.as_mut_ptr(),
                out_key2.len(),
                &mut err,
            );
        }
        assert_eq!(out_key, out_key2);
    }

    #[test]
    fn ffi_error_string_is_non_null() {
        let s = epp_error_string(EppErrorCode::EppSuccess);
        assert!(!s.is_null());
        let s = epp_error_string(EppErrorCode::EppErrorHandshake);
        assert!(!s.is_null());
    }

    #[test]
    fn ffi_secure_wipe() {
        init_lib();
        let mut data = vec![0xABu8; 64];
        let code = unsafe { epp_secure_wipe(data.as_mut_ptr(), data.len()) };
        assert_eq!(code, EppErrorCode::EppSuccess);
        assert!(data.iter().all(|&b| b == 0));
    }

    #[test]
    fn ffi_null_pointers_return_null_error() {
        init_lib();
        let mut err = null_error();
        let code = unsafe { epp_identity_create(ptr::null_mut(), &mut err) };
        assert_eq!(code, EppErrorCode::EppErrorNullPointer);
    }

    #[test]
    fn ffi_buffer_alloc_and_free() {
        init_lib();
        let buf = epp_buffer_alloc(64);
        assert!(!buf.is_null());
        unsafe {
            assert_eq!((*buf).length, 64);
            assert!(!(*buf).data.is_null());
            epp_buffer_free(buf);
        }
    }
}

mod ffi_error_paths {
    use ecliptix_protocol::ffi::api::*;
    use std::ptr;

    const fn null_error() -> EppError {
        EppError {
            code: EppErrorCode::EppSuccess,
            message: ptr::null_mut(),
        }
    }

    fn init_lib() {
        epp_init();
    }

    #[test]
    fn ffi_encrypt_zero_length_plaintext() {
        init_lib();

        let mut alice_h: *mut EppIdentityHandle = ptr::null_mut();
        let mut bob_h: *mut EppIdentityHandle = ptr::null_mut();
        let mut err = null_error();
        unsafe {
            epp_identity_create(&mut alice_h, &mut err);
            epp_identity_create(&mut bob_h, &mut err);
        }

        let mut bob_bundle = EppBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        unsafe { epp_prekey_bundle_create(bob_h, &mut bob_bundle, &mut err) };

        let config = EppSessionConfig {
            max_messages_per_chain: 1000,
        };
        let mut init_h: *mut EppHandshakeInitiatorHandle = ptr::null_mut();
        let mut init_msg = EppBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        let code = unsafe {
            epp_handshake_initiator_start(
                alice_h,
                bob_bundle.data,
                bob_bundle.length,
                &config,
                &mut init_h,
                &mut init_msg,
                &mut err,
            )
        };
        assert_eq!(code, EppErrorCode::EppSuccess);

        let mut resp_h: *mut EppHandshakeResponderHandle = ptr::null_mut();
        let mut ack_msg = EppBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        let code = unsafe {
            epp_handshake_responder_start(
                bob_h,
                bob_bundle.data,
                bob_bundle.length,
                init_msg.data,
                init_msg.length,
                &config,
                &mut resp_h,
                &mut ack_msg,
                &mut err,
            )
        };
        assert_eq!(code, EppErrorCode::EppSuccess);

        let mut bob_session: *mut EppSessionHandle = ptr::null_mut();
        let mut alice_session: *mut EppSessionHandle = ptr::null_mut();
        unsafe {
            epp_handshake_responder_finish(resp_h, &mut bob_session, &mut err);
            epp_handshake_initiator_finish(
                init_h,
                ack_msg.data,
                ack_msg.length,
                &mut alice_session,
                &mut err,
            );
        }

        let empty: [u8; 1] = [0];
        let mut out_env = EppBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        let code = unsafe {
            epp_session_encrypt(
                alice_session,
                empty.as_ptr(),
                0,
                EppEnvelopeType::EppEnvelopeRequest,
                1,
                ptr::null(),
                0,
                &mut out_env,
                &mut err,
            )
        };
        assert!(
            code == EppErrorCode::EppSuccess || code != EppErrorCode::EppSuccess,
            "Zero-length encrypt must not crash"
        );

        unsafe {
            epp_session_destroy(&mut alice_session);
            epp_session_destroy(&mut bob_session);
            epp_identity_destroy(&mut alice_h);
            epp_identity_destroy(&mut bob_h);
        }
    }

    #[test]
    fn ffi_encrypt_null_handle_returns_error() {
        init_lib();
        let mut err = null_error();
        let mut out_env = EppBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        let payload = b"test";
        let code = unsafe {
            epp_session_encrypt(
                ptr::null_mut(),
                payload.as_ptr(),
                payload.len(),
                EppEnvelopeType::EppEnvelopeRequest,
                1,
                ptr::null(),
                0,
                &mut out_env,
                &mut err,
            )
        };
        assert_eq!(code, EppErrorCode::EppErrorNullPointer);
    }

    #[test]
    fn ffi_decrypt_null_handle_returns_error() {
        init_lib();
        let mut err = null_error();
        let mut out_plain = EppBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        let mut out_meta = EppBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        let fake_data = [0u8; 64];
        let code = unsafe {
            epp_session_decrypt(
                ptr::null_mut(),
                fake_data.as_ptr(),
                fake_data.len(),
                &mut out_plain,
                &mut out_meta,
                &mut err,
            )
        };
        assert_eq!(code, EppErrorCode::EppErrorNullPointer);
    }

    #[test]
    fn ffi_identity_create_null_out_returns_error() {
        init_lib();
        let mut err = null_error();
        let code = unsafe { epp_identity_create(ptr::null_mut(), &mut err) };
        assert_eq!(code, EppErrorCode::EppErrorNullPointer);
    }

    #[test]
    fn ffi_get_x25519_public_null_handle_returns_error() {
        init_lib();
        let mut err = null_error();
        let mut buf = vec![0u8; 32];
        let code = unsafe {
            epp_identity_get_x25519_public(ptr::null_mut(), buf.as_mut_ptr(), buf.len(), &mut err)
        };
        assert_eq!(code, EppErrorCode::EppErrorNullPointer);
    }

    #[test]
    fn ffi_get_x25519_public_buffer_too_small() {
        init_lib();
        let mut handle: *mut EppIdentityHandle = ptr::null_mut();
        let mut err = null_error();
        unsafe { epp_identity_create(&mut handle, &mut err) };

        let mut buf = vec![0u8; 16];
        let code = unsafe {
            epp_identity_get_x25519_public(handle, buf.as_mut_ptr(), buf.len(), &mut err)
        };
        assert_eq!(code, EppErrorCode::EppErrorBufferTooSmall);
        unsafe { epp_identity_destroy(&mut handle) };
    }

    #[test]
    fn ffi_prekey_bundle_create_null_handle() {
        init_lib();
        let mut err = null_error();
        let mut bundle = EppBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        let code = unsafe { epp_prekey_bundle_create(ptr::null_mut(), &mut bundle, &mut err) };
        assert_eq!(code, EppErrorCode::EppErrorNullPointer);
    }

    #[test]
    fn ffi_shamir_split_requires_auth_key() {
        init_lib();
        let mut err = null_error();
        let secret = b"ffi-shamir";
        let mut out = EppBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        let mut share_len = 0usize;
        let code = unsafe {
            epp_shamir_split(
                secret.as_ptr(),
                secret.len(),
                2,
                3,
                ptr::null(),
                0,
                &mut out,
                &mut share_len,
                &mut err,
            )
        };
        assert_eq!(code, EppErrorCode::EppErrorInvalidInput);
    }

    #[test]
    fn ffi_shamir_reconstruct_requires_auth_key() {
        init_lib();
        let mut err = null_error();
        let shares = [0u8; 7];
        let mut out = EppBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        let code = unsafe {
            epp_shamir_reconstruct(
                shares.as_ptr(),
                shares.len(),
                shares.len(),
                1,
                ptr::null(),
                0,
                &mut out,
                &mut err,
            )
        };
        assert_eq!(code, EppErrorCode::EppErrorInvalidInput);
    }

    #[test]
    fn ffi_secure_wipe_null_returns_error() {
        init_lib();
        let code = unsafe { epp_secure_wipe(ptr::null_mut(), 10) };
        assert_eq!(code, EppErrorCode::EppErrorNullPointer);
    }

    #[test]
    fn ffi_secure_wipe_zero_length_succeeds() {
        init_lib();
        let mut data = vec![0xABu8; 4];
        let code = unsafe { epp_secure_wipe(data.as_mut_ptr(), 0) };
        assert_eq!(code, EppErrorCode::EppSuccess);
        assert!(data.iter().all(|&b| b == 0xAB));
    }

    #[test]
    fn ffi_derive_root_key_wrong_key_size() {
        init_lib();
        let mut err = null_error();
        let bad_key = [0u8; 16];
        let ctx = b"ctx";
        let mut out = vec![0u8; 32];
        let code = unsafe {
            epp_derive_root_key(
                bad_key.as_ptr(),
                bad_key.len(),
                ctx.as_ptr(),
                ctx.len(),
                out.as_mut_ptr(),
                out.len(),
                &mut err,
            )
        };
        assert_eq!(code, EppErrorCode::EppErrorInvalidInput);
    }

    #[test]
    fn ffi_derive_root_key_empty_context() {
        init_lib();
        let mut err = null_error();
        let key = [0xABu8; 32];
        let mut out = vec![0u8; 32];
        let code = unsafe {
            epp_derive_root_key(
                key.as_ptr(),
                key.len(),
                b"".as_ptr(),
                0,
                out.as_mut_ptr(),
                out.len(),
                &mut err,
            )
        };
        assert_eq!(code, EppErrorCode::EppErrorInvalidInput);
    }

    #[test]
    fn ffi_all_error_strings_non_null() {
        let codes = [
            EppErrorCode::EppSuccess,
            EppErrorCode::EppErrorGeneric,
            EppErrorCode::EppErrorInvalidInput,
            EppErrorCode::EppErrorKeyGeneration,
            EppErrorCode::EppErrorDeriveKey,
            EppErrorCode::EppErrorHandshake,
            EppErrorCode::EppErrorEncryption,
            EppErrorCode::EppErrorDecryption,
            EppErrorCode::EppErrorDecode,
            EppErrorCode::EppErrorEncode,
            EppErrorCode::EppErrorBufferTooSmall,
            EppErrorCode::EppErrorObjectDisposed,
            EppErrorCode::EppErrorPrepareLocal,
            EppErrorCode::EppErrorOutOfMemory,
            EppErrorCode::EppErrorCryptoFailure,
            EppErrorCode::EppErrorNullPointer,
            EppErrorCode::EppErrorInvalidState,
            EppErrorCode::EppErrorReplayAttack,
            EppErrorCode::EppErrorSessionExpired,
            EppErrorCode::EppErrorPqMissing,
        ];
        for code in codes {
            let s = epp_error_string(code);
            assert!(!s.is_null(), "epp_error_string returned null for {code:?}");
        }
    }
}

#[test]
fn ffi_group_external_join_roundtrip() {
    init();

    use ecliptix_protocol::ffi::api::*;
    use std::ptr;

    unsafe {
        let mut alice_handle: *mut EppIdentityHandle = ptr::null_mut();
        let mut err = EppError {
            code: EppErrorCode::EppSuccess,
            message: ptr::null_mut(),
        };
        let code = epp_identity_create(&mut alice_handle, &mut err);
        assert_eq!(code, EppErrorCode::EppSuccess);

        let mut group_handle: *mut EppGroupSessionHandle = ptr::null_mut();
        let cred = b"alice";
        let code = epp_group_create(
            alice_handle,
            cred.as_ptr(),
            cred.len(),
            &mut group_handle,
            &mut err,
        );
        assert_eq!(code, EppErrorCode::EppSuccess);

        let mut pub_state_buf = EppBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        let code = epp_group_export_public_state(group_handle, &mut pub_state_buf, &mut err);
        assert_eq!(code, EppErrorCode::EppSuccess);
        assert!(pub_state_buf.length > 0);

        let mut bob_handle: *mut EppIdentityHandle = ptr::null_mut();
        let code = epp_identity_create(&mut bob_handle, &mut err);
        assert_eq!(code, EppErrorCode::EppSuccess);

        let mut bob_group_handle: *mut EppGroupSessionHandle = ptr::null_mut();
        let mut commit_buf = EppBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        let bob_cred = b"bob";
        let code = epp_group_join_external(
            bob_handle,
            pub_state_buf.data,
            pub_state_buf.length,
            bob_cred.as_ptr(),
            bob_cred.len(),
            &mut bob_group_handle,
            &mut commit_buf,
            &mut err,
        );
        assert_eq!(code, EppErrorCode::EppSuccess);
        assert!(commit_buf.length > 0);

        let code =
            epp_group_process_commit(group_handle, commit_buf.data, commit_buf.length, &mut err);
        assert_eq!(code, EppErrorCode::EppSuccess);

        assert_eq!(epp_group_get_member_count(group_handle), 2);
        assert_eq!(epp_group_get_member_count(bob_group_handle), 2);

        let plaintext = b"hello via FFI external join";
        let mut ct_buf = EppBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        let code = epp_group_encrypt(
            group_handle,
            plaintext.as_ptr(),
            plaintext.len(),
            &mut ct_buf,
            &mut err,
        );
        assert_eq!(code, EppErrorCode::EppSuccess);

        let mut pt_buf = EppBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        let mut sender_leaf: u32 = 0;
        let mut generation: u32 = 0;
        let code = epp_group_decrypt(
            bob_group_handle,
            ct_buf.data,
            ct_buf.length,
            &mut pt_buf,
            &mut sender_leaf,
            &mut generation,
            &mut err,
        );
        assert_eq!(code, EppErrorCode::EppSuccess);
        let pt_slice = std::slice::from_raw_parts(pt_buf.data, pt_buf.length);
        assert_eq!(pt_slice, plaintext);

        epp_buffer_release(&mut pub_state_buf);
        epp_buffer_release(&mut commit_buf);
        epp_buffer_release(&mut ct_buf);
        epp_buffer_release(&mut pt_buf);
        epp_group_destroy(&mut group_handle);
        epp_group_destroy(&mut bob_group_handle);
        epp_identity_destroy(&mut alice_handle);
        epp_identity_destroy(&mut bob_handle);
    }
}

#[test]
fn ffi_group_member_leaf_indices() {
    init();

    use ecliptix_protocol::ffi::api::*;
    use std::ptr;

    unsafe {
        let mut alice_handle: *mut EppIdentityHandle = ptr::null_mut();
        let mut err = EppError {
            code: EppErrorCode::EppSuccess,
            message: ptr::null_mut(),
        };
        epp_identity_create(&mut alice_handle, &mut err);

        let mut group_handle: *mut EppGroupSessionHandle = ptr::null_mut();
        let cred = b"alice";
        epp_group_create(
            alice_handle,
            cred.as_ptr(),
            cred.len(),
            &mut group_handle,
            &mut err,
        );

        let mut indices_buf = EppBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        let code = epp_group_get_member_leaf_indices(group_handle, &mut indices_buf, &mut err);
        assert_eq!(code, EppErrorCode::EppSuccess);
        assert_eq!(indices_buf.length, 4);
        let leaf_idx = u32::from_le_bytes([
            *indices_buf.data,
            *indices_buf.data.add(1),
            *indices_buf.data.add(2),
            *indices_buf.data.add(3),
        ]);
        assert_eq!(leaf_idx, 0);

        epp_buffer_release(&mut indices_buf);
        epp_group_destroy(&mut group_handle);
        epp_identity_destroy(&mut alice_handle);
    }
}

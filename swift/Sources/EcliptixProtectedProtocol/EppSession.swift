// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

import Foundation

/// Represents a 1:1 encrypted session in the Ecliptix Protected Protocol.
///
/// A session is created through a handshake between two identities and provides
/// symmetric encryption/decryption of messages with forward secrecy via the
/// Double Ratchet algorithm. Sessions can be serialized for persistent storage
/// and later restored.
public final class EppSession {

    /// The opaque handle to the native session object.
    internal var handle: UnsafeMutableRawPointer?

    /// Creates an `EppSession` from a native handle.
    ///
    /// - Parameter handle: The opaque pointer to the native session.
    internal init(handle: UnsafeMutableRawPointer) {
        self.handle = handle
    }

    deinit {
        if handle != nil {
            native_epp_session_destroy(&handle)
        }
    }

    /// Encrypts plaintext into an encrypted envelope.
    ///
    /// The envelope type, ID, and correlation ID are metadata fields that are
    /// authenticated (included in the AAD) but not encrypted.
    ///
    /// - Parameters:
    ///   - plaintext: The data to encrypt.
    ///   - envelopeType: The type of envelope (default: `EPP_ENVELOPE_REQUEST`).
    ///   - envelopeId: An optional envelope identifier (default: 0).
    ///   - correlationId: An optional correlation string for request/response matching (default: empty).
    /// - Returns: The encrypted envelope as `Data`.
    /// - Throws: `EppError.objectDisposed` if the session has been destroyed,
    ///   or another `EppError` if encryption fails.
    public func encrypt(
        plaintext: Data,
        envelopeType: UInt32 = EPP_ENVELOPE_REQUEST,
        envelopeId: UInt32 = 0,
        correlationId: String = ""
    ) throws -> Data {
        guard handle != nil else {
            throw EppError.objectDisposed
        }
        var outBuffer = NativeEppBuffer(data: nil, length: 0)
        var outError = NativeEppError(code: 0, message: nil)
        let result = plaintext.withUnsafeBytes { plaintextBytes in
            correlationId.withCString { correlationPtr in
                native_epp_session_encrypt(
                    handle,
                    plaintextBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    plaintext.count,
                    envelopeType,
                    envelopeId,
                    correlationPtr,
                    correlationId.utf8.count,
                    &outBuffer,
                    &outError
                )
            }
        }
        defer {
            if outBuffer.data != nil { native_epp_buffer_release(&outBuffer) }
            native_epp_error_free(&outError)
        }
        guard result == EPP_SUCCESS else {
            throw EppError.from(code: result, nativeError: outError)
        }
        guard let data = dataFromBuffer(outBuffer) else {
            throw EppError.bufferTooSmall
        }
        return data
    }

    /// Decrypts an encrypted envelope and returns the plaintext.
    ///
    /// - Parameter encryptedEnvelope: The encrypted envelope data to decrypt.
    /// - Returns: The decrypted plaintext as `Data`.
    /// - Throws: `EppError.objectDisposed` if the session has been destroyed,
    ///   or another `EppError` if decryption fails (e.g., replay attack, expired session).
    public func decrypt(encryptedEnvelope: Data) throws -> Data {
        guard handle != nil else {
            throw EppError.objectDisposed
        }
        var outPlaintext = NativeEppBuffer(data: nil, length: 0)
        var outMetadata = NativeEppBuffer(data: nil, length: 0)
        var outError = NativeEppError(code: 0, message: nil)
        let result = encryptedEnvelope.withUnsafeBytes { envelopeBytes in
            native_epp_session_decrypt(
                handle,
                envelopeBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                encryptedEnvelope.count,
                &outPlaintext,
                &outMetadata,
                &outError
            )
        }
        defer {
            if outPlaintext.data != nil { native_epp_buffer_release(&outPlaintext) }
            if outMetadata.data != nil { native_epp_buffer_release(&outMetadata) }
            native_epp_error_free(&outError)
        }
        guard result == EPP_SUCCESS else {
            throw EppError.from(code: result, nativeError: outError)
        }
        guard let data = dataFromBuffer(outPlaintext) else {
            throw EppError.bufferTooSmall
        }
        return data
    }

    /// Serializes the session state, encrypted under the given key, for persistent storage.
    ///
    /// The external counter is a monotonic value that the caller must persist alongside
    /// the sealed state to prevent rollback attacks during deserialization.
    ///
    /// - Parameters:
    ///   - key: The encryption key used to seal the state.
    ///   - externalCounter: A monotonically increasing counter value.
    /// - Returns: The sealed session state as `Data`.
    /// - Throws: `EppError.objectDisposed` if the session has been destroyed,
    ///   or another `EppError` if serialization fails.
    public func serialize(key: Data, externalCounter: UInt64) throws -> Data {
        guard handle != nil else {
            throw EppError.objectDisposed
        }
        var outBuffer = NativeEppBuffer(data: nil, length: 0)
        var outError = NativeEppError(code: 0, message: nil)
        let result = key.withUnsafeBytes { keyBytes in
            native_epp_session_serialize_sealed(
                handle,
                keyBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                key.count,
                externalCounter,
                &outBuffer,
                &outError
            )
        }
        defer {
            if outBuffer.data != nil { native_epp_buffer_release(&outBuffer) }
            native_epp_error_free(&outError)
        }
        guard result == EPP_SUCCESS else {
            throw EppError.from(code: result, nativeError: outError)
        }
        guard let data = dataFromBuffer(outBuffer) else {
            throw EppError.bufferTooSmall
        }
        return data
    }

    /// Deserializes a previously sealed session state.
    ///
    /// The `minExternalCounter` parameter prevents rollback attacks by rejecting
    /// sealed states whose counter is below this value.
    ///
    /// - Parameters:
    ///   - sealedState: The sealed session state data.
    ///   - key: The encryption key used to unseal the state.
    ///   - minExternalCounter: The minimum acceptable external counter value.
    /// - Returns: A tuple containing the restored `EppSession` and its external counter.
    /// - Throws: `EppError` if deserialization or authentication fails.
    public static func deserialize(
        sealedState: Data,
        key: Data,
        minExternalCounter: UInt64
    ) throws -> (session: EppSession, externalCounter: UInt64) {
        var outHandle: UnsafeMutableRawPointer?
        var outCounter: UInt64 = 0
        var outError = NativeEppError(code: 0, message: nil)
        let result = sealedState.withUnsafeBytes { stateBytes in
            key.withUnsafeBytes { keyBytes in
                native_epp_session_deserialize_sealed(
                    stateBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    sealedState.count,
                    keyBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    key.count,
                    minExternalCounter,
                    &outCounter,
                    &outHandle,
                    &outError
                )
            }
        }
        defer { native_epp_error_free(&outError) }
        guard result == EPP_SUCCESS, let handle = outHandle else {
            throw EppError.from(code: result, nativeError: outError)
        }
        return (EppSession(handle: handle), outCounter)
    }

    /// Returns the number of nonce values remaining before the session must be rekeyed.
    ///
    /// When this value reaches zero, no more messages can be encrypted and the session
    /// must be re-established via a new handshake.
    ///
    /// - Returns: The number of remaining nonce values.
    /// - Throws: `EppError.objectDisposed` if the session has been destroyed,
    ///   or another `EppError` if the query fails.
    public func nonceRemaining() throws -> UInt64 {
        guard handle != nil else {
            throw EppError.objectDisposed
        }
        var remaining: UInt64 = 0
        var outError = NativeEppError(code: 0, message: nil)
        let result = native_epp_session_nonce_remaining(handle, &remaining, &outError)
        defer { native_epp_error_free(&outError) }
        guard result == EPP_SUCCESS else {
            throw EppError.from(code: result, nativeError: outError)
        }
        return remaining
    }
}

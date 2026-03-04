#pragma once
#include "epp_export.h"

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define EPP_API_VERSION_MAJOR 1
#define EPP_API_VERSION_MINOR 0
#define EPP_API_VERSION_PATCH 0

#define EPP_DEFAULT_ONE_TIME_KEY_COUNT 100
#define EPP_LIBRARY_VERSION "1.0.0"

typedef enum {
    EPP_SUCCESS = 0,
    EPP_ERROR_GENERIC = 1,
    EPP_ERROR_INVALID_INPUT = 2,
    EPP_ERROR_KEY_GENERATION = 3,
    EPP_ERROR_DERIVE_KEY = 4,
    EPP_ERROR_HANDSHAKE = 5,
    EPP_ERROR_ENCRYPTION = 6,
    EPP_ERROR_DECRYPTION = 7,
    EPP_ERROR_DECODE = 8,
    EPP_ERROR_ENCODE = 9,
    EPP_ERROR_BUFFER_TOO_SMALL = 10,
    EPP_ERROR_OBJECT_DISPOSED = 11,
    EPP_ERROR_PREPARE_LOCAL = 12,
    EPP_ERROR_OUT_OF_MEMORY = 13,
    EPP_ERROR_CRYPTO_FAILURE = 14,
    EPP_ERROR_NULL_POINTER = 15,
    EPP_ERROR_INVALID_STATE = 16,
    EPP_ERROR_REPLAY_ATTACK = 17,
    EPP_ERROR_SESSION_EXPIRED = 18,
    EPP_ERROR_PQ_MISSING = 19,
    EPP_ERROR_GROUP_PROTOCOL = 20,
    EPP_ERROR_GROUP_MEMBERSHIP = 21,
    EPP_ERROR_TREE_INTEGRITY = 22,
    EPP_ERROR_WELCOME = 23,
    EPP_ERROR_MESSAGE_EXPIRED = 24,
    EPP_ERROR_FRANKING = 25
} EppErrorCode;

typedef struct EppIdentityHandle EppIdentityHandle;
typedef struct EppSessionHandle EppSessionHandle;
typedef struct EppGroupSessionHandle EppGroupSessionHandle;
typedef struct EppKeyPackageSecretsHandle EppKeyPackageSecretsHandle;
#ifndef EPP_SERVER_BUILD
typedef struct EppHandshakeInitiatorHandle EppHandshakeInitiatorHandle;
#endif
typedef struct EppHandshakeResponderHandle EppHandshakeResponderHandle;

typedef struct EppBuffer {
    uint8_t* data;
    size_t length;
} EppBuffer;

typedef enum {
    EPP_ENVELOPE_REQUEST = 0,
    EPP_ENVELOPE_RESPONSE = 1,
    EPP_ENVELOPE_NOTIFICATION = 2,
    EPP_ENVELOPE_HEARTBEAT = 3,
    EPP_ENVELOPE_ERROR_RESPONSE = 4
} EppEnvelopeType;

typedef struct EppError {
    EppErrorCode code;
    char* message;
} EppError;

typedef struct EppSessionConfig {
    uint32_t max_messages_per_chain;
} EppSessionConfig;

EPP_API const char* epp_version(void);
EPP_API EppErrorCode epp_init(void);
EPP_API void epp_shutdown(void);

EPP_API EppErrorCode epp_identity_create(
    EppIdentityHandle** out_handle,
    EppError* out_error);

EPP_API EppErrorCode epp_identity_create_from_seed(
    const uint8_t* seed,
    size_t seed_length,
    EppIdentityHandle** out_handle,
    EppError* out_error);

EPP_API EppErrorCode epp_identity_create_with_context(
    const uint8_t* seed,
    size_t seed_length,
    const char* membership_id,
    size_t membership_id_length,
    EppIdentityHandle** out_handle,
    EppError* out_error);

EPP_API EppErrorCode epp_identity_get_x25519_public(
    const EppIdentityHandle* handle,
    uint8_t* out_key,
    size_t out_key_length,
    EppError* out_error);

EPP_API EppErrorCode epp_identity_get_ed25519_public(
    const EppIdentityHandle* handle,
    uint8_t* out_key,
    size_t out_key_length,
    EppError* out_error);

EPP_API EppErrorCode epp_identity_get_kyber_public(
    const EppIdentityHandle* handle,
    uint8_t* out_key,
    size_t out_key_length,
    EppError* out_error);

EPP_API void epp_identity_destroy(EppIdentityHandle** handle);

EPP_API EppErrorCode epp_prekey_bundle_create(
    const EppIdentityHandle* identity_keys,
    EppBuffer* out_bundle,
    EppError* out_error);

#ifndef EPP_SERVER_BUILD
EPP_API EppErrorCode epp_handshake_initiator_start(
    EppIdentityHandle* identity_keys,
    const uint8_t* peer_prekey_bundle,
    size_t peer_prekey_bundle_length,
    const EppSessionConfig* config,
    EppHandshakeInitiatorHandle** out_handle,
    EppBuffer* out_handshake_init,
    EppError* out_error);

EPP_API EppErrorCode epp_handshake_initiator_finish(
    EppHandshakeInitiatorHandle* handle,
    const uint8_t* handshake_ack,
    size_t handshake_ack_length,
    EppSessionHandle** out_session,
    EppError* out_error);

EPP_API void epp_handshake_initiator_destroy(EppHandshakeInitiatorHandle** handle);
#endif

EPP_API EppErrorCode epp_handshake_responder_start(
    EppIdentityHandle* identity_keys,
    const uint8_t* local_prekey_bundle,
    size_t local_prekey_bundle_length,
    const uint8_t* handshake_init,
    size_t handshake_init_length,
    const EppSessionConfig* config,
    EppHandshakeResponderHandle** out_handle,
    EppBuffer* out_handshake_ack,
    EppError* out_error);

EPP_API EppErrorCode epp_handshake_responder_finish(
    EppHandshakeResponderHandle* handle,
    EppSessionHandle** out_session,
    EppError* out_error);

EPP_API void epp_handshake_responder_destroy(EppHandshakeResponderHandle** handle);

EPP_API EppErrorCode epp_session_encrypt(
    EppSessionHandle* handle,
    const uint8_t* plaintext,
    size_t plaintext_length,
    EppEnvelopeType envelope_type,
    uint32_t envelope_id,
    const char* correlation_id,
    size_t correlation_id_length,
    EppBuffer* out_encrypted_envelope,
    EppError* out_error);

EPP_API EppErrorCode epp_session_decrypt(
    EppSessionHandle* handle,
    const uint8_t* encrypted_envelope,
    size_t encrypted_envelope_length,
    EppBuffer* out_plaintext,
    EppBuffer* out_metadata,
    EppError* out_error);

EPP_API EppErrorCode epp_session_serialize_sealed(
    EppSessionHandle* handle,
    const uint8_t* key,
    size_t key_length,
    uint64_t external_counter,
    EppBuffer* out_state,
    EppError* out_error);

EPP_API EppErrorCode epp_session_deserialize_sealed(
    const uint8_t* state_bytes,
    size_t state_length,
    const uint8_t* key,
    size_t key_length,
    uint64_t min_external_counter,
    uint64_t* out_external_counter,
    EppSessionHandle** out_handle,
    EppError* out_error);

EPP_API EppErrorCode epp_session_nonce_remaining(
    EppSessionHandle* handle,
    uint64_t* out_remaining,
    EppError* out_error);

EPP_API void epp_session_destroy(EppSessionHandle** handle);

EPP_API EppErrorCode epp_envelope_validate(
    const uint8_t* encrypted_envelope,
    size_t encrypted_envelope_length,
    EppError* out_error);

EPP_API EppErrorCode epp_derive_root_key(
    const uint8_t* opaque_session_key,
    size_t opaque_session_key_length,
    const uint8_t* user_context,
    size_t user_context_length,
    uint8_t* out_root_key,
    size_t out_root_key_length,
    EppError* out_error);

EPP_API EppErrorCode epp_shamir_split(
    const uint8_t* secret,
    size_t secret_length,
    uint8_t threshold,
    uint8_t share_count,
    const uint8_t* auth_key,
    size_t auth_key_length,
    EppBuffer* out_shares,
    size_t* out_share_length,
    EppError* out_error);

EPP_API EppErrorCode epp_shamir_reconstruct(
    const uint8_t* shares,
    size_t shares_length,
    size_t share_length,
    size_t share_count,
    const uint8_t* auth_key,
    size_t auth_key_length,
    EppBuffer* out_secret,
    EppError* out_error);

EPP_API void epp_buffer_release(EppBuffer* buffer);

EPP_API EppBuffer* epp_buffer_alloc(size_t capacity);

EPP_API void epp_buffer_free(EppBuffer* buffer);
EPP_API void epp_error_free(EppError* error);
EPP_API const char* epp_error_string(EppErrorCode code);

EPP_API EppErrorCode epp_secure_wipe(
    uint8_t* data,
    size_t length);

EPP_API EppErrorCode epp_group_generate_key_package(
    EppIdentityHandle* identity_handle,
    const uint8_t* credential,
    size_t credential_length,
    EppBuffer* out_key_package,
    EppKeyPackageSecretsHandle** out_secrets,
    EppError* out_error);

EPP_API void epp_group_key_package_secrets_destroy(
    EppKeyPackageSecretsHandle** handle);

EPP_API EppErrorCode epp_group_create(
    EppIdentityHandle* identity_handle,
    const uint8_t* credential,
    size_t credential_length,
    EppGroupSessionHandle** out_handle,
    EppError* out_error);

EPP_API EppErrorCode epp_group_create_shielded(
    EppIdentityHandle* identity_handle,
    const uint8_t* credential,
    size_t credential_length,
    EppGroupSessionHandle** out_handle,
    EppError* out_error);

EPP_API EppErrorCode epp_group_is_shielded(
    EppGroupSessionHandle* handle,
    uint8_t* out_shielded,
    EppError* out_error);

typedef struct EppGroupSecurityPolicy {
    uint32_t max_messages_per_epoch;
    uint32_t max_skipped_keys_per_sender;
    uint8_t  block_external_join;
    uint8_t  enhanced_key_schedule;
    uint8_t  mandatory_franking;
} EppGroupSecurityPolicy;

EPP_API EppErrorCode epp_group_create_with_policy(
    EppIdentityHandle* identity_handle,
    const uint8_t* credential,
    size_t credential_length,
    const EppGroupSecurityPolicy* policy,
    EppGroupSessionHandle** out_handle,
    EppError* out_error);

EPP_API EppErrorCode epp_group_get_security_policy(
    EppGroupSessionHandle* handle,
    EppGroupSecurityPolicy* out_policy,
    EppError* out_error);

EPP_API EppErrorCode epp_group_join(
    EppIdentityHandle* identity_handle,
    const uint8_t* welcome_bytes,
    size_t welcome_length,
    EppKeyPackageSecretsHandle* secrets_handle,
    EppGroupSessionHandle** out_group_handle,
    EppError* out_error);

EPP_API EppErrorCode epp_group_add_member(
    EppGroupSessionHandle* handle,
    const uint8_t* key_package_bytes,
    size_t key_package_length,
    EppBuffer* out_commit,
    EppBuffer* out_welcome,
    EppError* out_error);

EPP_API EppErrorCode epp_group_remove_member(
    EppGroupSessionHandle* handle,
    uint32_t leaf_index,
    EppBuffer* out_commit,
    EppError* out_error);

EPP_API EppErrorCode epp_group_update(
    EppGroupSessionHandle* handle,
    EppBuffer* out_commit,
    EppError* out_error);

EPP_API EppErrorCode epp_group_process_commit(
    EppGroupSessionHandle* handle,
    const uint8_t* commit_bytes,
    size_t commit_length,
    EppError* out_error);

EPP_API EppErrorCode epp_group_encrypt(
    EppGroupSessionHandle* handle,
    const uint8_t* plaintext,
    size_t plaintext_length,
    EppBuffer* out_ciphertext,
    EppError* out_error);

EPP_API EppErrorCode epp_group_decrypt(
    EppGroupSessionHandle* handle,
    const uint8_t* ciphertext,
    size_t ciphertext_length,
    EppBuffer* out_plaintext,
    uint32_t* out_sender_leaf,
    uint32_t* out_generation,
    EppError* out_error);

EPP_API EppErrorCode epp_group_get_id(
    EppGroupSessionHandle* handle,
    EppBuffer* out_group_id,
    EppError* out_error);

EPP_API uint64_t epp_group_get_epoch(
    EppGroupSessionHandle* handle);

EPP_API uint32_t epp_group_get_my_leaf_index(
    EppGroupSessionHandle* handle);

EPP_API uint32_t epp_group_get_member_count(
    EppGroupSessionHandle* handle);

EPP_API EppErrorCode epp_group_get_member_leaf_indices(
    EppGroupSessionHandle* handle,
    EppBuffer* out_indices,
    EppError* out_error);

EPP_API EppErrorCode epp_group_serialize(
    EppGroupSessionHandle* handle,
    const uint8_t* key,
    size_t key_length,
    uint64_t external_counter,
    EppBuffer* out_state,
    EppError* out_error);

EPP_API EppErrorCode epp_group_deserialize(
    const uint8_t* state_bytes,
    size_t state_length,
    const uint8_t* key,
    size_t key_length,
    uint64_t min_external_counter,
    uint64_t* out_external_counter,
    EppIdentityHandle* identity_handle,
    EppGroupSessionHandle** out_handle,
    EppError* out_error);

EPP_API EppErrorCode epp_group_export_public_state(
    EppGroupSessionHandle* handle,
    EppBuffer* out_public_state,
    EppError* out_error);

EPP_API EppErrorCode epp_group_join_external(
    EppIdentityHandle* identity_handle,
    const uint8_t* public_state,
    size_t public_state_length,
    const uint8_t* credential,
    size_t credential_length,
    EppGroupSessionHandle** out_group_handle,
    EppBuffer* out_commit,
    EppError* out_error);

EPP_API EppErrorCode epp_group_encrypt_sealed(
    EppGroupSessionHandle* handle,
    const uint8_t* plaintext,
    size_t plaintext_length,
    const uint8_t* hint,
    size_t hint_length,
    EppBuffer* out_ciphertext,
    EppError* out_error);

EPP_API EppErrorCode epp_group_encrypt_disappearing(
    EppGroupSessionHandle* handle,
    const uint8_t* plaintext,
    size_t plaintext_length,
    uint32_t ttl_seconds,
    EppBuffer* out_ciphertext,
    EppError* out_error);

EPP_API EppErrorCode epp_group_encrypt_frankable(
    EppGroupSessionHandle* handle,
    const uint8_t* plaintext,
    size_t plaintext_length,
    EppBuffer* out_ciphertext,
    EppError* out_error);

EPP_API EppErrorCode epp_group_encrypt_edit(
    EppGroupSessionHandle* handle,
    const uint8_t* new_content,
    size_t new_content_length,
    const uint8_t* target_message_id,
    size_t target_message_id_length,
    EppBuffer* out_ciphertext,
    EppError* out_error);

EPP_API EppErrorCode epp_group_encrypt_delete(
    EppGroupSessionHandle* handle,
    const uint8_t* target_message_id,
    size_t target_message_id_length,
    EppBuffer* out_ciphertext,
    EppError* out_error);

typedef struct {
    EppBuffer plaintext;
    uint32_t sender_leaf_index;
    uint32_t generation;
    uint32_t content_type;
    uint32_t ttl_seconds;
    uint64_t sent_timestamp;
    EppBuffer message_id;
    EppBuffer referenced_message_id;
    uint8_t has_sealed_payload;
    uint8_t has_franking_data;
} EppGroupDecryptResult;

EPP_API void epp_group_decrypt_result_free(EppGroupDecryptResult* result);

EPP_API EppErrorCode epp_group_decrypt_ex(
    EppGroupSessionHandle* handle,
    const uint8_t* ciphertext,
    size_t ciphertext_length,
    EppGroupDecryptResult* out_result,
    EppError* out_error);

EPP_API EppErrorCode epp_group_compute_message_id(
    const uint8_t* group_id,
    size_t group_id_length,
    uint64_t epoch,
    uint32_t sender_leaf_index,
    uint32_t generation,
    EppBuffer* out_message_id,
    EppError* out_error);

EPP_API EppErrorCode epp_group_reveal_sealed(
    const uint8_t* hint,
    size_t hint_length,
    const uint8_t* encrypted_content,
    size_t encrypted_content_length,
    const uint8_t* nonce,
    size_t nonce_length,
    const uint8_t* seal_key,
    size_t seal_key_length,
    EppBuffer* out_plaintext,
    EppError* out_error);

EPP_API EppErrorCode epp_group_verify_franking(
    const uint8_t* franking_tag,
    size_t franking_tag_length,
    const uint8_t* franking_key,
    size_t franking_key_length,
    const uint8_t* content,
    size_t content_length,
    const uint8_t* sealed_content,
    size_t sealed_content_length,
    uint8_t* out_valid,
    EppError* out_error);

EPP_API EppErrorCode epp_group_set_psk(
    EppGroupSessionHandle* handle,
    const uint8_t* psk_id,
    size_t psk_id_length,
    const uint8_t* psk,
    size_t psk_length,
    EppError* out_error);

EPP_API EppErrorCode epp_group_get_pending_reinit(
    EppGroupSessionHandle* handle,
    EppBuffer* out_new_group_id,
    uint32_t* out_new_version,
    EppError* out_error);

EPP_API void epp_group_destroy(EppGroupSessionHandle** handle);

#ifdef __cplusplus
}
#endif

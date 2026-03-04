#![no_main]
use libfuzzer_sys::fuzz_target;
use prost::Message;

use ecliptix_protocol::crypto::CryptoInterop;
use ecliptix_protocol::identity::IdentityKeys;
use ecliptix_protocol::proto::{GroupCommit, GroupKeyPackage};
use ecliptix_protocol::protocol::group::GroupSession;
use std::sync::Once;

static INIT: Once = Once::new();

fuzz_target!(|data: &[u8]| {
    INIT.call_once(|| {
        CryptoInterop::initialize().unwrap();
    });

    let alice = match IdentityKeys::create(2) {
        Ok(ik) => ik,
        Err(_) => return,
    };

    let alice_session = match GroupSession::create(&alice, b"fuzz-group".to_vec()) {
        Ok(s) => s,
        Err(_) => return,
    };

    // Try decoding fuzz data as a GroupCommit and process it
    if let Ok(commit) = GroupCommit::decode(data) {
        let mut commit_bytes = Vec::new();
        if commit.encode(&mut commit_bytes).is_ok() {
            let _ = alice_session.process_commit(&commit_bytes);
        }
    }

    // Also try raw bytes directly
    let _ = alice_session.process_commit(data);

    // Fuzz add_member with a decoded key package
    if let Ok(kp) = GroupKeyPackage::decode(data) {
        let _ = alice_session.add_member(&kp);
    }
});

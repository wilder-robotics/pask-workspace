// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics) <rob@wilder-robotics.com>
// pask-wire is licensed Apache-2.0. No commercial agreement is required to use,
// modify or redistribute it; see LICENSING.md in the workspace root.

//! End-to-end producer and verifier tests.

use ed25519_dalek::SigningKey;
use pask_wire::{
    Payload, produce_ed25519,
    testvectors::{MINIMAL_CHAIN_HASH, MINIMAL_VALID_JCS, MINIMAL_VALID_PAYLOAD},
    verify_ed25519,
};

#[test]
fn produce_serialize_parse_verify_round_trip() {
    let payload = Payload::from_json_for_production(MINIMAL_VALID_PAYLOAD.as_bytes()).unwrap();
    assert_eq!(payload.chain_hash(), MINIMAL_CHAIN_HASH);
    assert_eq!(payload.to_jcs().unwrap(), MINIMAL_VALID_JCS.as_bytes());

    let key = SigningKey::generate(&mut rand_core::OsRng);
    let statement = produce_ed25519(&payload, payload.witness_key(), &key).unwrap();
    let verified = verify_ed25519(&statement, &key.verifying_key()).unwrap();
    assert_eq!(verified, payload);
}

#[cfg(feature = "es256")]
#[test]
fn es256_round_trip() {
    let payload = Payload::from_json_for_production(MINIMAL_VALID_PAYLOAD.as_bytes()).unwrap();
    let key = p256::ecdsa::SigningKey::random(&mut rand_core::OsRng);
    let statement = pask_wire::produce_es256(&payload, payload.witness_key(), &key).unwrap();
    let verified = pask_wire::verify_es256(&statement, key.verifying_key()).unwrap();
    assert_eq!(verified, payload);
}

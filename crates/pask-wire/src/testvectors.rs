// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Wilder Robotics <rob@wilder-robotics.com>
// pask-wire is licensed AGPL-3.0-only with a commercial exception; see
// COMMERCIAL-EXCEPTION.md in the workspace root.

//! Compile-time test vectors required by the profile package.
//!
//! # The values are illustrative, and one of them is load-bearing
//!
//! Every value here is synthetic. Digests are repeated-nibble placeholders,
//! the site is the RES-001 reference fixture, and `attestation.teeClass` is a
//! conforming registry value chosen so the vector round-trips. No Pask witness
//! device has been built and no confidential-compute silicon has been
//! selected, so `teeClass` here discloses nothing and prefers nothing.
//!
//! The load-bearing part: `MINIMAL_VALID_JCS` is the source of the example
//! figure carried by the profile document, emitted through
//! [`crate::canonical_example`] and asserted byte-identical to the document in
//! CI. Changing any value in this vector changes the published figure. Change
//! it deliberately, and regenerate with
//! `cargo run -p pask-wire-cli -- canonical-example`.

/// Minimal valid unsigned payload with the package's placeholder chain hash.
pub const MINIMAL_VALID_PAYLOAD: &str = r#"{
  "spec": "wilder.pser/0.4",
  "id": "uuid:00000000-0000-4000-8000-000000000001",
  "ts": "2026-10-15T14:00:00Z",
  "site": {
    "id": "site:res-001",
    "class": "residential",
    "envelope": {
      "id": "env:res-001:2026-Q4",
      "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
      "geobounds": null,
      "temporal": { "starts": "2026-10-01T00:00:00Z", "ends": null }
    }
  },
  "actor": {
    "id": "actor:robot-alpha-01",
    "class": "AUTONOMOUS",
    "operator": "operator:wilder-robotics"
  },
  "engagement": {
    "id": "eng:res-001:20261015-140000",
    "window": { "start": "2026-10-15T13:30:00Z", "end": "2026-10-15T14:00:00Z" },
    "type": "patrol",
    "outcomeClass": "COMPLETED",
    "envelopeConformance": "WITHIN",
    "evidenceDigest": "sha256:1111111111111111111111111111111111111111111111111111111111111111"
  },
  "attestation": {
    "teeClass": "arm.cca",
    "measuredBoot": {
      "chain": "sha256:98a6efd412bb768ea7f090e8228401c11bc72a7caae44170395445c097d5ffa1",
      "components": [
        {
          "name": "bl1",
          "digest": "sha256:2222222222222222222222222222222222222222222222222222222222222222"
        }
      ]
    },
    "platformEvidence": {
      "encoding": "opaque/1",
      "digest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    },
    "sealedEvidence": {
      "digest": "sha256:3333333333333333333333333333333333333333333333333333333333333333",
      "sizeBytes": 4096,
      "encoding": "opaque/1"
    },
    "witnessKey": "key:tee:res-001-witness-01",
    "validity": {
      "notBefore": "2026-10-15T13:00:00Z",
      "notAfter": "2026-10-15T15:00:00Z"
    }
  },
  "adapter": {
    "system": "example.ticketing",
    "endpoint": "endpoint:res-001",
    "postedAt": "2026-10-15T14:00:05Z",
    "ackDigest": "sha256:4444444444444444444444444444444444444444444444444444444444444444",
    "ackProvenance": "THIRD_PARTY",
    "mode": "WRITE_ONLY"
  },
  "chain": {
    "seq": 0,
    "prevHash": null,
    "hash": "sha256:5555555555555555555555555555555555555555555555555555555555555555"
  }
}"#;

/// Correct chain digest for [`MINIMAL_VALID_PAYLOAD`] after production normalization.
pub const MINIMAL_CHAIN_HASH: &str =
    "sha256:96eb8bb3743f07b05067f16d4bea99d170019db5307a87ca78ff019a52984018";

/// Expected JCS bytes for the normalized minimal payload.
pub const MINIMAL_VALID_JCS: &str = r#"{"actor":{"class":"AUTONOMOUS","id":"actor:robot-alpha-01","operator":"operator:wilder-robotics"},"adapter":{"ackDigest":"sha256:4444444444444444444444444444444444444444444444444444444444444444","ackProvenance":"THIRD_PARTY","endpoint":"endpoint:res-001","mode":"WRITE_ONLY","postedAt":"2026-10-15T14:00:05Z","system":"example.ticketing"},"attestation":{"measuredBoot":{"chain":"sha256:98a6efd412bb768ea7f090e8228401c11bc72a7caae44170395445c097d5ffa1","components":[{"digest":"sha256:2222222222222222222222222222222222222222222222222222222222222222","name":"bl1"}]},"platformEvidence":{"digest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","encoding":"opaque/1"},"sealedEvidence":{"digest":"sha256:3333333333333333333333333333333333333333333333333333333333333333","encoding":"opaque/1","sizeBytes":4096},"teeClass":"arm.cca","validity":{"notAfter":"2026-10-15T15:00:00Z","notBefore":"2026-10-15T13:00:00Z"},"witnessKey":"key:tee:res-001-witness-01"},"chain":{"hash":"sha256:96eb8bb3743f07b05067f16d4bea99d170019db5307a87ca78ff019a52984018","prevHash":null,"seq":0},"engagement":{"envelopeConformance":"WITHIN","evidenceDigest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","id":"eng:res-001:20261015-140000","outcomeClass":"COMPLETED","type":"patrol","window":{"end":"2026-10-15T14:00:00Z","start":"2026-10-15T13:30:00Z"}},"id":"uuid:00000000-0000-4000-8000-000000000001","site":{"class":"residential","envelope":{"digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000","geobounds":null,"id":"env:res-001:2026-Q4","temporal":{"ends":null,"starts":"2026-10-01T00:00:00Z"}},"id":"site:res-001"},"spec":"wilder.pser/0.4","ts":"2026-10-15T14:00:00Z"}"#;

/// Unsupported version used by malformed-payload tests.
///
/// MUST stay strictly below every version this profile has ever accepted, so
/// that adopting a new `SPEC_VERSION` can never collide with the negative
/// fixture the verifier is asserted to reject.
pub const WRONG_SPEC: &str = "wilder.pser/0.0";
/// Invalid actor class used by malformed-payload tests.
pub const INVALID_ACTOR_CLASS: &str = "ROBOT";
/// Reversed engagement end used by malformed-payload tests.
pub const REVERSED_WINDOW_END: &str = "2026-10-15T13:00:00Z";
/// Invalid digest used by malformed-payload tests.
pub const INVALID_DIGEST: &str = "sha256:xyz";
/// Reserved adapter mode used by malformed-payload tests.
pub const INVALID_ADAPTER_MODE: &str = "WRITE_READ";
/// Wrong protected content type used by malformed-envelope tests.
pub const WRONG_CONTENT_TYPE: &str = "application/json";
/// Wrong CWT subject used by malformed-envelope tests.
pub const WRONG_CWT_SUBJECT: &[u8] = b"site:not-res-001";

/// RFC 8785 number-serialization input.
pub const JCS_NUMBERS_INPUT: &str =
    r#"{"numbers":[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001]}"#;
/// RFC 8785 number-serialization output.
pub const JCS_NUMBERS_EXPECTED: &str = r#"{"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27]}"#;
/// RFC 8785 property-order input.
pub const JCS_ORDER_INPUT: &str = "{\"\\u20ac\":\"Euro Sign\",\"\\r\":\"Carriage Return\",\"\\ufb33\":\"Hebrew Letter Dalet With Dagesh\",\"1\":\"One\",\"\\ud83d\\ude00\":\"Emoji: Grinning Face\",\"\\u0080\":\"Control\",\"\\u00f6\":\"Latin Small Letter O With Diaeresis\"}";
/// RFC 8785 property-order output.
pub const JCS_ORDER_EXPECTED: &str = "{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\u{0080}\":\"Control\",\"\u{00f6}\":\"Latin Small Letter O With Diaeresis\",\"\u{20ac}\":\"Euro Sign\",\"\u{1f600}\":\"Emoji: Grinning Face\",\"\u{fb33}\":\"Hebrew Letter Dalet With Dagesh\"}";
/// RFC 8785 literal-serialization input.
pub const JCS_LITERALS_INPUT: &str = r#"{ "literals" : [ null, true, false ] }"#;
/// RFC 8785 literal-serialization output.
pub const JCS_LITERALS_EXPECTED: &str = r#"{"literals":[null,true,false]}"#;

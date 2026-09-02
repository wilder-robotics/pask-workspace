// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics) <rob@wilder-robotics.com>
// pask-site is licensed AGPL-3.0-only with a commercial exception; see
// COMMERCIAL-EXCEPTION.md in the workspace root.

mod common;

use std::sync::Arc;

use pask_adapter::{AdapterOutcome, InMemoryDedupLog, mock::MockHttpTransport};
use pask_site::ReferenceSite;

#[test]
fn end_to_end_dedup_returns_already_pushed_on_replay() {
    let (producer, _) = common::producer();
    let request = common::request();
    let transport = Arc::new(MockHttpTransport::new(vec![
        common::success_response(),
        common::success_response(),
    ]));
    let adapter = common::buildium(transport.clone(), Arc::new(InMemoryDedupLog::new()));
    let site = ReferenceSite::new(producer, adapter);

    let first = site.run_engagement(&request).unwrap();
    let second = site.run_engagement(&request).unwrap();
    assert!(matches!(
        first,
        AdapterOutcome::Pushed {
            adapter_name: "buildium",
            adapter_receipt_id,
            ..
        } if adapter_receipt_id == "buildium-note-42"
    ));
    assert!(matches!(
        second,
        AdapterOutcome::AlreadyPushed {
            adapter_name: "buildium",
            prior_receipt_id,
        } if prior_receipt_id == "buildium-note-42"
    ));
    assert_eq!(transport.recorded_calls().len(), 1);
}

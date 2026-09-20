# Versioned software-only evidence contract

The unchanged source implements `pask-robotics-evidence-dev/1` and
`pask-robotics-evidence-dev/2`. This integration's actual fixtures use dev/2,
profile `software-test-only/not-PSER`, recipient `dev-recipient/2`, and prospective
policy `collector-monotonic-sampled-bracket/1`. Unknown versions are not coerced.
Dev/1 retains its original semantics; it is not silently graded under dev/2.

## Separate meanings

* **Event data:** actual callbacks inside the requested collector-monotonic
  interval, trigger minus 2 seconds through trigger plus 3 seconds.
* **Boundary support:** retained actual nearest preceding/first following
  observations, at most one per side per topic. An exact endpoint observation
  can satisfy support without duplicating bytes. Support is explicitly labelled
  `before` or `after`, not misrepresented as in-window data.
* **Sampled coverage:** movement's intended period is 100 ms; control and
  diagnostics are 500 ms. The inherited maximum span is two native periods.
  Each boundary and adjacent retained pair must meet the named policy. This is
  sampled collector coverage, not proof that every physical sample was received
  or that real-world state was continuously known.
* **Raw offsets:** `in_window_start_offset_ns` and
  `in_window_end_offset_ns` expose raw in-window edge offsets.
  `left_offset_ns` and `right_offset_ns` describe supporting observations.
  Positive raw edge offsets are not erased when valid support satisfies policy.
* **Source anomalies:** source-clock rollback is adverse independently of
  collector-monotonic coverage.
* **Real-world mapping:** `unknown_clock_relationship` remains visible as a
  warning. It is not automatically collector failure, but wall-time mapping
  and application acceptance remain unestablished.

The recipient recomputes with its own code path and fixed local policy parameters.
Signed manifest fields cannot weaken the local period/capacity policy. Unknown
quality reasons remain adverse. Loss counters, queue overflow, capacity
eviction, malformed quality/count metadata, missing streams, excessive spans,
insufficient prehistory and premature completion cannot become clean passes
just because boundary observations happen to be present.

## Fixed finite bounds

Ingress queue 8 records; each record at most 4,096 bytes; prebuffer 128 records
and 262,144 bytes; event buffer 256 records and 524,288 bytes; export ceiling
1,048,576 bytes; input limit 5,000 records; quality entries 64; duration 30 seconds.
Readiness and right-side completion require the actual bounded observations;
a deadline by itself is not evidence of completion. Requested event bounds,
actual in-window bounds and retained support bounds remain separate.

Original callback CDR bytes go to capture, export and bags unchanged.
The smoke contract separately tests complete typed-field fidelity, original
byte integrity and fresh encoding stability. The last of these is diagnostic:
the eight retained unequal fifth-run pairs remain **unclassified**, with full
small bytes and typed snapshots preserved. They are not labelled harmless
padding, proven leakage or the established cause of the fourth-run failure.

## Independent findings, not an assurance ladder shortcut

Manifest signature, object integrity, supplied-key association, sampled
coverage, source anomalies, real-world time and application policy are separate
findings. A signature can pass on an export with altered objects. A valid
local software-key association is not organizational authentication. The
recipient is a separate process with independently written coverage logic,
but reused delivered code, not a new external implementation.

No claim here establishes a SCITT Receipt, trusted transparency service,
complete PSER, hardware origin, physical safety or external relying-party
acceptance. The external bridge produces an unsigned local evidence commitment
under its separate mapping contract; it does not change these limits.

These contracts were exercised in the accepted
[fifth isolated experiment](https://github.com/wilder-robotics/pask-workspace/actions/runs/35470820929).
Only bounded offline regression of the preserved bytes was executed on this
new current-main candidate.

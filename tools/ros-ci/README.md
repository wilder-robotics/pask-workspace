# Minimal proposed ROS CI definition

**Local definition only. Not published and not executed on a hosted runner.**
Publication or opening the dedicated test PR requires separate authorization.
No default-branch change, merge or dispatch bootstrap is needed for this proposal.

## Two lanes

1. `ros-offline.yml` is the ongoing PR lane for opened, synchronize and reopened
   events on the listed paths. It checks out the immutable PR head, not the
   generated merge ref. It installs the existing declared Python test dependency,
   runs the source plan, the four existing suites and the wrapper's mock/static
   tests. There is no Docker or ROS execution. "Offline" describes the tests;
   dependency installation and action setup can use the network. Failure does
   not authorize changing dependency versions or automatic retry.
2. `ros-integration-once.yml` is a separately authorized pre-merge arrangement.
   Prepare a **fresh same-repository draft branch** named
   `test/ros-integration-once` starting at corrected source commit
   `f3f8576fa3f77c3ac029fd1ce070907dc3292d55`, then add this exact reviewed
   payload. The branch must include all 29 corrected ROS additions, not just
   the CI files on bare main, so the offline lane has its test inputs.
   Open one draft PR against `main`. Only its `opened` event and first run attempt are
   eligible. Synchronize/reopened events do not trigger it and reruns are gated
   out. Forks, other repositories, other branch names and non-drafts are blocked.
   This does not enforce a lifetime global counter across deleting/recreating
   branches or new PRs. Those actions and any further attempt require new
   authorization. Do not use this definition to silently reopen/retry a run.

The ROS job checks out two separate directories:

- `harness`: `${{ github.event.pull_request.head.sha }}` from the immutable
  opened event. It runs the wrapper/decoder from this exact head.
- `ros-source`: the exact corrected published source commit in `source-pin.json`
  and `ROS_SOURCE_COMMIT`. The wrapper verifies commit, tree, every indexed
  source-file hash/size, clean tracked files and absence of untracked files.
  It records the event base separately. No moving branch, merge ref, fallback
  or repaired source is used to execute the adapter.

The two checkouts intentionally test different scopes. This is not a run of the
PR merge result or of main. A successful source run would not itself establish
merge readiness, DCO certification or compatibility with later main changes.
The resulting immutable harness head is a child of the pinned corrected source
commit; the separate source checkout remains exactly that original source head.
The pinned source tree is `750a376fbc0dd7ac0f82a6c43c2970c8dc5c3452`.
Its source-review PR is https://github.com/wilder-robotics/pask-workspace/pull/85.

GitHub documents the default-branch requirement for `workflow_dispatch`, the
ordinary PR `opened` event and the explicit-head alternative to the default
merge ref:
https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows

A merge-conflicted PR may not run ordinary PR workflows. Treat that as blocked,
not permission to use `pull_request_target`, merge first or substitute a
dispatcher. The separate source-review PR does not install these workflows.

## Exact budgets and boundaries

- Standard GitHub-hosted `ubuntu-24.04`, x86_64; contents read only; no secrets,
  persisted checkout credentials, cache, artifact upload, billing/protection
  change, self-hosted runner or repository-writing action.
- Entire ROS job: 30 minutes. Each checkout: 1 minute. Main step: 26 minutes.
  The wrapper allows 1,500 seconds (25 minutes) including its checks and adapter,
  followed by at most two 5-second process termination waits. This reserves
  recovery time rather than allowing every per-command timeout to accumulate.
- Always-run recovery step: 2 minutes. Its own cleanup budget is 100 seconds,
  with the final 25 seconds reserved from new cleanup iterations for packaging.
  Recovery tries to collect diagnostics and remove only the enumerated containers
  whose `/out` mount exactly matches this attempt's output. A missing ownership
  marker prohibits cleanup. It never removes a preexisting/foreign container.
- Preflight requires 4 GiB available RAM, 12 GiB free workspace and 12 GiB free
  Docker backing storage. The existing adapter checks remain intact. The outer
  monitor additionally stops on raw-evidence overflow or a 1 GiB emergency
  workspace floor. This does not raise any container or package limit.
- The unchanged adapter retains networked dependency/image preparation followed
  by network-none runtime, read-only root, nonroot user, one CPU, 256 MiB memory,
  96 processes, bounded tmpfs, explicit mounts and 60-second container deadlines.
  The wrapper passes only a minimal host environment, not CI token/secret
  environment variables. No production, home, device or Docker-socket mount is
  added to any runtime container.
- The adapter remains responsible for all 48 fixed smoke cases before capture,
  unchanged selected ROS package versions, original-byte bag reopen, clean
  sampled-coverage pass, gap/missing-stream failures, separate recipient image
  and altered-export integrity failure. The wrapper invokes that exact entry
  point once. It does not reimplement or weaken any of those expectations.

Cancellation, loss of the runner, a hard platform/job timeout or missing harness
checkout can prevent recovery. This is bounded best-effort recovery, not a claim
of guaranteed retrieval after infrastructure destruction. A process-group kill
stops host adapter descendants; Docker daemon work can outlive a killed client
until cancellation/disposal, so no claim of perfect daemon cleanup is made.
Any incomplete cleanup or missing evidence is a failure, not a success substitute.

## Bounded evidence recovery

Raw evidence payload limit: **20 MiB**. Compressed transport limit: **4 MiB**.
Build context and the wrapper's empty/private host-home workspace are explicitly
excluded, as in the adapter's evidence accounting. Original logs, manifests,
signatures, bag bytes, installed/image inventories and reports are otherwise
retained unchanged when they fit. The transport index hashes every file.

The recovery step emits ordered 3,072-character base64 chunks to ordinary job
logs, with chunk numbers, total count and the compressed archive's SHA-256.
It locally decodes/verifies the complete transport twice before emission.
No upload-artifact or billing change is required.

If raw size, compressed size, file-count, symlink or other structural limits
prevent complete transport, it emits a small **explicitly incomplete diagnostic
archive** and returns failure. It does not silently truncate files, claim a
partial archive is complete or retry with a broader cap.

After a future separately authorized run, obtain the complete recovery-step
plain-text log through GitHub's normal read-only log download. Save it as
`hosted-recovery.log`, then run from the repository root:

```sh
python3 -B tools/ros-ci/evidence.py hosted-recovery.log --output recovered-new
```

This reads and verifies the indexed chunks twice, checks compressed hash/size,
bounded decompression, safe unique regular files and all per-file hashes before
writing a new output directory. Inspect `DECODE_VERIFIED.json` and
`files/RECOVERY_TRANSPORT.json`; require `complete: true` before treating the
archive as a full record. Missing/reordered/duplicate/changed chunks reject.
Downloaded full-job logs larger than 16 MiB must be reduced to the exact
unmodified recovery-step section, not "fixed" or reconstructed from assumptions.

These are unsigned equality checks, not independently authenticated issuer,
service or hardware provenance. Double decoding is not an independent semantic
implementation. No expected digest becomes externally authenticated by appearing
in a job log.

## Local checks, no Docker or ROS

From a checkout containing this proposed payload:

```sh
python3 -B -m unittest discover -s tools/ros-ci/tests -v
```

All process boundaries in these tests are mocked. The decoder fixtures are
explicitly synthetic transport tests, not a new capture. Existing corrected
source tests have their own source-specific record; this package does not
transfer accepted experiment-five results to a new tree.

The new workflow, wrapper, decoder and tests use Apache-2.0. `LICENSE` contains
the unchanged Apache text from the source integration. No AGPL bridge code,
recipient kit, private signing key or original experiment archive is copied
or relicensed. Publication and execution require separate authorization.

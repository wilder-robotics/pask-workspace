# Proposed ongoing checks: document only

No workflow file is added or changed. No job is started. This proposal requires
an explicit future approval and is not inherited automatically from the one-shot
experimental PR workflow.

## Fast offline lane

Proposed events: pull request opened, synchronize and reopened, limited to
`examples/ros-evidence-dev2/**` and the eventual approved check definition.
Read-only contents permission, ordinary Ubuntu 24.04 hosted runner, no secrets,
no Docker, no artifact publication or writable repository token. Install the
declared offline dependency in a fresh environment and run `local_run.py plan`,
21 actual-data/adapter tests, 39 smoke mocks, 27 runtime mocks and 10 actual-module
RINT-01 boundary-mocked tests.

Proposed timeout: 5 minutes, one attempt, concurrency one per PR; do not retry a
failure automatically. Test logs are the CI record; no broad cache or recursive
historical evidence upload. Dependency availability failure is a failure, not
permission to change the declared dependency.

## Separately approved ROS integration lane

Proposed event: maintainer-authorized manual dispatch with an exact reviewed
immutable commit input. No automatic ROS run for each PR change. Verify the
source map and checkout that exact commit; record target-main separately.
An authorization must identify one attempt and the expected changes. The
successful old PR opened-event arrangement is not reused implicitly.

Use an ordinary Ubuntu 24.04 hosted runner, read-only repository permission,
no secrets or elevated repository actions. Proposed total job timeout is
30 minutes, with a 26-minute orchestration budget and always-run bounded log
recovery/cleanup for owned containers. The future workflow must implement
that outer timeout and evidence retrieval; `local_run.py` currently supplies
per-command/container deadlines, not a total job scheduler.

Keep the unchanged selected ROS pins, explicit base resolution/inventory,
networked build followed by network-none runtime, read-only root, nonroot user,
one CPU, 256 MiB, 96 processes, existing tmpfs/mount restrictions and 60-second
per-container deadlines. Require the existing 4 GiB available host memory and
12 GiB free workspace/Docker storage checks. Preserve full original logs,
source identity, smoke pairs, package/image inventories and capped evidence.
Do not substitute self-hosted, paid, larger or differently configured runners.

Gate all 48 fixed smoke cases before capture. Then require the unchanged clean
coverage pass, adverse scenario/missing-stream findings, original-byte bag
reopen and recipient/tamper behavior. Stop and report the first failed stage
and stages not reached. No retry, automatic pin refresh, fallback or repair.

## Merge and release policy remain separate

This document changes no required check, DCO requirement, branch protection,
billing setting or approval policy. Successful offline checks would not establish
ROS execution of the new tree. Successful ROS execution would not establish
external acceptance, hardware assurance or merge permission. No second-human
maintainer requirement is proposed. Rob's explicit source/DCO/merge decisions
remain outstanding.

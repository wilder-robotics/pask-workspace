#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics)
"""Run real executable I/O regressions, preserving commands, streams and exits.

No build, download, source repair or retry. /dev/full cases are Linux/Unix-only;
unavailability is reported as NOT_RUN, never inferred from mocked writer tests.
An optional separately built no-alloc binary exercises the feature diagnostic.
"""
from __future__ import annotations

import argparse
import errno
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import time

EXPECTED_HELP = (
    b"Local proposed recipient replay (not full PSER acceptance)\n"
    b"Usage: proposed_recipient_replay --mode single|chain --input replay.json "
    b"--key public-key.hex [--output report.json]\n"
    b"The key file is an explicitly supplied 64-lowercase-hex Ed25519 public key.\n"
    b"Output files are created exclusively; existing files are never overwritten.\n"
    b"Exit 0: report produced (may contain failures). Exit 2: input/usage/I/O failure.\n"
    b"Single mode requires one entry and never checks predecessor contiguity.\n"
    b"Chain mode checks presented links from genesis using one key for all entries.\n"
    b"Neither mode establishes latest history, hardware, identity, or application acceptance.\n"
)
NO_FEATURE = b"This local example requires --features alloc.\n"


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fixture_inventory(root: Path) -> dict[str, str]:
    return {str(p.relative_to(root)): sha(p) for p in sorted(root.rglob('*')) if p.is_file()}


def failing_sink() -> tuple[Path | None, str]:
    sink = Path('/dev/full')
    if os.name != 'posix' or not sink.exists() or not stat.S_ISCHR(sink.stat().st_mode):
        return None, '/dev/full character device unavailable'
    try:
        with sink.open('wb', buffering=0) as f:
            os.write(f.fileno(), b'x')
    except OSError as exc:
        if exc.errno == errno.ENOSPC:
            return sink, 'verified ENOSPC from /dev/full'
        return None, f'/dev/full did not produce expected ENOSPC: {exc}'
    return None, '/dev/full unexpectedly accepted a byte'


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', type=Path, required=True)
    p.add_argument('--fixtures', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--no-alloc-binary', type=Path)
    a = p.parse_args()
    binary, fixtures, output = (x.resolve() for x in (a.binary, a.fixtures, a.output))
    if not binary.is_file() or not fixtures.is_dir():
        p.error('supply the actual compiled binary and preserved fixture directory')
    if output.exists() or output == fixtures or output.is_relative_to(fixtures) or fixtures.is_relative_to(output):
        p.error('use a new output directory, separate from fixtures')
    output.mkdir(parents=True)
    before = fixture_inventory(fixtures)
    before_binary = sha(binary)
    base = ['--mode', 'single', '--input', str(fixtures / 'single-match.json'),
            '--key', str(fixtures / 'public-key.hex')]
    rows: list[dict] = []
    sink, sink_note = failing_sink()
    env = {k: v for k, v in os.environ.items() if not k.startswith(('CARGO_', 'RUST_LOG'))}
    env['RUST_BACKTRACE'] = '0'

    def run(label: str, args: list[str], expected: int, *, full_out: bool = False,
            full_err: bool = False, stdout: bytes | None = None, stderr: bytes | None = None,
            selected: Path = binary) -> dict:
        cmd = [str(selected), *args]
        row = dict(label=label, command=cmd, expected_exit=expected,
                   stdout_sink='/dev/full' if full_out else label + '.stdout',
                   stderr_sink='/dev/full' if full_err else label + '.stderr')
        if (full_out or full_err) and sink is None:
            row.update(status='NOT_RUN', reason=sink_note)
        else:
            out_path = sink if full_out else output / (label + '.stdout')
            err_path = sink if full_err else output / (label + '.stderr')
            start = time.monotonic_ns()
            try:
                with out_path.open('wb', buffering=0) as so, err_path.open('wb', buffering=0) as se:
                    done = subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=so, stderr=se,
                                          env=env, cwd=output, timeout=30, check=False)
                row.update(actual_exit=done.returncode, elapsed_ns=time.monotonic_ns() - start,
                           status='PASS' if done.returncode == expected else 'FAIL')
                for stream, path, full, expected_bytes in (
                        ('stdout', out_path, full_out, stdout), ('stderr', err_path, full_err, stderr)):
                    if full:
                        row[stream + '_captured'] = False
                    else:
                        actual = path.read_bytes()
                        row.update({stream + '_captured': True, stream + '_bytes': len(actual),
                                    stream + '_sha256': hashlib.sha256(actual).hexdigest()})
                        if expected_bytes is not None and actual != expected_bytes:
                            row['status'] = 'FAIL'
                            row[stream + '_expected_sha256'] = hashlib.sha256(expected_bytes).hexdigest()
            except (OSError, subprocess.TimeoutExpired) as exc:
                row.update(status='ERROR', error=str(exc), elapsed_ns=time.monotonic_ns() - start)
        rows.append(row)
        (output / 'COMMANDS.json').write_text(json.dumps(rows, indent=2) + '\n')
        return row

    run('help-long-control', ['--help'], 0, stdout=EXPECTED_HELP, stderr=b'')
    run('help-short-control', ['-h'], 0, stdout=EXPECTED_HELP, stderr=b'')
    run('invalid-option-control', ['--unknown', 'x'], 2, stdout=b'',
        stderr=b'replay_error: unknown or duplicate option\n')
    run('report-stdout-control', base, 0, stderr=b'')
    report = output / 'new-report.json'
    file_row = run('report-file-control', base + ['--output', str(report)], 0, stdout=b'', stderr=b'')
    stdout_report = output / 'report-stdout-control.stdout'
    same_report = report.is_file() and stdout_report.is_file() and report.read_bytes() == stdout_report.read_bytes()
    parsed_report = False
    if same_report:
        try:
            parsed_report = isinstance(json.loads(report.read_bytes()), dict)
        except (ValueError, UnicodeError):
            pass
    if not same_report or not parsed_report:
        file_row.update(status='FAIL', report_match=bool(same_report), json_object=parsed_report)
    run('help-stdout-full', ['--help'], 2, full_out=True, stderr=b'replay_error: help output failed\n')
    run('short-help-stdout-full', ['-h'], 2, full_out=True, stderr=b'replay_error: help output failed\n')
    run('invalid-option-stderr-full', ['--unknown', 'x'], 2, full_err=True, stdout=b'')
    absent = ['--mode', 'single', '--input', str(output / 'absent-input.json'),
              '--key', str(fixtures / 'public-key.hex')]
    run('missing-input-stderr-full', absent, 2, full_err=True, stdout=b'')
    run('help-both-full', ['--help'], 2, full_out=True, full_err=True)
    run('report-stdout-full', base, 2, full_out=True, stderr=b'replay_error: report output failed\n')
    run('report-both-full', base, 2, full_out=True, full_err=True)
    preserved = output / 'already-exists.json'
    preserved.write_bytes(b'unchanged existing output\n')
    preserved_hash = sha(preserved)
    exists_row = run('existing-output-stderr-full', base + ['--output', str(preserved)],
                     2, full_err=True, stdout=b'')
    if sha(preserved) != preserved_hash:
        exists_row.update(status='FAIL', existing_output_preserved=False)
    run('help-with-failed-stderr-unused', ['--help'], 0, full_err=True, stdout=EXPECTED_HELP)
    run('report-with-failed-stderr-unused', base, 0, full_err=True,
        stdout=stdout_report.read_bytes() if stdout_report.is_file() else None)
    no_alloc = None
    if a.no_alloc_binary:
        selected = a.no_alloc_binary.resolve()
        if not selected.is_file():
            p.error('no-alloc binary is missing')
        no_alloc = {'path': str(selected), 'sha256': sha(selected)}
        run('no-alloc-control', [], 2, selected=selected, stdout=b'', stderr=NO_FEATURE)
        run('no-alloc-stderr-full', [], 2, selected=selected, full_err=True, stdout=b'')
        no_alloc['preserved'] = no_alloc['sha256'] == sha(selected)
    after = fixture_inventory(fixtures)
    preservation = before == after and sha(binary) == before_binary and (no_alloc is None or no_alloc['preserved'])
    (output / 'COMMANDS.json').write_text(json.dumps(rows, indent=2) + '\n')
    result = {'binary': str(binary), 'binary_sha256': before_binary,
              'no_alloc_binary': no_alloc, 'failing_sink': sink_note,
              'cases': len(rows), 'passed': sum(r['status'] == 'PASS' for r in rows),
              'failed': sum(r['status'] in ('FAIL', 'ERROR') for r in rows),
              'not_run': sum(r['status'] == 'NOT_RUN' for r in rows),
              'fixtures_and_binaries_preserved': preservation,
              'report_file_equals_stdout': same_report,
              'scope': 'actual supplied executable; output failures, not independent semantic verification',
              'results': rows}
    (output / 'RESULTS.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({k: v for k, v in result.items() if k != 'results'}, indent=2))
    return 1 if result['failed'] or not preservation else (2 if result['not_run'] else 0)


if __name__ == '__main__':
    raise SystemExit(main())

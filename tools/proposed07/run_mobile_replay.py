# SPDX-License-Identifier: Apache-2.0
"""Run the real compiled replay example on the 11 mobile/vocabulary specimens.

No build, install, repair, retry, network or publication. Exit zero from the
example means report production, not application acceptance.
"""
import argparse
import hashlib
import json
import subprocess
from pathlib import Path


def lookup(report, path):
    for part in path:
        report = report[part]
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--fixtures', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    binary, fixtures, output = (p.resolve() for p in (args.binary, args.fixtures, args.output))
    output.mkdir(parents=True, exist_ok=False)
    catalog = json.loads((fixtures / 'catalog.json').read_bytes())
    if catalog['schema'] != 'pask-local-mobile-v2-fixtures/1':
        raise ValueError('unsupported fixture catalog')
    before = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in fixtures.iterdir() if p.is_file()}
    results = []
    binary_hash = hashlib.sha256(binary.read_bytes()).hexdigest()
    for case in catalog['cases']:
        source = fixtures / case['file']
        if hashlib.sha256(source.read_bytes()).hexdigest() != case['sha256']:
            raise ValueError('fixture hash mismatch')
        report = output / (case['id'] + '.report.json')
        command = [str(binary), '--mode', case['mode'], '--input', str(source), '--key',
                   str(fixtures / 'public-key.hex'), '--output', str(report)]
        result = dict(id=case['id'], command=command, native_binary_sha256=binary_hash)
        try:
            done = subprocess.run(command, capture_output=True, timeout=30)
            (output / (case['id'] + '.stdout')).write_bytes(done.stdout)
            (output / (case['id'] + '.stderr')).write_bytes(done.stderr)
            result['exit'] = done.returncode
            result['expectations_met'] = False
            if done.returncode == 0 and report.is_file():
                data = report.read_bytes(); parsed = json.loads(data)
                result['report_sha256'] = hashlib.sha256(data).hexdigest()
                result['checks'] = []
                for check in case['checks']:
                    observed = lookup(parsed, check['path'])
                    result['checks'].append(dict(path=check['path'], expected=check['equals'],
                                                 observed=observed, matched=observed == check['equals']))
                result['expectations_met'] = all(c['matched'] for c in result['checks'])
        except (OSError, subprocess.TimeoutExpired, KeyError, IndexError, ValueError) as error:
            result.update(error=str(error), expectations_met=False)
        results.append(result)
        (output / 'RESULTS.json').write_text(json.dumps(results, indent=2) + '\n')
    after = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in fixtures.iterdir() if p.is_file()}
    preserved = before == after and hashlib.sha256(binary.read_bytes()).hexdigest() == binary_hash
    summary = dict(cases=len(results), expected=sum(r['expectations_met'] for r in results),
                   original_inputs_and_binary_preserved=preserved,
                   scope='native fixture expectations, not location or party authentication')
    (output / 'SUMMARY.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary, indent=2))
    return 0 if preserved and all(r['expectations_met'] for r in results) else 1


if __name__ == '__main__':
    raise SystemExit(main())

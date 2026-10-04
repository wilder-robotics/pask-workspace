# SPDX-License-Identifier: Apache-2.0
"""Check or explicitly regenerate pinned local v1/v2 tables; no network or installs."""
import argparse
import hashlib
import json
from pathlib import Path
from vocabulary_codegen import confined, load_profile, parse_json, require


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', choices=('v1', 'v2', 'all'), default='all')
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument('--check', action='store_true', help='default: compare without writing')
    actions.add_argument('--write', action='store_true', help='explicitly replace only configured generated tables')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    config = parse_json((root / 'tools/proposed07/vocabulary_profiles.json').read_bytes())
    selected = ('v1', 'v2') if args.profile == 'all' else (args.profile,)
    # Verify every input before writing any output.
    loaded = [(name, load_profile(root, config, name)) for name in selected]
    result = {}
    for name, (profile, _vocab, counts, generated) in loaded:
        output = confined(root, profile['output'])
        if args.write:
            output.write_bytes(generated)
        else:
            require(output.read_bytes() == generated, name + ': generated Rust differs')
        result[name] = dict(counts=counts, source_sha256=profile['source_sha256'],
                            generated_sha256=hashlib.sha256(generated).hexdigest(),
                            action='write' if args.write else 'check')
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()

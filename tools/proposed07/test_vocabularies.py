# SPDX-License-Identifier: Apache-2.0
"""Author tests for pinned generation/dialect. Not Rust or recipient executions."""
import copy
import hashlib
import json
from pathlib import Path
import unittest
from vocabulary_codegen import (
    classifications, load_profile, parse_json, render, validate_relation,
    validate_schema, validate_vocabulary,
)

ROOT = Path(__file__).resolve().parents[2]
CONFIG = parse_json((ROOT / 'tools/proposed07/vocabulary_profiles.json').read_bytes())
V1 = parse_json((ROOT / CONFIG['profiles']['v1']['source']).read_bytes())
V2 = parse_json((ROOT / CONFIG['profiles']['v2']['source']).read_bytes())
POSE = V2['facts'][-1]


class GenerationTests(unittest.TestCase):
    def test_both_pinned_sources_relations_and_outputs(self):
        for name in ('v1', 'v2'):
            with self.subTest(name=name):
                cfg, _v, _counts, output = load_profile(ROOT, CONFIG, name)
                self.assertEqual(output, (ROOT / cfg['output']).read_bytes())

    def test_v1_hash_is_frozen(self):
        self.assertEqual(CONFIG['profiles']['v1']['source_sha256'],
                         '030cd709841fc057ba76f2568d44401b36d8ce823369756e11e2989309d4468d')

    def test_v1_generated_bytes_are_frozen(self):
        result = render(V1, CONFIG['profiles']['v1']['source_sha256'], legacy=True)
        self.assertEqual(hashlib.sha256(result).hexdigest(),
                         'cb13b49683ad62e6345dda82e056403306998ba9dd295570f3edcf227e396cf9')

    def test_new_vocabulary_is_only_version_and_appended_row(self):
        reduced = copy.deepcopy(V2)
        self.assertEqual(reduced['facts'].pop()['name'], 'site.pose')
        reduced['version'] = V1['version']
        self.assertEqual(reduced, V1)

    def test_all_original_966_classifications_identical(self):
        self.assertEqual(classifications(V2)[:966], classifications(V1))

    def test_21_pose_pairs_exactly_four(self):
        actual = {(r['party'], r['basis']) for r in classifications(V2)[966:] if r['allowed']}
        self.assertEqual(actual, {('appliance-measured', 'measured'),
                                 ('appliance-measured', 'estimated'),
                                 ('platform-recorded', 'measured'),
                                 ('operator-entered', 'declared')})

    def test_extra_allowed_pair_fails_fixed_expected_relation(self):
        v = copy.deepcopy(V2)
        v['facts'][-1]['pairsForbidden'].pop()
        expected = parse_json((ROOT / CONFIG['profiles']['v2']['expected_relation']).read_bytes())
        with self.assertRaises(ValueError):
            validate_relation(v, CONFIG['profiles']['v2'], expected)

    def test_same_count_swapped_relation_still_fails(self):
        v = copy.deepcopy(V2)
        v['facts'][-1]['pairsForbidden'][0] = ['platform-recorded', 'measured']
        self.assertEqual(sum(x['allowed'] for x in classifications(v)), 157)
        expected = parse_json((ROOT / CONFIG['profiles']['v2']['expected_relation']).read_bytes())
        with self.assertRaises(ValueError):
            validate_relation(v, CONFIG['profiles']['v2'], expected)

    def test_every_v2_schema_supported(self):
        validate_vocabulary(V2, CONFIG['profiles']['v2'])

    def test_unknown_allowlist_party_rejects(self):
        v = copy.deepcopy(V2)
        v['facts'][-1]['assertedBy'].append('invented')
        with self.assertRaises(ValueError):
            validate_vocabulary(v, CONFIG['profiles']['v2'])

    def test_old_robot_signed_is_not_reintroduced(self):
        self.assertNotIn('robot-signed', json.dumps(V2))

    def test_global_rules_unchanged(self):
        self.assertEqual(V2['globalRules'], V1['globalRules'])

    def test_unknown_version_does_not_use_a_table(self):
        v = copy.deepcopy(V2)
        v['version'] = 'wilder.pser-content-vocab/999'
        with self.assertRaises(ValueError):
            validate_vocabulary(v, CONFIG['profiles']['v2'])

    def test_duplicate_escaped_key_rejects(self):
        with self.assertRaises(ValueError):
            parse_json(b'{"type":"string","ty\\u0070e":"integer"}')

    def test_non_json_numeric_constant_rejects(self):
        with self.assertRaises(ValueError):
            parse_json(b'{"maximum":NaN}')

    def test_v1_path_not_subject_to_v2_schema_dialect(self):
        v = copy.deepcopy(V1)
        v['facts'][0]['value']['additionalProperties'] = True
        validate_vocabulary(v, CONFIG['profiles']['v1'])
        # Hash-pinned loading still prevents this edited value being generated as v1.


class DialectTests(unittest.TestCase):
    def reject(self, schema):
        with self.assertRaises(ValueError):
            validate_schema(schema)

    def test_unknown_keyword(self):
        self.reject({'type': 'string', 'format': 'date-time'})

    def test_keyword_wrong_type(self):
        self.reject({'type': 'integer', 'maximum': '10'})

    def test_boolean_not_integer_bound(self):
        self.reject({'type': 'integer', 'minimum': True})

    def test_float_not_integer_bound(self):
        self.reject({'type': 'integer', 'maximum': 10.0})

    def test_bound_outside_i64(self):
        self.reject({'type': 'integer', 'maximum': 2**63})

    def test_reversed_integer_bounds(self):
        self.reject({'type': 'integer', 'minimum': 2, 'maximum': 1})

    def test_additional_properties_true(self):
        self.reject({'type': 'object', 'properties': {}, 'additionalProperties': True})

    def test_additional_properties_object(self):
        self.reject({'type': 'object', 'properties': {}, 'additionalProperties': {}})

    def test_additional_properties_zero_not_false(self):
        self.reject({'type': 'object', 'properties': {}, 'additionalProperties': 0})

    def test_unknown_pattern(self):
        self.reject({'type': 'string', 'pattern': '^.*$'})

    def test_nullable_string(self):
        self.reject({'type': 'integer', 'nullable': 'yes'})

    def test_nullable_integer(self):
        self.reject({'type': 'integer', 'nullable': 1})

    def test_required_must_be_array(self):
        self.reject({'type': 'object', 'properties': {}, 'required': 'x'})

    def test_required_undeclared_property(self):
        self.reject({'type': 'object', 'properties': {}, 'required': ['x']})

    def test_duplicate_required_names(self):
        self.reject({'type': 'object', 'properties': {'x': {'type': 'string'}},
                     'required': ['x', 'x']})

    def test_properties_wrong_type(self):
        self.reject({'type': 'object', 'properties': []})

    def test_unknown_nested_keyword(self):
        self.reject({'type': 'object', 'properties': {'x': {'type': 'string', 'bogus': 1}}})

    def test_inapplicable_keyword(self):
        self.reject({'type': 'integer', 'enum': ['1']})

    def test_bad_enum(self):
        self.reject({'type': 'string', 'enum': [1]})

    def test_duplicate_enum(self):
        self.reject({'type': 'string', 'enum': ['x', 'x']})

    def test_bad_max_length(self):
        self.reject({'type': 'string', 'maxLength': -1})

    def test_schema_not_object(self):
        self.reject([])

    def test_unsupported_type(self):
        self.reject({'type': 'array'})

    def test_supported_closed_pose(self):
        validate_schema(POSE['value'])

    def test_nested_depth_limit(self):
        s = {'type': 'string'}
        for _ in range(10):
            s = {'type': 'object', 'properties': {'x': s}}
        self.reject(s)


if __name__ == '__main__':
    unittest.main(verbosity=2)

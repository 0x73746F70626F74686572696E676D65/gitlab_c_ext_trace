import copy
import json
import unittest
from build import annotate, generate


class EvidenceLimits(unittest.TestCase):
    def setUp(self):
        self.row = dict(hop_count=1, path='root -> helper', c_function='root',
                        site_function='helper', argument_index=0, parameter_name='value',
                        visible_parameters=[dict(index=0, name='value')], entry_id='fixture')
        self.root = dict(arity='1', parameter_names=['self', 'value'])

    def test_helper_does_not_imply_value_or_formal_identity(self):
        result = annotate(self.row, self.root, 1, 1, b'fixture')
        self.assertEqual(result['nested_parameter_identity'], 'per_hop_formal_bindings_not_serialized')
        self.assertEqual(result['value_preservation'], 'not_established')
        self.assertEqual(result['local_checks'], 'not_assessed_by_saved_inventory')

    def test_variadic_binding_does_not_guess_extraction(self):
        self.root.update(arity='-1', parameter_names=['argc', 'argv', 'self'])
        result = annotate(self.row, self.root, 1, 1, b'fixture')
        self.assertEqual(result['argument_origin'], 'positional_binding_exact_extraction_not_serialized')

    def test_corrupt_depth_or_endpoint_is_rejected(self):
        for change in ({'hop_count': 2}, {'site_function': 'other'}, {'c_function': 'other'}):
            row = copy.deepcopy(self.row)
            row.update(change)
            with self.assertRaises(AssertionError):
                annotate(row, self.root, 1, 1, b'fixture')

    def test_every_saved_row_has_an_explicit_open_gap_record(self):
        outputs = generate()
        rows = [json.loads(line) for line in outputs['rows.jsonl'].splitlines()]
        gaps = [json.loads(line) for line in outputs['unresolved-rows.jsonl'].splitlines()]
        self.assertEqual(len(rows), len(gaps))
        for row, gap in zip(rows, gaps):
            self.assertEqual(row['inventory_row_sha256'], gap['inventory_row_sha256'])
            self.assertEqual(row['inventory_line'], gap['inventory_line'])
            self.assertEqual(gap['status'], 'open_evidence_gap')
            self.assertIn('local_checks_not_assessed', gap['gaps'])
            self.assertEqual('per_hop_formal_identity_not_serialized' in gap['gaps'], row['call_depth'] > 0)


if __name__ == '__main__':
    unittest.main()

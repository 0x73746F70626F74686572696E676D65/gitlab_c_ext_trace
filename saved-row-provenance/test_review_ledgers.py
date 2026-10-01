import hashlib
import json
import unittest
from build_review_ledgers import resolve_record, generate


class ExactEvidenceJoins(unittest.TestCase):
    def setUp(self):
        self.raw = json.dumps(dict(entry_id='fixture', file='recorded.c')).encode()
        self.gap = dict(root_evidence='../roots.jsonl:1',
                        root_row_sha256=hashlib.sha256(self.raw).hexdigest(), entry_id='fixture')

    def test_matching_reference_is_copied(self):
        number, row = resolve_record(self.gap, [self.raw], 'root_evidence', 'root_row_sha256')
        self.assertEqual(number, 1)
        self.assertEqual(row['file'], 'recorded.c')

    def test_changed_original_record_cannot_be_silently_joined(self):
        with self.assertRaises(AssertionError):
            resolve_record(self.gap, [self.raw + b' '], 'root_evidence', 'root_row_sha256')

    def test_conflicting_identity_is_rejected(self):
        self.gap['entry_id'] = 'different'
        with self.assertRaises(AssertionError):
            resolve_record(self.gap, [self.raw], 'root_evidence', 'root_row_sha256')

    def test_complete_ledgers_remain_semantically_open(self):
        report = json.loads(generate()['review-ledgers-validation.json'])
        self.assertEqual(report['rows'], 615)
        self.assertFalse(report['semantic_gaps_reassessed'])


if __name__ == '__main__':
    unittest.main()

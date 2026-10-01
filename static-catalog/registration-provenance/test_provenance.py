import json
import unittest
from pathlib import Path
from unittest.mock import patch
from build import CATALOG, generate, normalize_status


class RegistrationEvidence(unittest.TestCase):
    def test_disagreement_is_not_silently_resolved(self):
        self.assertEqual(normalize_status(dict(inventory_status='resolved',
                                              status='unresolved_arity_or_callback_signature')),
                         ['historical_and_current_status_differ'])

    def test_unresolved_signature_is_distinct_from_missing_function(self):
        self.assertEqual(normalize_status(dict(inventory_status='unresolved_signature',
                                              status='unresolved_arity_or_callback_signature')),
                         ['parameter_signature_unresolved'])

    def test_all_registrations_and_gaps_join(self):
        outputs = generate()
        rows = [json.loads(line) for line in outputs['rows.jsonl'].splitlines()]
        gaps = [json.loads(line) for line in outputs['unresolved-rows.jsonl'].splitlines()]
        by_id = {r['entry_id']: r for r in rows}
        self.assertEqual(len(rows), 3655)
        self.assertEqual(len(gaps), 262)
        for gap in gaps:
            row = by_id[gap['entry_id']]
            self.assertEqual(row['root_row_sha256'], gap['root_row_sha256'])
            self.assertEqual(row['evidence_status'], 'open_evidence_gap')
        self.assertEqual({r['runtime_activation'] for r in rows}, {'not_established'})

    def test_changed_source_bytes_are_rejected(self):
        original_read = Path.read_bytes
        def corrupt_source(path):
            data = original_read(path)
            return data + b'\n' if path.is_relative_to('/workspace/static-catalog-cache/sources') else data
        with patch.object(Path, 'read_bytes', corrupt_source):
            with self.assertRaises(AssertionError):
                generate()

    def test_missing_argument_gap_row_is_rejected(self):
        original_read = Path.read_bytes
        target = CATALOG / 'review-metadata/unresolved-rows.jsonl'
        def omit_row(path):
            data = original_read(path)
            return b'\n'.join(data.splitlines()[1:]) + b'\n' if path == target else data
        with patch.object(Path, 'read_bytes', omit_row):
            with self.assertRaises(AssertionError):
                generate()

    def test_coverage_uses_actual_row_ids_not_saved_summary(self):
        coverage = json.loads(generate()['coverage-accounting.json'])
        self.assertEqual(coverage['registrations_with_argument_rows'], 197)
        self.assertEqual(coverage['registrations_without_argument_rows'], 3458)
        self.assertEqual(coverage['argument_rows'], 353)
        self.assertEqual(coverage['candidate_registration_ids_including_alternatives'], 207)
        self.assertEqual(coverage['registrations_only_in_alternatives'], 10)
        self.assertEqual(coverage['candidate_rows_including_alternatives'], 384)


if __name__ == '__main__':
    unittest.main()

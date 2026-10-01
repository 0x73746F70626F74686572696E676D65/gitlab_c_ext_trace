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


if __name__ == '__main__':
    unittest.main()

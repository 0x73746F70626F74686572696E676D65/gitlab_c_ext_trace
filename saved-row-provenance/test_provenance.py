import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from build import FILTER, reference, load_manifest


class RecordedReferences(unittest.TestCase):
    def setUp(self):
        self.metadata = dict(catalog_sha256='a' * 64, source_catalog_sha256='b' * 64, revision='recorded')

    def test_missing_reference_does_not_invent_a_location(self):
        result = reference({}, 2, 'c' * 64, FILTER, self.metadata, {})
        self.assertEqual(result['file'], '')
        self.assertEqual(result['line'], '')
        self.assertEqual(result['recorded_source_sha256'], '')
        self.assertEqual(result['provenance_status'], 'unresolved')

    def test_artifact_digest_is_not_source_verification(self):
        result = reference(dict(file='recorded.rb', line='12'), 2, 'c' * 64,
                           FILTER, self.metadata, {'recorded.rb': 'd' * 64})
        self.assertEqual(result['catalog_sha256'], 'a' * 64)
        self.assertEqual(result['recorded_source_sha256'], 'd' * 64)
        self.assertEqual(result['source_verification'], 'manifest_only_source_checkout_unavailable')

    def test_invalid_line_remains_unresolved(self):
        for line in (-1, 0, 'unknown', None):
            result = reference(dict(file='recorded.rb', line=line), 2, 'c' * 64,
                               FILTER, self.metadata, {'recorded.rb': 'd' * 64})
            self.assertEqual(result['line'], '')
            self.assertEqual(result['provenance_status'], 'unresolved')

    def test_conflicting_source_manifest_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'manifest.jsonl'
            path.write_text('\n'.join(json.dumps(dict(file='same.rb', sha256=value * 64))
                                      for value in ('a', 'b')))
            with self.assertRaises(AssertionError):
                load_manifest(path)


if __name__ == '__main__':
    unittest.main()

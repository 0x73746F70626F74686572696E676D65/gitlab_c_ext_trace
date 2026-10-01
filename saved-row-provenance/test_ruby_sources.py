import hashlib
import unittest
from verify_ruby_sources import check_source
from build import FILTER, reference


class ByteAndRangeEvidence(unittest.TestCase):
    def test_digest_mismatch_is_not_promoted(self):
        self.assertEqual(check_source(b'fixture\n', '0' * 64, 1)[2], 'unresolved_source_digest_mismatch')

    def test_matching_bytes_do_not_validate_an_invalid_line(self):
        data = b'fixture\n'
        self.assertEqual(check_source(data, hashlib.sha256(data).hexdigest(), 2)[2],
                         'unresolved_recorded_line_out_of_range')

    def test_missing_source_is_explicit(self):
        self.assertEqual(check_source(None, '0' * 64, 1)[2], 'unresolved_source_file_missing')

    def test_verified_status_requires_exact_source_hash_and_line(self):
        metadata = dict(catalog_sha256='a' * 64, source_catalog_sha256='b' * 64, revision='recorded',
                        verified_sources={'fixture.rb': dict(status='source_bytes_and_line_range_verified',
                                         actual_source_sha256='c' * 64, source_line_count=2)})
        good = reference(dict(file='fixture.rb', line=2), 1, 'd' * 64, FILTER, metadata, {'fixture.rb': 'c' * 64})
        self.assertEqual(good['provenance_status'], 'source_bytes_and_line_range_verified')
        bad = reference(dict(file='fixture.rb', line=3), 1, 'd' * 64, FILTER, metadata, {'fixture.rb': 'c' * 64})
        self.assertEqual(bad['provenance_status'], 'unresolved')


if __name__ == '__main__':
    unittest.main()

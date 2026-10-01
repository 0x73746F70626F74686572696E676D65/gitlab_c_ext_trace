# Provenance for existing saved rows

This companion copies only file/line references already recorded in the saved
rows and joins them to their original source-hash manifests. It adds no call
paths, argument transfers, receiver/sink resolutions, native source locations,
authentication conclusions or local-check assessments. Existing tables and
their unresolved classifications remain unchanged.

- `anonymous-filtered.csv.gz`: the 122 filtered rows whose existing `auth` is
  `unauthenticated` or `conditional_anonymous`. These labels are preserved as a
  selection rule, not revalidated. A row is identified by its record number in
  `gem_receiver_identifier_filter/filtered_matches.csv`, counting the header
  as record 1. It is a CSV record number, not a physical source line.
- `unresolved-stops.csv.gz`: all 895,714 original unresolved-stop JSONL records,
  identified by their one-based decompressed record number. The existing Ruby
  file and source line are copied; the original unresolved reason remains in
  the input ledger. No unresolved call is resolved by this companion.

Both outputs can be read with `gzip -dc` or Python's standard `gzip`/`csv`
modules. Repeated file/line references remain separate records; they are not
independent findings. Source revisions remain those recorded by the original
artifacts (`9cfc39017e700a28649858f6a902117f9d5e8edd`), not the native catalog's
different GitLab snapshot.

## Checksums and evidence meaning

`catalog_file` identifies the original containing artifact. `catalog_sha256`
is its newly computed byte checksum: for the stop ledger it hashes the stored
compressed file. It is **not a source checksum**. The generator also verifies
the input artifact, source manifest and summary against their existing checksum
manifest before generating any results.

For filtered rows, `argument_catalog_file` and `argument_catalog_sha256` also
pin the already-associated `static-catalog/entry-argument-sites.csv` artifact;
its digest is freshly checked against the filter's saved input metadata.
`argument_catalog_record` copies the existing `argument_table_line` reference
without dereferencing it or adding a native source location. Stop records have
no such recorded association, so these cells stay blank and the status is
`not_recorded`. This does not create an argument-catalog association for a stop.

`catalog_record_sha256` hashes a filtered CSV record after JSON serialization
with sorted keys and compact separators, or an original decompressed JSONL
record excluding its line ending. Those two encodings are explicit and are not
interchangeable. No row is joined by method name or inferred source identity.

`file` and `line` are the already-recorded Ruby source reference.
`recorded_source_sha256` is copied from the original source manifest;
`source_catalog` and `source_catalog_sha256` identify and pin that manifest.
The native argument catalog is not dereferenced to add new operation locations.

The pinned GitLab source checkout is absent in this environment. Consequently,
all source verification statuses are
`manifest_only_source_checkout_unavailable`: source bytes and source-line ranges
were **not freshly verified**. `recorded_reference_and_manifest_hash` means
that existing references and a recorded digest were available, not that the
source, path feasibility, authentication, dispatch or argument values were
revalidated. Missing files, positive line numbers or recorded hashes would be
left blank with explicit `unresolved` status and a reason; no replacement is
guessed. All current records have a recorded file, positive line and hash.

## Reproduction

From the repository root:

```sh
python saved-row-provenance/build.py --check
python -m unittest discover -s saved-row-provenance -p 'test_*.py'
```

Omit `--check` to regenerate. Gzip outputs have fixed timestamps and no stored
filename. Check mode regenerates in a temporary directory and compares file
digests. `validation.json` records complete input hashes, row counts and output
hashes. `SHA256SUMS` covers this companion. Only saved artifacts are read; no
target code, parser, application, endpoint or build hook is executed.

Batch base: verified remote `work` at
`40290fcaef7350a7b745cd3dff269e8fcbcf8dbd`. The top-level README checksum is
corrected separately in the existing root `SHA256SUMS`; every other historical
checksum entry is retained.

## Existing native-review ledgers: separate provenance batch

`review-ledgers.csv` supplies direct file, line, catalog checksum and source
checksum columns for all **615 existing unresolved-review rows**: 353 argument
review rows and 262 registration review rows. These records are not joined to
the anonymous filtered table. Each original evidence pointer is checked against
its saved record hash before any reference is copied; registration identities
are also checked when present. Catalog and ledger checksums hash their complete
containing JSONL artifacts. Source-catalog checksums hash `files-scanned.csv`.

The available native source cache permits fresh byte and line-range verification
for all 615 references across **66 files**. `recorded_source_sha256` identifies
the full source file; `verified_source_line_sha256` hashes the referenced source
line excluding its line ending. No source text, new native location, argument
transfer or binding conclusion is derived. Every source path and line comes from
the originally cited record. These byte/range checks do not validate the meaning
of the cited code, applicability of local checks, or correctness of call paths.
All original semantic gaps and statuses remain unchanged. A missing manifest
record, source file or valid line would retain an explicit unresolved status.

Run `python saved-row-provenance/build_review_ledgers.py --check` to reproduce
this separate batch. It reads only saved metadata and source bytes and requires
the existing digest-matched source cache for the same verification outcome.
`review-ledgers-validation.json` pins its exact inputs and reports coverage.
`checks.json` remains the first batch's check receipt; the second batch's results
are in `review-ledgers-checks.json`. The shared test command now runs eight tests.

Second batch base: verified remote `work` at
`10790e21deed328b9c592fd7442d3f28c40d80d2`.

Remaining provenance limitation: the Ruby/GitLab references in the first batch
remain manifest-only because the pinned GitLab checkout is unavailable. Source
semantics, authentication, binding and local-check gaps remain outside these
provenance passes. No further substantive provenance gap is identified within
the requested saved-row populations using currently available evidence.

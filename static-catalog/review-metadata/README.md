# Saved inventory evidence limits

This additive companion documents all 353 existing argument-site rows. It is
benign static documentation of evidence quality, not a new call graph or runtime
analysis. Original rows, deduplication, source snapshots and coverage counts are
unchanged. No frontend, endpoint, authentication or exploit mapping is added.

`rows.csv` and `rows.jsonl` provide the same review columns. `inventory_line`
is the one-based JSONL line; `inventory_row_sha256` hashes its original bytes
excluding the newline. Evidence references resolve relative to this directory.
`validation.json` pins the complete input files. Source file/line and original
expressions remain in the referenced original row, without being reinterpreted.

Column meanings:

- `argument_origin`: 187 rows agree with a fixed-arity root formal at Ruby
  position i / C position i+1. The remaining 166 retain positional binding
  identity but do not serialize the exact extraction event. This is not HTTP
  input provenance or proof of the value at the site.
- `call_depth`: the original `hop_count`, with root depth zero. All 353 saved
  paths have matching depth and root/site endpoints. Counts at depths 0–5 are
  169, 98, 53, 8, 23 and 2. This is the retained shortest syntactic context,
  not runtime stack depth, exhaustive paths or all possible contexts.
- `parameter_identity`: registration identity plus zero-based Ruby position.
  `parameter_name_semantics` makes explicit that the original name labels an
  origin binding. For 184 helper rows, actual/formal bindings at each intervening
  hop were not serialized. Reading a terminal expression's token as the original
  formal, or equating their current values, is unsupported. The other 169 rows
  have no helper hops; reassignment can still change their values.
- `local_checks`: all 353 are `not_assessed_by_saved_inventory`. The existing
  extractor traverses syntax without solving branch admission; its implementation
  and `../notes.txt` document that scope. This status never means guards are
  absent, ineffective, or bypassable. Fresh check review requires source bodies
  and branch context, not merely a nearby comparison.
- `source_reinspection`: semantic review remains pending. `source_integrity`
  records the subsequent successful digest and saved-site syntax validation;
  `source_validation_evidence` links its versioned receipt. Those automated
  checks are not a new independent semantic source review.

`unresolved-rows.jsonl` is an explicit open-evidence ledger for all 353 rows,
joined by original line and row hash. Gap counts overlap: local-check assessment,
value preservation and fresh source reinspection are open for all rows; exact
positional extraction is open for 166; per-hop formal identity is open for 184.
These are documentation gaps, not vulnerability findings. No row is silently
promoted to a proven flow when one gap closes. Historical unresolved-hop records
remain separate and unchanged (168,263 records, a different denominator).

Evidence needed to close a gap:

- Local checks: pin the matching source digest, cite the enclosing function and
  check locations, and document what was checked and what remains unknown about
  applicability. A syntactically nearby check alone does not establish admission.
- Value preservation: review assignments and transformations in the bounded
  source context; retain uncertainty for aliases, returns and missing bodies.
- Exact positional extraction: cite the extraction expression and position with
  its source identity; do not infer it from a binding name alone.
- Per-hop formal identity: cite each helper declaration and corresponding actual
  expression, keeping original Ruby position separate from local formal names.
- Source reinspection: independently review the bounded semantic claim against
  the recovered digest-matched source and record the scope and outcome. The
  completed automated digest/syntax checks alone do not close this gap.

This ledger was added as a second bounded batch after verifying remote `work`
at 3d70354f44a92c0b9c9b47799773610b44e72f96. It adds no registrations, sites,
routes, runtime claims, or resolved-source claims.

Run from the repository root:

```sh
python static-catalog/review-metadata/build.py --check
python -m unittest discover -s static-catalog/review-metadata -p 'test_*.py'
```

Omit `--check` to regenerate this companion. The script uses only the Python
standard library and never runs target code. It also checks the input digests
pinned by the fresh source-validation receipt. Historical `../validation.json`
is preserved; the fresh run is recorded in `source-validation.json`. Checksum,
source-syntax and saved-row consistency checks provide no runtime or
semantic-accuracy guarantee.

## Source-validation follow-up

The third batch resolved the missing-cache/parser blockers reported by the first
two batches. All 70 needed locked package variants were restored with the
documented `scripts/restore_inventory_sources.py`, after checking each manifest
digest against Gemfile.lock and verifying official HTTPS RubyGems URLs. The
restorer reads archive members without running Ruby or build hooks. The pinned
three parser versions were installed from binary PyPI wheels in
`/workspace/inventory-validation-venv`. The receipt records package provenance,
dependency versions, wheel URLs/digests and the exact validator input hashes.

The validator ran in `/workspace/inventory-validation-20261001/static-catalog`,
a copy of the catalog, so historical reports remained unchanged. Its 41 inert
parser tests passed. It verified 5,773 source digests, 3,655 registrations,
353 rows, 31 collision alternatives and 168,263 unresolved source references.
Reference validity does not resolve those unresolved hops. The prior metadata
columns and open semantic gaps remain; no new argument transfers or check
effectiveness claims were inferred.

Reproduce in a fresh disposable copy of `static-catalog` (the original validator
writes `validation.json` and `SHA256SUMS`): create a Python venv, install
`scripts/requirements.txt` using `--only-binary=:all:` and the PyPI index, run
`scripts/restore_inventory_sources.py`, then run
`scripts/validate_call_argument_inventory.py` with that venv's Python. Source
restoration uses the manifest's absolute `/workspace/static-catalog-cache` paths.
No application or extension execution is needed. Full generation of new graph
or argument traces is outside this validation step.

Repository inspection found a clean local `work` at 7675bfa, matching the saved
results branch. It was fast-forwarded to remote `work` at
64f283562a70df1159613cca047e2bb6c3e30024 before this batch. No AGENTS.md or
local .agents/skills SKILL.md files were found in the workspace; .agents and
.codex were empty. No earlier changes were discarded.

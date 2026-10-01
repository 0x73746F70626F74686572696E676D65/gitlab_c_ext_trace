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
- `source_reinspection`: none in this batch. The restored workspace has no
  native source cache. These annotations are supported by saved metadata and
  analyzer semantics, not a new independent source review.

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
- Source reinspection: recover digest-matched source files and record the scope
  and outcome of the static review. Saved checksums alone do not close this gap.

This ledger was added as a second bounded batch after verifying remote `work`
at 3d70354f44a92c0b9c9b47799773610b44e72f96. It adds no registrations, sites,
routes, runtime claims, or resolved-source claims.

Run from the repository root:

```sh
python static-catalog/review-metadata/build.py --check
python -m unittest discover -s static-catalog/review-metadata -p 'test_*.py'
```

Omit `--check` to regenerate this companion. The script uses only the Python
standard library and never runs target code. Full original source validation
with `scripts/validate_call_argument_inventory.py` is blocked in this restored
environment by missing `tree_sitter` and the native source cache. Historical
`../validation.json` is preserved; it is not a fresh run. Checksum and saved-row
consistency checks provide no runtime or semantic-accuracy guarantee.

Repository inspection found a clean local `work` at 7675bfa, matching the saved
results branch. It was fast-forwarded to remote `work` at
64f283562a70df1159613cca047e2bb6c3e30024 before this batch. No AGENTS.md or
local .agents/skills SKILL.md files were found in the workspace; .agents and
.codex were empty. No earlier changes were discarded.

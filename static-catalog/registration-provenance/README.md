# Registration source identity and documentation completeness

This companion covers all **3,655 existing native registrations**, including
those without an argument-site row. It adds no registrations or call/argument
traces. Its purpose is to make source identity and unresolved binding status
reviewable independently of selected operation-site coverage.

The original argument-site schema includes call/store names, selected operands,
parameter names and helper paths for native copy, allocation, formatting and
indexed-store operations. Those are syntactic occurrences, not attacker-control
or runtime claims. This companion does not expand or join them to frontend paths.

`rows.csv` and `rows.jsonl` contain the same fields. `root_line` is a one-based
line in the original root JSONL; its hash excludes the newline. Evidence links
resolve relative to this directory. Original registration identity is preserved.
Every entry-point CSV field is checked against the corresponding root record.

Source identity columns record the registration file/line, source SHA256,
registration-line SHA256 (excluding its line ending), source variants, selected
locked variant, package URL and package SHA256. The generator reads the restored
sources, checks their catalog digests, checks line ranges and confirms that the
recorded registration token occurs on its cited line. It verified **274 source
files**. A token on a line is not a new parser-level registration/binding proof.
The earlier source-validation receipt pins the supporting input files and
package provenance; this report does not claim build or deployment equivalence.

Definition evidence is kept separate: **3,396** records have a digest-matched
definition file and valid line reference; **259** have no recorded definition.
Definition content, parameter semantics and final Ruby dispatch were not
revalidated. Original parameter-name presence is documented without claiming
that a nonempty list establishes a correct signature. Runtime activation remains
`not_established` for every row.

Both historical and current binding statuses remain visible:

| Current saved status | Registrations |
| --- | ---: |
| resolved | 3,394 |
| unresolved | 259 |
| unresolved_signature | 2 |

`unresolved-rows.jsonl` explicitly retains **262 documentation-review rows**:
259 unresolved function bindings, two unresolved signatures, and one historical
versus current resolution disagreement. The disagreement is RedCloth's `to`
registration, whose historical status is `unresolved_arity_or_callback_signature`
and current status is `resolved`. Both claims are preserved; this batch does not
choose between them. These three groups are disjoint in the current snapshot.
Rows outside this ledger have consistent saved binding claims, not newly proven
runtime behavior. General semantic uncertainty still applies to all rows.

This registration ledger is a different population from
`../review-metadata/unresolved-rows.jsonl` (353 selected argument rows) and
`../unresolved-hops.csv.gz` (168,263 recorded boundaries). Their counts cannot be
added as distinct findings. Missing argument-site rows do not establish absence
of behavior or complete analysis of those registrations.

Run from the repository root after the documented source restoration:

```sh
python static-catalog/registration-provenance/build.py --check
python -m unittest discover -s static-catalog/registration-provenance -p 'test_*.py'
```

Omit `--check` to regenerate. The standard-library script only reads source
bytes and saved metadata; it performs no preprocessing, compilation, Ruby,
extension, application or endpoint execution. It requires the restored source
cache and fails on missing files or digest/reference mismatches. The existing
full source validator and historical reports remain unchanged.

Batch base: verified remote `work` at
`20744fd00e2cc7ccecfe405edf1dcdc5951cc1a9`.

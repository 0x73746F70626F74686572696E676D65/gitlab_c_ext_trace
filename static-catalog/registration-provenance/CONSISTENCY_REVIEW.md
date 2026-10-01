# Coverage denominators and saved status consistency

This batch uses saved records and analyzer implementation evidence only. It adds
no native argument transfers, resolves no sensitive operation bindings, and
performs no missing-check discovery.

## Coverage accounting

`coverage-accounting.json` distinguishes these populations:

| Population | Count |
| --- | ---: |
| All registration records | 3,655 |
| Selected representative argument rows | 353 |
| Registration IDs in those representative rows | 197 |
| Registrations without a representative argument row | 3,458 |
| Preserved alternative rows | 31 |
| Representative plus alternative rows | 384 |
| Registration IDs including alternatives | 207 |
| Registration IDs present only in alternatives | 10 |

The saved `summary.json:roots_with_rows = 207` counts `inventory.rows` before
deduplication (`../scripts/call_argument_inventory.py:511`), whereas the published
argument table retains one representative per requested key. The selection and
collision retention are at lines 480–495. Rejoining the saved alternative
records reproduces 207 distinct registration IDs and all 384 candidate rows.
Thus the initial apparent inconsistency is an explained denominator difference,
not a stale count. Historical fields and values remain unchanged.

The requested deduplication key lacks registration identity, receiver and source
file. Ten registrations therefore occur only among alternatives; their missing
representative rows do not establish missing behavior or safety. Of the 3,458
registrations without a representative row, 3,197 have a saved resolved binding,
259 have an unresolved binding, and two have an unresolved signature. These
statuses do not establish coverage completeness or runtime activation.

The generator validates all 353 argument gap records against exact input line
and row hash, their open status, and their expected gap set. It also regenerates
the 262-row registration gap ledger deterministically. The populations are
different: adding their row counts would not count distinct defects.

## RedCloth historical/current status disagreement

Evidence: `../argument-inventory-roots.jsonl:1` and its matching CSV entry identify
`RedCloth:ext/redcloth_scan/redcloth_scan.c:24400:to`, saved arity `1`, and saved
parameter names `self, formatter`. Its historical status is
`unresolved_arity_or_callback_signature`; its current status is `resolved`.

The historical script checks unknown/unsupported arity and whether the available
formal count is less than arity plus one (`../scripts/entry_catalog.py:506-510`).
The newer inventory accepts nonnegative arity with at least arity plus one
formals (`../scripts/call_argument_inventory.py:338-348`). Substituting only the
currently saved metadata (arity 1, formal count 2) would pass both signature
gates. This does not reproduce the historical analyzer's selected function or
formal list, which is not serialized in the entry CSV. The scripts also use
different function-resolution implementations.

Consequently the older unresolved label cannot be explained uniquely from these
records. No label is overwritten and the disagreement remains open. Determining
the historical cause would require the exact earlier selected-function metadata
or a separately scoped reproduction of that historical analysis; this batch
does neither. No conclusion about native behavior follows from the disagreement.

Base: remote `work` at `f8e0090e900466defb475906c507c0e4468305d5`.

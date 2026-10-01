# Handler-binding slice 201–400

Reviewed unresolved handler bindings 201 through 400, in ledger order, on `work` at `b345aa73b97628aeda052b89e169472fe22a2712`. They occupy records 591–928 of `unmatched-depth2-join/entrypoints-considered.jsonl.gz`. Selection used the prior slice's end cursor and stopped at binding 400. The first 200 bindings and later bindings were not reviewed.

All 200 recorded declaration files were available, across 22 distinct files. Handler-file fields were blank, so reads began at the recorded declaration ranges. Each recorded field method was checked for a definition only in that declaration file. Eighteen bindings name explicit resolvers; their declarations and bounded bodies or factories were inspected in 14 resolver files. At most one named call was followed. Neither `send` nor `method_missing` was followed. Application code and repository scripts were not executed.

No qualifying call had both a receiver resolved to a catalogued gem and a method present in `static-catalog/entry-argument-sites.csv`. Consequently, `rows.csv` contains the 34-column header and zero data rows; no source labels were added.

| Source | Rows |
| --- | ---: |
| params | 0 |
| literal | 0 |
| local | 0 |
| unresolved | 0 |

The review stopped at 182 implicit fields without a local recorded method, 9 local resolver bodies, 4 resolver classes without a local resolve body, 4 factories without a local definition, and 1 local factory returning another resolver class. Helper calls, inherited behavior, implicit object dispatch, and returned resolver classes were not expanded. This is an empty bounded join, not a finding that those deeper paths have no gem calls.

`bindings-considered.jsonl` records the 200 selected bindings and individual stop reasons. `source-files.jsonl` records the 36 source files, hashes, and read ranges. `summary.json` records input hashes, checkout SHA, selection bounds, and counts. `SHA256SUMS` covers the five output artifacts. Earlier tables remain unchanged.

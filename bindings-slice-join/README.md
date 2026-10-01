# First unresolved handler-binding slice

The input is the first **200** `unresolved_root` records, in existing order,
from `unmatched-depth2-join/entrypoints-considered.jsonl.gz` at analysis commit
`e6730954a11dd9baed91fb9e779055d06b6d0b15`. They span ledger records **14–590**;
only those selected entrypoint IDs are reviewed and joined.

All 200 binding-ledger handler-file fields are null. Their recorded declaration
files are recovered by ID from `unauthenticated_entrypoints/entrypoints.json`.
**200 of 200 have an existing recorded declaration file**, across **53 files**,
and each file was opened. The slice has 92 Grape endpoints and 108 GraphQL
fields: five explicit resolver declarations, five local methods and 98 implicit
fields without a local body. The three work-item registrations have shifted
within their recorded file; the ledger records both original and current lines.

[rows.csv](rows.csv) contains **8 stored catalog associations from 2 entrypoints**.
Both selected NuGet V2 feed registrations at
`lib/api/concerns/packages/nuget/public_endpoints.rb:110` call
`Packages::Nuget::V2::ServiceIndexPresenter#xml`, whose line 19 contains
`Nokogiri::XML::Builder.new(encoding: 'UTF-8')`. Each entrypoint joins the four
existing `nokogiri/new` catalog records 271–274. The options argument at index
0 is fixed; index 1 has no visible expression and remains unresolved.

| source | Rows |
| --- | ---: |
| params | 0 |
| literal | 4 |
| local | 0 |
| unresolved | 4 |
| Total | 8 |

All eight rows retain the inventory's `unauthenticated` label. Gem, method,
argument index, stored label, slot and native hop count are copied from the
call-argument catalog. `call_chain_depth` separately records one repository
helper hop. This namespace/method join includes generic `new` registrations
and does not establish dispatch to a specific native registration.

The review follows at most one source-bound named repository call per handler.
There are 87 such selected call chains. Explicit resolver bodies are read from
their declarations; other implicit framework/object dispatch and dynamic calls
are not expanded. `send` and `method_missing` are skipped. No second helper hop,
Ruby/C default or missing argument is inferred. Existing tables are unchanged.
No target code, project scripts or tests ran.

[bindings-considered.jsonl](bindings-considered.jsonl) accounts for all 200
selected records, file availability, handler scope, chosen named call and result.
[source-files.jsonl](source-files.jsonl) records full-file hashes for the source
files read, including the excluded file described below. [summary.json](summary.json)
records exact input hashes, counts, source evidence and validation. Source reads
use the retained checkout at `90f38934040c4790f79b9aada22b50c1597f42dc`; the
inventory revision is recorded separately. Run `sha256sum -c SHA256SUMS` from
this directory to verify the artifacts.

Two scope mistakes are recorded in the summary. An initial metadata filter used
`unresolved` rather than `unresolved_root` and traversed the ledger without
selecting records; the corrected filter stopped at the 200th match. Also,
`app/services/gravatar_service.rb` was opened in error while reading an
unselected field in a shared GraphQL file. That helper is excluded from the
review and join and contributes no rows. No later binding is included in the
output.

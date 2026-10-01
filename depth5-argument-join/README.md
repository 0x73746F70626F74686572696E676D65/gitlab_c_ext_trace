# Depth-5 gem argument matches

[rows.csv](rows.csv) adds **20 depth-5 associations** from existing chains in
`gem_receiver_identifier_filter/filtered_matches.csv` at analysis commit
`b8bb8ba75bf07ba743d634ae43fcbfae39d93898`. [summary.json](summary.json)
records inputs, hashes, frontier decisions, source evidence and counts.

| Auth label | params | literal | local | unresolved | Total |
| --- | ---: | ---: | ---: | ---: | ---: |
| authenticated | 4 | 4 | 0 | 0 | 8 |
| unknown | 6 | 6 | 0 | 0 | 12 |
| conditional_anonymous | 0 | 0 | 0 | 0 | 0 |
| unauthenticated | 0 | 0 | 0 | 0 | 0 |
| Total | 10 | 10 | 0 | 0 | 20 |

The saved filtered table has 392 rows. Its 98 depth-4 rows represent 56 distinct
entrypoint/frontier chains ending in five methods. Repeated seed catalog
associations are collapsed before extension; `seed_filtered_records` preserves
all originating CSV record numbers, counting the header as record 1. Earlier
depths are not rewalked, and all depth-4 artifacts remain unchanged.

Manual source reading finds one extra named repository call:
`Ci::DailyBuildGroupReportResultsFinder#start_date` calls `end_date` at line 90
of `app/finders/ci/daily_build_group_report_results_finder.rb`. The same file
defines `end_date` at line 93. Its line 94 call is
`Date.strptime(params[:end_date], DATE_FORMAT_ALLOWED)`. The saved receiver
manifest assigns `Date` to the `date` gem. Four catalog records, 82 through 85,
match `date/strptime`, yielding four rows for each of five recorded chains.
The other frontier methods have no additional resolved source-defined repository
call within this step.

Argument 0 is a direct `params[:end_date]` expression and gets `params`.
Argument 1 is fixed by `DATE_FORMAT_ALLOWED = '%Y-%m-%d'` at line 25 and gets
`literal`. The extension accepts the visible params expression; it does not
repeat the earlier identifier-only argument filter. `Date.current` in the rescue
branch has no matching method in the date argument catalog and produces no row.

The final Ruby site already appears at depth 4 for the format argument. This
output retains the distinct longer chain through `start_date -> end_date`;
it adds zero physical Ruby call sites. Ten associations share an
entrypoint/site/catalog reference with the older filtered table and differ in
their recorded chain and depth.

`gem`, `method`, `argument_index`, `stored_label`, `slot` and `call_depth`
are copied from the existing catalog. `call_depth` is its native `hop_count`;
`call_chain_depth` is the frontend depth. The latter is 5 for every output row.
The existing depth convention counts the entrypoint body as 0 and each followed
repository method as another hop; the terminal gem invocation adds no helper hop.

Four source files were read. Each matches its recorded SHA-256 from GitLab
revision `9cfc39017e700a28649858f6a902117f9d5e8edd`, despite the existing checkout
being `90f38934040c4790f79b9aada22b50c1597f42dc`. Source was read as text.
No repository scripts, application code or native code ran, and no repository
search by method name was used. Dynamic dispatch such as `send` and
`method_missing` is skipped.

Verification checked every copied catalog field, saved seed chain prefix,
one-hop extension, preserved entrypoint/auth metadata and exact CSV read-back.
These source matches retain the earlier runtime and dispatch limitations.

From this directory, `sha256sum -c SHA256SUMS` verifies the output artifacts.

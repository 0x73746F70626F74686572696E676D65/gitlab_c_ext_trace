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

The operand review at analysis commit
`d7cc6c17b23b0733679196f4fda609dc02c01259` adds `same_value` and `replaced`
only for the **six unknown `params` rows**. All six have `same_value=no` and
`replaced=yes`; nested rows total **0**. The other 14 rows have blank flags.
Authenticated row contents were not returned, parsed or reviewed. An opaque
CSV transformation preserves every original field and row, verified byte for
byte after removing the two appended columns.

Catalog records 82 and 83 point directly into `date_s_strptime` at line 4443
and `datetime_s_strptime` at line 8389 of date 3.5.1's `ext/date/date_core.c`.
Both sites are `argv2[0] = str`: the index operand is literal `0`, and `str`
is the stored value. Both functions assign a default to `str` before the site,
at lines 4433 and 8379, in `case 0` of `switch (argc)`. `replaced=yes` records
the source-visible assignment; it does not assert that the zero-argument branch
executes for this two-argument Ruby call. No nested function was followed.

The cached C file matches the exact package bytes and its SHA-256 is
`c924c97b67cbe87cb1d1f48197547bfd5d0ecc2007bab5788505908a6b744aa5`.
The package SHA-256 matches the saved catalog source manifest. No target code
or repository scripts ran. `summary.json` contains the per-site evidence and
operand counts.

From this directory, `sha256sum -c SHA256SUMS` verifies the output artifacts.

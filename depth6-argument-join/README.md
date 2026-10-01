# Depth-6 argument join

[rows.csv](rows.csv) is a header-only CSV with **0 matches**.
[summary.json](summary.json) records the inputs, frontier decisions and counts
on branch `work` at input commit `67b3b1b190fcbc29fae98615927535638c5adb46`.

The 20 saved depth-5 rows represent five entrypoint chains, all ending in
`Ci::DailyBuildGroupReportResultsFinder#end_date` at line 93 of
`app/finders/ci/daily_build_group_report_results_finder.rb`. Its body contains
`Date.strptime(params[:end_date], DATE_FORMAT_ALLOWED)` and a rescue call to
`Date.current`. Neither provides an additional repository helper body.
`params` is declared by `attr_reader` at line 27; no ordinary source-defined
method body is followed for that accessor. The indexed accessor result has no
established gem receiver. `current` is absent from the date argument catalog.

The existing depth convention counts a followed repository method as one hop;
the terminal gem invocation adds no repository helper hop. The existing
`strptime` associations remain at depth 5. No chain can be extended to a
qualifying depth-6 match within this procedure.

Output auth counts: **authenticated 0, unknown 0, conditional_anonymous 0,
unauthenticated 0**. Source counts: **params 0, literal 0, local 0,
unresolved 0**. Blank sources: **0**.

Only the saved depth-5 seeds and their common frontier were reviewed. The source
file matches the recorded SHA-256 at revision
`9cfc39017e700a28649858f6a902117f9d5e8edd`. Earlier tables remain unchanged.
No repository search by method name, dynamic-dispatch traversal, repository
script execution or target code execution was used.

The CSV retains the join schema and adds `seed_depth5_records` for immediate
seed provenance. From this directory, `sha256sum -c SHA256SUMS` verifies the
output artifacts.

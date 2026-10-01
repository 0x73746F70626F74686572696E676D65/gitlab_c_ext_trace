# Unknown matches with stored call-argument fields

[rows.csv](rows.csv) contains **127 rows**, one for every existing filtered match
whose saved `auth` is `unknown`. [summary.json](summary.json) records input paths,
checksums, source evidence and counts.

Inputs are `gem_receiver_identifier_filter/filtered_matches.csv` and
`static-catalog/entry-argument-sites.csv` on analysis branch `work` at
`493faa0db0fa338040de7d7fde434a0d9723840e`. Only the unknown records were selected
for this review; the anonymous join was not opened or reanalysed. Original record
numbers count the header as record 1. Each saved `argument_table_line` identifies
the existing catalog association; gem, method, argument index and slot are checked
before copying. Repeated matches and input order are preserved.

`gem`, `method`, `argument_index`, `stored_label`, `slot` and `call_depth`
copy the catalog's `gem`, `ruby_method_name`, `argument_index`, `argument_label`,
`slot` and `hop_count`. The saved frontend depth is copied separately as
`call_chain_depth`. Stored auth labels and catalog labels retain their original
meaning.

Source classification reads the recorded argument at its exact index. A direct
`params`, `request` or route-parameter expression, or a visible assignment from
one, gets `params`. A fixed literal, including a same-file constant definition,
gets `literal`. Other identifier-backed local or object values get `local`.
An unassigned method formal uses only the immediate caller in its recorded chain;
a missing corresponding caller gets `unresolved`. Inline-block identifiers are
classified within the recorded file. No repository search by method name or
additional helper/caller traversal is used.

The 127 rows cover eight call sites:

- **71 `value` rows** in `safe_format_helper.rb` and **6 `text` rows** in
  `char_diff.rb` use visible block-local identifiers and get `local`.
- **24 `doc` rows** get `local` from the same-method
  `doc = Nokogiri::XML(svg)` assignment.
- **12 `DATE_FORMAT_ALLOWED` rows** get `literal` from the fixed
  `'%Y-%m-%d'` definition. Their catalogued argument is index 1; the request
  parameter in these calls is index 0.
- **8 `expires_at` rows**, **2 time-coercion `value` rows** and **4
  contribution-analytics `value` rows** get `local` from their single recorded
  caller expressions: `expires_at`, `object['last_health_checked_at']` and
  `start_date_param`. Those callers' upstream origins and other helper bodies
  are outside this review.

Rows in: **127**. Rows written: **127**. Source counts: **params 0, literal 12,
local 115, unresolved 0**. Blank sources: **0**.

The existing GitLab checkout is
`90f38934040c4790f79b9aada22b50c1597f42dc`. All eight source files read match
their stored full-file SHA-256 hashes from recorded revision
`9cfc39017e700a28649858f6a902117f9d5e8edd`.

Verification checked complete unknown-row coverage, catalog-field equality,
recorded argument indices, one-caller references, order and multiplicity, input
hashes and exact output read-back. Source was read as text; no repository scripts
or target code ran.

From this directory, `sha256sum -c SHA256SUMS` verifies the output artifacts.

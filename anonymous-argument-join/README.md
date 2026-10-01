# Anonymous matches with stored call-argument fields

[rows.csv](rows.csv) contains **122 rows**, one for every existing anonymous
filtered record. [summary.json](summary.json) records the input paths, Git SHA,
checksums and counts.

The inputs are `saved-row-provenance/anonymous-filtered.csv.gz`,
`gem_receiver_identifier_filter/filtered_matches.csv` and
`static-catalog/entry-argument-sites.csv`, all from analysis branch `work` at
`ec0048aeb13302abb0d7a11b761d2fbba002028a`. Each saved anonymous record supplies
its existing filtered-record and argument-catalog-record references. Record
numbers include the header as record 1. The join verifies gem, method, argument
index and slot before copying fields, preserving order and repeated matches.

`method`, `argument_index`, `stored_label`, `slot` and `call_depth` copy the
catalog's `ruby_method_name`, `argument_index`, `argument_label`, `slot` and
`hop_count`. Catalog depth counts native helper calls from the registered root.
The saved frontend depth is copied separately as `call_chain_depth`.
Other identity and location fields come from the existing filtered/provenance
rows. In particular, the stored label is independent of the new `source` cell.

The missing GitLab tree was cloned shallow from the official remote at its
latest default-branch commit,
`90f38934040c4790f79b9aada22b50c1597f42dc`. All five referenced files match their
recorded full-file SHA-256 hashes from revision
`9cfc39017e700a28649858f6a902117f9d5e8edd`; the recorded lines still match.

Source annotations were filled from this same 122-row CSV at
`d486bce53c7e4908c6f6c3367a0ad982c1576dbc`. The recorded calls and zero-based
argument expressions were parsed by reading source text. A literal expression
gets `literal`. For an identifier, the last assignment to its exact name in
the same method gets `params` if its RHS is `params`, `request` or a route
parameter, and `local` otherwise. An identifier with no body assignment in
that method gets `unresolved`. No file boundary is crossed.

All 122 argument expressions are identifiers. The 118 rows using `value`,
`field`, `date` or `rich_line` have no assignment to that exact name in the
enclosing method and get `unresolved`. Method and block parameter declarations
are not body assignments; `@rich_line` is a different name from `rich_line`.

The four `text` rows get `local`: `CharDiff#to_html` assigns
`text = ERB::Util.html_escape(text)` on recorded line 50. The revised
same-method rule includes this assignment on the call's line. This records the
assignment's presence; the RHS argument is evaluated before its result is
assigned. Per-location evidence is in `summary.json`.

Rows in: **122**. Rows written: **122**. Source counts: **params 0, local 4,
literal 0, unresolved 118**. Blank sources: **0**.

Verification checked complete anonymous coverage, every recorded catalog
association, copied field equality, row order, retained multiplicity, unchanged
input hashes and exact output read-back. Every non-source CSV field is unchanged.
Source files were read as text; no
repository analysis scripts or target code were run.

From this directory, `sha256sum -c SHA256SUMS` verifies the output artifacts.

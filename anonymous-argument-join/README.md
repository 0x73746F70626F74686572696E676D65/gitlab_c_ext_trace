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

Source labels use only a visible preceding explicit assignment of the argument
in its scope. A method formal or block parameter alone leaves the cell blank.
The five recorded argument names are `value`, `field`, `date`, `rich_line`
and `text`; none has such an assignment. At `char_diff.rb:50`, the assignment
receives the call result after the argument is evaluated. It does not supply
the argument to that same call. No origin was propagated through other calls.

Rows in: **122**. Rows written: **122**. Source counts: **params 0, local 0,
literal 0, unresolved 0**. Blank sources: **122**.

Verification checked complete anonymous coverage, every recorded catalog
association, copied field equality, row order, retained multiplicity, unchanged
input hashes and exact output read-back. Source files were read as text; no
repository analysis scripts or target code were run.

From this directory, `sha256sum -c SHA256SUMS` verifies the output artifacts.

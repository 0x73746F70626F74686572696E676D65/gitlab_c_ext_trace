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

The caller pass starts from this same CSV at
`6012c88dafd8471452fc1d0312bbf0c294a4c5ab` and selects its **118 unresolved
rows**. The four existing `local` rows are retained. For a method parameter,
only the immediately preceding caller in the saved filtered row's `call_chain`
is read. The formal's position identifies the corresponding caller argument;
the catalog's native `argument_index` remains unchanged.

Caller arguments from `params`, `request` or a route parameter get `params`.
Literals get `literal`. A caller identifier assigned from `params` or
`request` gets `params`; other caller expressions get `local`. A missing
corresponding caller remains `unresolved`. No repository search by method name
or further caller/helper traversal is used.

The caller review changes **84 rows**:

- **72 `field` rows become `params`**. The recorded `date_range` caller passes
  `params[:created_after]` or `params[:created_before]` at lines 53/54.
- **8 `date` rows become `local`**. The recorded `context_commits` caller passes
  `context_commits_params[:committed_before]` or
  `context_commits_params[:committed_after]` at lines 194/195. The helper that
  returns `context_commits_params` is outside the one-caller scope.
- **4 `rich_line` rows become `local`**. The recorded `InlineDiffMarker` caller
  passes `rich_line || line` to `super` at line 7. `rich_line` is formal index 1
  of the enclosing initializer, while the saved native argument index is 0.

The chain records method starts rather than exact invocation positions. Both
compatible date invocations in each caller agree on their source category;
the review retains both expressions without choosing an unsupported call site.

**34 `value` rows remain unresolved**. `value` is a `transform_values` block
parameter rather than a `safe_format` method formal. The block invocation is
absent from the saved chain. The three inspected caller files match their
original source-manifest hashes. Per-location expressions, indices, source
hashes and reasons are in `summary.json`.

Rows in: **122**. Rows written: **122**. Source counts: **params 72, local 16,
literal 0, unresolved 34**. Blank sources: **0**.

Verification checked all 118 selected rows against their saved chain references,
complete row coverage, order and multiplicity, unchanged non-source fields,
the four retained resolved labels, input hashes and exact output read-back.
Source files were read as text; no repository scripts or target code ran.

From this directory, `sha256sum -c SHA256SUMS` verifies the output artifacts.

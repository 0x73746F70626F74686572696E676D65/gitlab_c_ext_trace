# Gem receiver and identifier filter

[filtered_matches.csv](filtered_matches.csv) contains the full filtered table.
Its compressed companion contains the same rows. All original columns and auth
labels are unchanged; receiver evidence and the input CSV record number are added.

| Count | Rows |
| --- | ---: |
| Rows in | 1,712,629 |
| Rows kept | 392 |
| Dropped for receiver | 1,712,027 |
| Dropped for literal/non-identifier/empty argument | 210 |
| Anonymous kept | 122 |
| Unknown kept | 127 |

Counts are exclusive: the receiver check runs first. The argument-drop count
includes **40 literals**, **104 empty or splat-obscured positions**, and **66
other non-identifier expressions**. An identifier is required to keep a row;
an expression such as arithmetic or a method call is also rejected. No surviving
receiver-qualified row had a separately recognized size-expression argument.

Anonymous kept combines `unauthenticated` (8) and `conditional_anonymous` (114),
using the existing auth labels. Authenticated kept is 143. The separate
`anonymous_access` field is also preserved verbatim. Counts describe rows; the
392 rows represent 11 distinct file/line/method/argument-expression sites.

## Recorded inputs

The analysis repository is `/workspace/gitlab_c_ext_trace`, branch `work`, at
the requested input commit `ed3b8897982d4b040858cb8c74a9a9d0860d73b1`.

* Match table:
  `/workspace/gitlab_c_ext_trace/depth_limited_name_match/matches.csv.gz`.
* Call-argument table:
  `/workspace/gitlab_c_ext_trace/static-catalog/entry-argument-sites.csv`.
* GitLab tree: `/workspace/gitlab`, unchanged at
  `9cfc39017e700a28649858f6a902117f9d5e8edd`.
* Existing receiver ownership metadata:
  `/workspace/gitlab_c_ext_trace/frontend_gem_api_map/api_catalog.jsonl`, also
  from the requested analysis commit.

`summary.json` records these paths, repository SHAs, and SHA-256 input hashes.
Opened source files are checked against the original walk's recorded hashes
when available. `source_files_read.jsonl` records every Ruby file opened by this
filter, including files opened to check a receiver constant or alias.

## Receiver and argument rules

Only the saved rows are filtered. The recorded file, line, method, argument
index, expression, and final body in the saved call chain locate the Ruby
invocation. Parsing that recorded body recovers its receiver and arguments;
no entrypoint inventory is loaded, no entrypoint is rewalked, and no call graph
is expanded. The existing parser's syntax extractor is reused without invoking
its root, target, or method-lookup traversal.

Receiver namespaces use the existing API ownership metadata. A non-core root
namespace is accepted when all recorded owners associate it with one gem.
Generic Ruby core classes are excluded; named gem-owned subnamespaces can still
be accepted. The exact accepted prefixes and their evidence IDs appear in
`receiver_namespace_manifest.json`. Shared prefixes `Google`, `JSON`, and
`Prism` remain unresolved and are dropped. Ruby versions and deployed extension
activation are not inferred from this older namespace metadata.

`Gem.method` and `Gem::method` are handled equally. A literal constant alias can
resolve to a gem namespace or a gem constructor. Local, instance, class, or
global variables can qualify only through a visible, unique, preceding direct
assignment to a resolved constant or `Constant.new`, including simple alias
chains. Reassignment, conditional bindings, an assignment in another block,
and block-parameter shadowing prevent resolution. `self` is kept only when its
source owner or explicit singleton-method owner resolves to a gem namespace.

Bare method names, unresolved receivers, GitLab wrapper classes, arbitrary
method-return values, inferred model types, parent/mixin-based object types,
and ambiguous aliases are dropped. A receiver attributed to a different gem is
also dropped. Literal constant resolution respects source-visible lexical
bindings and can inspect conventional files for that constant; it performs no
whole-tree content search. This attributes the receiver namespace to the gem;
it does not establish that the specific method dispatch reaches a catalogued
native registration or that a native memory slot receives the Ruby value.

The argument is re-read at the catalogued zero-based index. Local names,
instance/class/global variable names, constants, qualified constants, and
`self` are syntactic identifiers. Literals, empty positions, splat-obscured
positions, size/length calls, arithmetic, constructor calls, and all other
compound expressions are rejected. Identifier values are not propagated:
`DATE_FORMAT_ALLOWED` remains an identifier even if its definition is a string.
The catalog's index and slot are copied unchanged.

The input table lacks byte offsets. When identical names and expressions share
a source line, a row qualifies only if every compatible invocation resolves to
the same row gem and every indexed argument is an identifier. Multiple candidate
receivers and columns are retained together when that check succeeds; mixed or
unresolved candidates are dropped. There are no such ambiguous retained rows
in this output.

## Delivery and verification

* `filtered_matches.csv` and `filtered_matches.csv.gz`: complete retained table.
* `summary.json`: requested counts, argument-drop breakdown, all decision reasons,
  and input provenance.
* `decisions.csv.gz`: one decision per input record, including drop reasons and
  any resolved receiver/gem. `input_row` counts CSV records with header record 1;
  it is not a physical line number in the compressed input.
* `receiver_namespace_manifest.json` and `source_files_read.jsonl`: ownership
  evidence and opened-source hashes.
* `filter.py`, `test_filter.py`, `validate.py`, `validation.json`, `SHA256SUMS`:
  static analysis tooling, checks, and integrity records.

Five parser-fixture checks cover direct constants and `::` calls, aliases and
constructors, missing receivers and unresolved `self`, identifier-only argument
selection, reassignment, block shadowing, cross-block bindings, and ambiguous
same-line calls. The independent output check verifies every decision against
the input record order, every retained original field, unchanged auth labels,
plain/compressed table equality, and all partition/reason counts.

Only source readers, syntax parsing, Git operations, and Python analysis tooling
ran. No Ruby, GitLab, gem, native extension, source snippet, endpoint, or build
hook was executed. No gem or C sources were fetched. The existing GitLab tree
and all original analysis outputs remain unchanged.

With the recorded input files and GitLab tree present, reproduce the filter:

```sh
python gem_receiver_identifier_filter/filter.py
python -m unittest discover -s gem_receiver_identifier_filter -p test_filter.py
python gem_receiver_identifier_filter/validate.py
cd gem_receiver_identifier_filter
sha256sum -c SHA256SUMS
```

The filter verifies that its input bytes match the requested Git commit. Parser
dependencies are the existing `tree-sitter==0.25.2` and `tree-sitter-ruby==0.23.1`.

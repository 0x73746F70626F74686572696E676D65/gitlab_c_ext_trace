# Depth-limited name match from entrypoints

The complete table is [matches.csv.gz](matches.csv.gz). Each row intersects a
Ruby invocation in a walked entrypoint body or GitLab helper with one row of
[entry-argument-sites.csv](../static-catalog/entry-argument-sites.csv), by Ruby
method name. Argument index and slot are copied without reinterpretation.
This is a syntactic name intersection: common names can match several gems,
and a row does not establish the receiver's gem type, deployed reachability,
argument control, or a vulnerability.

| Summary | Count |
| --- | ---: |
| Inventory entrypoints considered | 50,424 |
| Entrypoint bodies walked | 19,435 |
| Entrypoints with matches | 14,277 |
| Match rows | 1,712,629 |
| Anonymous-labeled match rows | 346,088 |
| Unknown-auth match rows | 514,326 |
| Ruby method names with no match | 109 of 158 |
| Call-argument table rows with no match | 217 of 353 |
| Dynamic-dispatch unresolved stops | 693 |
| Other unresolved ordinary-call stops | 822,830 |
| Stops at the depth limit | 72,191 |
| Total stops in walked bodies | 895,714 |
| Unresolved entrypoint body bindings | 30,989 |
| GitLab Ruby files read | 7,726 |

Anonymous-labeled rows combine `unauthenticated` (81,234) and
`conditional_anonymous` (264,854). Auth labels are copied from the inventory;
`unknown` remains unknown. The inventory's separate `anonymous_access` Boolean
is also retained, including false values on error-only records. Authenticated
match rows total 852,215. These are row counts, not distinct routes, calls,
memory operations, or allocations.

## Inputs and source revisions

The analysis repository was checked out on `work` at
`7675bfa2b401cf5097546452d50f2d38a87fbde5`. The remote branch contained the requested
inputs in newer commits, so the clean checkout was fast-forwarded to
`916e4c373c9e1393cfc66895d813fd292a8cd0ed` before analysis.

* Entrypoint inventory: `unauthenticated_entrypoints/entrypoints.json`.
* Call-argument table: `static-catalog/entry-argument-sites.csv`.
* GitLab tree: `/workspace/gitlab`, shallow clone of
  `https://gitlab.com/gitlab-org/gitlab.git`, default branch `master`, at
  `9cfc39017e700a28649858f6a902117f9d5e8edd`. The default-branch HEAD was checked
  before and after cloning and had the same SHA.

The inventory describes GitLab revision
`d75e5afaa21d45bc04139d4a538ea5954be1ef4f`, which differs from the fresh tree.
Output files and lines refer to the fresh tree. Recorded auth labels and handler
bindings remain inventory facts, with no new authentication review or claim
that the older routes still have the same exposure. A missing or ambiguous
binding is retained as unresolved. Grape roots require an exact recorded line,
compatible verb, and compatible literal route suffix; 622 fail that check.

## Walk rules and limits

Each entrypoint starts at its recorded Ruby registration or action source.
Rails action names and recorded GraphQL resolver bindings select a body;
middleware and dedicated health listeners select `call`. GraphQL fields without
a source-defined method remain unresolved. Registration-only, snapshot, proxy,
and WebSocket records without an ordinary Ruby handler binding remain unresolved.
No framework-generated method or callback activation is inferred.

The entrypoint body has depth **0**. Each followed GitLab method adds one hop.
Bodies at depths **0 through 4** are searched for catalogued Ruby invocations;
the terminal name occurrence itself does not add another GitLab helper hop.
The table includes a source witness chain, and one shortest encountered chain
per entrypoint/body is retained. Cycles and repeated bodies are collapsed.

Only source-defined calls are followed: same-owner methods, literal constant
receivers, literal `Constant.new.method` receivers, a uniquely assigned local
from `Constant.new`, and source-resolved parents/mixins. `new` can select a
GitLab `initialize` body. Ordinary bare calls, operators, index calls, and
attribute setters are included. Receiver return types, arbitrary local aliases,
model-generated accessors, dynamic factories, Ruby metaprogramming, deferred
lambda bodies, and external implementations are not resolved. Method bodies
unrelated to the selected entrypoint or followed calls do not contribute rows.
This limited syntactic lookup is not a complete Ruby method-lookup model;
runtime overrides, prepend activation, monkey patches, branches, and loading
conditions are not proven.

`send`, `public_send`, `__send__`, `method_missing`, and interpolated method names
stop their branch and are counted as dynamic unresolved stops. Their target
names and nested branches are not followed. An explicit catalogued name at the
stop can still receive a name row. Unsupported ordinary calls, parser errors,
and depth cutoffs are recorded separately. No whole-tree method-name search or
global source-definition index is used. Additional files are opened only through
recorded source paths and conventional paths for explicit source constants,
parents, or mixins; all opened Ruby files appear in `files_read.jsonl`.

`argument_index` is the table's zero-based Ruby positional index. The table's
slot is a native-site category, copied as catalog metadata; it is not a new
native dataflow finding. The visible Ruby expression is marked `literal`,
`identifier`, `expression`, or `not_visible`. Missing positions and positions
obscured by a splat retain a match but have no visible expression. Arguments
are not substituted through helper calls or traced back to request input.

## Files and verification

* `matches.csv.gz`: complete table, including all required row fields, auth,
  edition, catalog-row reference, expression kind, and source call chain.
* `summary.json`: counts, source SHAs, exact input paths and input hashes, and
  the full list of Ruby method names with no match.
* `methods_with_no_match.csv`: all unmatched call-argument table rows.
* `entrypoints_walked.jsonl.gz`: one record per inventory entrypoint, including
  unresolved bindings and per-entrypoint match/stop counts.
* `unresolved_stops.jsonl.gz`: stops in walked bodies, with locations and chains.
* `files_read.jsonl`: hashes and parser-error status of every opened Ruby file.
* `walk.py`, `test_walk.py`, `validate.py`, `validation.json`, `SHA256SUMS`:
  analysis tooling, parser fixtures, and saved-output integrity checks.

Only Git commands, source readers, Ruby syntax parsing, and Python analysis
tooling ran. No Ruby, GitLab application, endpoint, gem, extension, source
snippet, build hook, or C implementation was executed. No gem or separate C
source was fetched. The Python parser wheels were installed as analysis tooling.

To inspect the complete table without executing target code:

```sh
gzip -cd depth_limited_name_match/matches.csv.gz > /tmp/depth-limited-matches.csv
```

Static reproduction uses the recorded GitLab revision and Python packages
`tree-sitter==0.25.2` and `tree-sitter-ruby==0.23.1`:

```sh
python depth_limited_name_match/walk.py --source /workspace/gitlab
python -m unittest discover -s depth_limited_name_match -p test_walk.py
python depth_limited_name_match/validate.py
cd depth_limited_name_match
sha256sum -c SHA256SUMS
```

The four parser-fixture checks cover method scope, bare calls, dynamic branch
stopping, setters/index arguments, direct receiver bindings, and expression
classification, assignment receivers, and `super`. The independent saved-output check verifies every match against
its exact catalog row and auth label, the depth bound and chain length, complete
inventory accounting, no-match partitions, and all stop counts. It does not
establish runtime reachability or full static-search recall.

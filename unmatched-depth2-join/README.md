# Previously unmatched entrypoints through depth 2

[rows.csv](rows.csv) contains **55 catalog associations** from **25 entrypoints**
absent from the existing filtered, depth-5 and depth-6 tables at analysis commit
`fbfc8d619d083daf4668867c6c63dbfec98466c9`.

| Auth label | params | literal | local | unresolved | Total |
| --- | ---: | ---: | ---: | ---: | ---: |
| unauthenticated | 0 | 8 | 0 | 8 | 16 |
| conditional_anonymous | 0 | 0 | 2 | 0 | 2 |
| unknown | 4 | 0 | 21 | 12 | 37 |
| authenticated | 0 | 0 | 0 | 0 | 0 |
| Total | 4 | 8 | 23 | 20 | 55 |

The inventory has 25,109 anonymous-labeled or unknown entries. Excluding 181
such entries already present in the three tables leaves **24,928 eligible IDs**.
The union of all existing IDs, including authenticated ones, has 312 members.

The saved static walk provides named-call chains and receiver decisions.
Selecting its paths at depths **0 through 2** yields the new associations;
31 rows occur at depth 0 and 24 at depth 1. No depth-2 row qualifies.
Entrypoint bodies have depth 0; each followed repository method adds one hop.
The terminal gem call adds no helper hop. Dynamic dispatch such as `send` and
`method_missing` is skipped. The `end_date` chains are not extended, and earlier
tables remain unchanged.

[entrypoints-considered.jsonl.gz](entrypoints-considered.jsonl.gz) accounts for
all eligible IDs, preserving their saved root binding status and reporting
output row counts. **9,775** have recorded handler bindings and **15,153**
have unresolved bindings. Coverage inherits those root gaps, unresolved calls
and conservative receiver rules. Source inspection rereads the retained sites
and immediate callers; the earlier walker and parser are not rerun.

The 55 rows cover seven Ruby sites in eight source files. All eight files match
their full-file hashes at saved revision
`9cfc39017e700a28649858f6a902117f9d5e8edd`.
[source-files.jsonl](source-files.jsonl) records them.

Four direct `params[:expires_at]` arguments get `params`. Eight fixed
`encoding: 'UTF-8'` option arguments get `literal`. The 23 local rows read
object or helper values: diff text, label/milestone titles,
`permitted_params[:date]` and serialized checkpoints. Source is bounded to the
call and one recorded caller; another helper's origin is not propagated.
Twenty saved catalog positions are absent from the visible call argument list
and get `unresolved`. Ruby and C defaults are not inferred.

The catalog's gem, method, index, stored label, slot and native hop count are
copied unchanged. `call_chain_depth` records the separate frontend depth.
`name_match_record` identifies the existing source-witness CSV record, counting
the header as record 1. A gem namespace/method association, including a generic
`new` match, does not prove dispatch to a specific native registration.

[summary.json](summary.json) contains the exact input paths/hashes, per-site
source evidence, counts and validation. Auth labels remain inventory facts.
No target code or repository scripts ran. From this directory,
`sha256sum -c SHA256SUMS` verifies the output artifacts.

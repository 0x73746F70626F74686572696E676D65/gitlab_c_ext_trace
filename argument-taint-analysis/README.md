# Gem argument to native memory operand tracing

This directory contains a scripted static taint census of the sources referenced
by the `work` branch at `2b0bc9e9229755b1f7a9233c8cd67f75d1f83af5`.
Published, version-pinned gem archives and every recorded native repository
commit are restored as inert source files. Gitlinks are fetched at their recorded
commits. No gem code, extension, build hook, saved analysis script, or serialized
Python object is executed. Published packages and upstream repositories remain
separate source variants; identical API names are deduplicated in the census.

## Results

The committed delivery is an **interrupted checkpoint snapshot**, not a closed
census. The source recovery and harness are preserved. The intact checkpoint
contains 177,418 function evaluations and still has pending updates. No fresh
tracing is needed to export its existing argument-to-memory witnesses.

The snapshot contains 63,076 flow records for 1,719 API identities across 65 gems
(3,352 identities when versions count separately). Its native primitive subset
contains 33,080 flow records for 1,012 API identities. The deepest saved witness
has 78 call bindings. These are saved checkpoint counts; 19,653 function updates
were still pending.

## Per-chain archive

`packages/gem-api-memory-flow-chains.tar.gz` contains a directory with one JSON
file for each of the 63,076 saved flow records. Every file embeds the ordered
chain and its source paths, one-based lines, original source-line text, SHA256s,
registration and C entrypoint citations, and Git commit permalinks where available.
The original record's event-ID vector can be reconstructed from `flow[*].id`.
All other original fields are preserved. `index.jsonl` maps API names to chain
files; the archive's `SHA256SUMS` checks each payload. It retains the interrupted
checkpoint status from the input snapshot.

The adjacent `.tar.gz.json` records the archive digest and input identities;
`.tar.gz.validation.json` records checks of every chain, binding and checksum.

```sh
python argument-taint-analysis/scripts/package_flows.py \
  --results argument-taint-analysis/results \
  --archive argument-taint-analysis/packages/gem-api-memory-flow-chains.tar.gz
python argument-taint-analysis/scripts/verify_flow_package.py \
  argument-taint-analysis/packages/gem-api-memory-flow-chains.tar.gz
```

## Snapshot JSON files

- `results/gem-api-memory-flow-apis.json`: the API identities with saved flows.
- `results/gem-api-memory-flows/part-*.jsonl`: every saved explicit API argument flow
  into a memory operand, with call-site locations, parameter indices/expressions
  when recovered, and event-chain references. Ordinary field stores are excluded.
- `results/gem-api-native-memory-flows/part-*.jsonl`: the native primitive subset.
- `results/gem-api-memory-flow-files.json`: ordered JSONL parts, counts and
  digests; each part is below 32 MiB to keep the commit pushable.
- `results/gem-api-memory-flow-events.jsonl`: the cited events, bindings and
  source identities; join each flow's `event_chain` to these event IDs.
- `results/gem-api-memory-flow-snapshot.json`: counts, pending-work status and
  the exact checkpoint/source/harness identities.
- `results/gem-api-memory-flow-SHA256SUMS`: digests of the delivery files and parts.

Export the intact checkpoint without resuming analysis:

```sh
python argument-taint-analysis/scripts/export_checkpoint.py \
  --repo /workspace/gitlab_c_ext_trace-work \
  --checkpoint /workspace/scratch/gem-argument-memory-audit/operand-hash1 \
  --index /workspace/scratch/gem-argument-memory-audit/all-sources-index.json \
  --manifest /workspace/gitlab_c_ext_trace-work/argument-taint-analysis/results/source-manifest.json \
  --native-data /workspace/scratch/gem-argument-memory-audit/native \
  --out /workspace/gitlab_c_ext_trace-work/argument-taint-analysis/results
```

The following files are produced by the full-census pipeline after closure;
they are not completion claims for this snapshot:

- `results/apis-primary-lock.csv`: APIs at the versions in the current saved lockfile.
- `results/apis.csv`: the set across every restored version referenced by saved native registrations.
- `results/apis-unique.csv`: that set with repeated versions combined into one API name.
- `results/apis-native-low-level-operations.csv`: allocation, copying, filling, reads/comparisons,
  release and formatting operations, excluding APIs supported only by Ruby
  coercion/container models or implicit stores. The other scope CSVs retain
  named-function and field-store-inclusive views of the same computed facts.
- `results/witnesses.jsonl`: argument positions, memory operand roles, source hashes,
  and event chains. A representative shortest derivation is retained per formal
  origin, operation category, and operand role; this is an API census rather than
  enumeration of every possible path.
- `results/events.jsonl` and `results/witness-functions.jsonl`: actual/formal
  bindings, assignments, returns, operations, and expanded C function bodies.
- `results/callback-table-bindings.jsonl` and `results/function-pointer-arguments.jsonl`:
  concrete table/global hook declarations, their source hashes and locations,
  and function pointer bindings, including pointers to modeled memory primitives.
- `results/api-argument-memory-operands.csv`: a flat API/argument/operation/operand
  list with source locations, hashes, call depths and event-chain references.
- `results/native-api-argument-memory-operands.jsonl`: native-operation records
  with the registered C entrypoint and full event chain embedded in each record.
- `results/counts-by-gem.csv`: primary-lock, all-version and version-deduplicated counts.
- `results/counts-by-gem-native-low-level-operations.csv`: those counts restricted
  to native allocation, copying, filling, reads/comparisons, release and formatting.
- `results/roots.jsonl`: every discovered or reconciled API root, including entries
  with no explicit arguments, no witness, or an unresolved target.
- `results/saved-registration-reconciliation.jsonl`: every saved native registration
  and its matching fresh source root.
- `results/all-scavenged-registration-reconciliation.jsonl`: the union of saved
  registration records, including the newer checkpoint's additional aliases.
- `results/scavenged-files.jsonl` and `results/scavenged-native-evidence.jsonl`:
  archive/file inventory and content-addressed retained evidence. Old graph
  connectivity is not promoted into a new argument-flow witness.
- `results/source-manifest.json`, `validation.json`, `repeat-validation.json`, and
  `summary.json`: pinned bytes, checks, replay digests, and counts.
- `results/published-source-manifest.json`, `git-source-manifest.json`, and
  `git-source-recovery.json`: the 136 published packages, 146 recorded repositories,
  84 pinned gitlinks, six additional vendor checkouts and their source identities.
  The combined manifest contains 44,792 source files and 81 gem names. C code embedded in retained
  grammar/template files is also parsed; those paths remain visible in the ledgers.

API identities include gem, version, recorded receiver, Ruby method name and
instance/singleton form. Aliases count as distinct names. Generated class
registration templates count once per recorded receiver, not once per runtime
instance or generated schema class. The wider restored corpus retains the
original tests/examples/vendor and sibling extension source scope; the root and
file ledgers expose each source path. A repository variant is version-associated
upstream evidence rather than a claim that every retained file ships in the
published gem or loads by default.

## Flow definition

A source is an explicit Ruby positional argument of a registered C method.
Receivers, argument counts and argumentless allocator hooks are excluded as root
sources. Variadic argument vectors and `rb_scan_args` extraction are mapped to
positions; `*` denotes a variable position within the explicit argument vector.

Taint can change value through arithmetic, accessors, conversion, object-content
reads, assignments, returns and output pointers. Concrete function pointers,
callback tables and documented Ruby callback ABIs are followed. Local reassignments
and shadowing kill the overwritten dependency. Control-only influence is excluded.
Interprocedural summaries join possible effects across recursion depths; they
retain previously discovered effects as later callback/alias information arrives.

Memory operation models are enumerated in `memory-operation-models.json`:
allocation/resizing/release, memory/string copying, filling, reads/comparisons and buffer formatting,
Ruby buffer/container constructors and mutators, conditional numeric conversion
and coercion, symbol interning, wrapper/class construction, standard C++ memory
algorithms, explicit buffer stores and stack array extents/initializers.
Ordinary struct field stores are retained separately and do not by themselves
put an API in `apis.csv`. A constructor/conversion witness can be conditional;
the count concerns argument flow into the modeled operation's operand rather
than fresh allocation on every invocation.

The analyzer summarizes all reachable functions and solves returns, output
memory, callback bindings and sink dependencies to a fixed point. There is no
call-depth limit or per-root traversal budget. Recursion uses finite parameter,
allocation-site and field abstractions; witness strings retain their shortest
established derivation instead of growing through repeated cycles. C calls may
cross gem boundaries only through explicitly recorded locked gem dependencies.
The initial pass schedules callees before callers. Later recursive/callback
updates wait behind pending work, coalescing changes until closure. C function bodies hidden by file-level parser recovery
are located by balanced tokens and parsed independently. C registration casts
are resolved only when their symbol identifies an indexed function; distinct
alias argument ABIs retain separate binding identities. Block capture through
`rb_scan_args` is excluded from the positional argument sources.

This is a conservative static **may-data-flow set** under the listed models.
Branches are joined, pointer fields use a finite abstraction, and preprocessing
alternatives are retained. A witness is not a runtime path-feasibility proof.
Unknown external returns are not tainted automatically. Unmodeled calls, macro
collisions, parser diagnostics and unresolved roots are retained in the ledgers;
`no_witness` is not a proof that an API has no memory effect.

## Reproduce

Install the pinned parser dependencies into a Python virtual environment, then run:

```sh
python -m pip install -r argument-taint-analysis/scripts/requirements.txt
python argument-taint-analysis/scripts/run.py \
  --repo /workspace/gitlab_c_ext_trace-work \
  --cache /workspace/scratch/gem-argument-memory-audit \
  --verify-repeat
```

The driver restores published packages and recorded Git commits/submodules,
scavenges every work-tree data container, runs the
semantic fixtures, traces to a fixed point, validates the source/operand joins,
and repeats tracing with another Python hash seed. Package digests are frozen
in the source manifest. All 5,773 current catalogue source hashes are checked
against restored package bytes. Cached function indexes contain inert JSON.
Delete a cached index to rebuild it from the pinned sources.

The historical byte reconciliation restored 23,579 of 23,628 saved file hashes.
The remaining ledger entries are 46 grammar inputs in Ruby wrapper packages
and three older Nokogiri vendor files whose saved bytes differ from the freshly
restored recorded source. Those discrepancies are preserved in
`saved-source-byte-reconciliation.jsonl`; they are not silently treated as
matching source. All 146 recorded repository recoveries succeeded.

The semantic fixtures cover deep return chains, recursion, overwrites, shadowing,
control-only paths, output pointers, local buffer addresses, array initializers,
symbol interning, macro generation/pasting/stringification/continuations,
argument extraction, unknown returns, callback ABIs/tables, wrapper/coercion
contracts, builtin memory calls, and pointer cycles.
Additional fixtures cover parser recovery, cast registrations, alias ABI
variants and block/positional argument separation.
Recursive buffer permutations verify that alternating dependencies join to a
finite set rather than oscillating between invocation depths.
Thirty-nine fixtures also verify callback shadowing, file-local static hook bindings,
global allocator hooks and pointers to external memory primitives. Inert index
loading is incremental; line maps retain only line transitions without changing
source locations. Callback caches are keyed to the index, manifest, locked
dependencies, parser requirements and harness code.
Worklist checkpoints use inert JSON, are replaced atomically, and require matching
source, root, parser and analyzer hashes before resuming. They preserve event IDs,
summaries, callback inputs and the pending worklist. An interruption does not
require restarting completed function evaluations. Join operations avoid sorting
long witness paths; repeated memory reads are cached until a write or branch
restore invalidates them. The fixture suite checks checkpoint equivalence and
cache invalidation through overwrites and branches.
Reference substitution is cached within each call application. The recursive
scheduler benchmark reaches identical summaries and events in 72 evaluations,
versus 2,348 with the previous priority policy. Event identities are SHA256 hashes
of their source and binding content, independent of evaluation order.
Stack objects retain local identities, and symbolic field reads bind to actual
field contents across helper calls. A fixture verifies argument-to-copy flow
through a stack struct and its removal after known field overwrites.
File-local functions and hooks in headers require transitive include visibility;
unrelated vendor headers do not become callees merely because a C symbol matches.
Literal conditional includes are retained, with equally close header alternatives
and includes outside the restored corpus recorded in `include-boundaries.jsonl`.
The fixtures check both transitive visibility and an unrelated-header negative case.
Definite C prototypes constrain calls to their argument counts, including callback
calls. A comparator called with two operands cannot become a four-argument
allocator merely because the pointer abstraction has seen that allocator elsewhere.
Variadic and unresolved macro signatures retain their alternatives. Rejected
bindings are recorded in `call-abi-boundaries.jsonl`.
The structural checks cover every source file, root, event, argument position,
actual/formal binding and reported memory operand. These checks establish
reproducibility and internal consistency rather than whole-program soundness.

Field values returned by helpers preserve the referenced pointer, and dynamic
stack-buffer offsets retain argument-derived address dependencies. Helper output
effects bind to the call input state before writes are applied. Fixtures cover
these patterns and fixed-address/overwritten-field negative cases.

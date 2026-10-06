# Ruby call sites connected to native memory operands

This analysis joins the 63,076 saved C argument-to-memory witnesses to static Ruby call sites in the canonical `gitlab-org/gitlab` repository at commit `c65829f5f51e046dc09fb16a66545ff099d58a5c`. It uses that checkout's `Gemfile.lock`. All tracked `.rb`, `.rake`, and `.ru` files are scanned; application and test/fixture counts are separate. Embedded Ruby in template languages is outside this source inventory.

Each file under `results/callsites/` represents one physical GitLab Ruby call site. A record exists only when receiver type/owner and method lookup resolve, and an actual Ruby argument occupies the position that reaches a saved C memory-operation operand. Omitted arguments are excluded; unknown splats cannot establish positions after them. Aliases, inheritance, overrides, assignments, helper returns and parameter bindings participate in a worklist fixed point with no call-depth cap. Ruby gem wrappers are followed with explicit formal-to-actual argument bindings. Receiver evidence and wrapper edges cite source lines, hashes and pinned provenance. Static receiver resolution is a source-analysis conclusion, not execution evidence.

`native_flows` records the supplied Ruby argument, the native API/argument position and the matching `c_flow_ids`. Join each ID to `results/c-flow-library/*.jsonl` for the original native registration, C entry, memory call-site file/line/hash, operand parameters and saved chain event IDs. The same IDs are the filenames of complete witness JSONs in `argument-taint-analysis/packages/gem-api-memory-flow-chains.tar.gz`. The native input remains the previously exported interrupted-checkpoint snapshot; this Ruby run does not restart or claim completion of the original C census.

`results/flow-coverage.jsonl` accounts for every input C witness, including witnesses without a verified Ruby call site and inactive versions/unresolved native owners. Rejected candidate sites appear in `receiver-or-argument-boundaries.jsonl`. `files.jsonl` inventories source hashes and parser-error flags. `summary.json`, `validation.json` and `semantic-tests.log` record counts and checks.

## Recorded result

The worklist closed after 586,946 function evaluations. The output contains **2,387** unique callsite JSONs: **519** application calls and **1,868** test/fixture calls. Their **4,691** argument bindings reference **1,149** original C witnesses across **110** native API groups. `validation.json` confirms all 55,710 GitLab/gem source-file hashes, exact Ruby call expressions, independently parsed argument expressions/positions and joins to every original C witness. All 23 semantic fixtures pass; their full evidence is identical under two Python hash seeds.

The fresh lockfile matches 26,455 normalized C witness records. The coverage ledger accounts for all 63,076 inputs, distinguishing matches from active witnesses without verified callers and inactive versions/unresolved owners. Four source files have parser errors; none contributes an accepted call site. Receiver types are statically inferred; unknown return values retain input taint without being assigned a concrete receiver class.

`packages/gitlab-gem-api-memory-callsites.tar.gz` contains the 2,387 individual JSONs plus shared C-flow, coverage and provenance tables. Each binding also embeds its memory call-site citations and operand parameters. Large rejected-candidate JSONL data is split into files under 32 MiB; `results/jsonl-parts.json` records their hashes. `results/api-callsite-map.jsonl` indexes matches by native API.

## Reproduction

Install the pinned Python parser dependencies in `scripts/requirements.txt`. Restore wrapper sources from checksum-verified published gem archives with `restore_wrappers.py --manifest results/gem-ruby-source-manifest.json --destination /path/to/wrappers --packages /path/to/gem-cache`. This reads archives as data and does not execute gem code. The manifest is updated with local source paths. The native catalog inputs needed for normalization are included in `inputs/native/`.

Use a GitLab checkout at the recorded commit containing all tracked `.rb`, `.rake`, `.ru` files and `Gemfile.lock`. Run `PYTHON_BIN=/path/to/python scripts/run.sh /path/to/gitlab`. Source hashes and witness hashes are independently checked by `validate.py`. `package_results.py` creates the stable tar.gz of individual callsite JSONs and shared lookup/provenance files.

The matcher does not use method-name matches as receiver proof. Other installed gems' C registrations do not replace a separately defined Ruby wrapper merely because a namespace/method name coincides. Unresolved receiver types, conflicting dispatch targets and missing flow arguments do not produce accepted records.

## Sources for application and library review

`packages/gitlab-app-lib-gem-memory-review-sources.tar.gz` selects only saved
callsites under `app/`, `lib/`, `ee/app/`, and `ee/lib/`: **374 callsites** and
their **900 C witnesses**, across **21 gems** and **40 published/Git source
variants**. It contains full original files, preserving line numbers and hashes,
rather than extracting function snippets. The 1,432 source files include all
171 files cited by the selected C chains, cited Ruby wrapper files, and
resolvable local include dependencies. Unrelated C translation units are omitted.

Inside the archive, `sources/` holds the source files, `chains/` the complete
selected C witness JSONs, and `callsites/` the selected Ruby callsite JSONs.
`flow-source-map.jsonl` connects them. `source-packages.json` records exact
published versions/package hashes and upstream commits, including recorded
gitlinks/vendor provenance. `source-files.jsonl` records each file's SHA256,
original path and inclusion reason. `include-dependencies.jsonl` records
resolved, external/missing and ambiguous include references; the source slice
is intended for review, not as a buildable checkout. It preserves the original
saved C snapshot status and does not run new tracing.

Recreate the package from the restored source paths in the existing manifests:

```sh
python ruby-callsite-analysis/scripts/package_review_sources.py \
  --archive ruby-callsite-analysis/packages/gitlab-app-lib-gem-memory-review-sources.tar.gz
```

The adjacent `.tar.gz.json` records scope, counts, input hashes, the archive
digest, and verification of all packaged bytes and source citations.

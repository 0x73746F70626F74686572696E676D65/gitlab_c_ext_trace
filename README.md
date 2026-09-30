# GitLab static native results and semantic audit

**The end-to-end path counts are candidates, not established user reachability.** The initial seeded source review of 80 frozen v2 chains found **59 contradicted, 14 conditionally supported, and 7 unresolved**. Errors include ignored Ruby overrides and argument/branch combinations that cannot follow the reported chain. No application, extension, endpoint or build hook was run.

Start with [PATH_AUDIT.txt](PATH_AUDIT.txt). Deterministic layer denominators are in [COVERAGE_FUNNEL.txt](COVERAGE_FUNNEL.txt) and the compact [coverage tables/scripts archive](gitlab-layer-coverage.tar.gz). Primary memory-call candidates: **29,108 → 6,707 with native-registration graph paths → CE497 / EE504 frontend candidate sites**. These are graph-discovery counters, not accuracy or recall. The small [audit archive](gitlab-path-audit.tar.gz) is **1,164,037 bytes** and contains samples, per-hop verdicts/evidence, coverage reviews, methodology, schemas and reproducible scripts. Weighted estimates have very wide conservative uncertainty intervals; neither a precise runtime accuracy percentage nor global path recall is established.

## Start here: compact current input-flow evidence

[CURRENT_INPUT_FLOWS.tar.gz](CURRENT_INPUT_FLOWS.tar.gz) (**686,941 bytes**; [index](CURRENT_INPUT_FLOWS_INDEX.txt)) contains the current overview CSV, all **20 reference records with full recipes**, selected source evidence, independent reviews and schemas. Inspect the current input-flow findings without downloading earlier analysis archives.

The main scope has **17 conditional terminal-flow records, two partials, five native sites and four mechanisms**. A separate **one-flow libyaml-version-conditioned model** overlaps the CI-lint partial; it is not primary or deployed coverage. Records are not independent routes. The [middleware delta](gitlab-c-ext-json-validation.tar.gz) (**61,149 bytes**; [index](JSON_VALIDATION_INDEX.txt)) adds the CE/EE uncompressed JSON-validation phase on the existing collect-events route family, reusing the Oj site. Its selected **10 MiB check follows body reading and precedes native parsing**; generic zero disables that size check. No authentication-bypass, all-routes, runtime or vulnerability claim.

The [BCrypt companion](gitlab-c-ext-passkey-bcrypt.tar.gz) (**57,302 bytes**; [index](PASSKEY_BCRYPT_INDEX.txt)) adds the existing passkey route's current-password callback: request String content reaches the native freezing constructor before password-match outcome. Its copy effect requires an admitted authenticated User, a valid stored BCrypt hash, blank pepper and an unfrozen embedded/embeddable effective key. The selected dummy has nine bytes; the minimum is eight and the wrapper cap is 72. No actual credentials were inspected or executed, and no new external route is counted. Corrected evidence spans, callback invocation proof and independent reviews are retained.

The broad graph remains iteration6: **119 candidates, 24,070 partials and 14,310 conditional exclusions**. Input-flow recipes are a separately reviewed, deliberately bounded subset. Sources remain local and prior history is preserved.

## YAML evidence with separate external-library assumptions

The [YAML/Psych companion](gitlab-c-ext-yaml-psych.tar.gz) (**79,100 bytes**; [index](YAML_PSYCH_INDEX.txt)) records a CI-lint request-content prefix. Its primary path remains **partial** because the linked libyaml version is unpinned. A separate, explicitly auxiliary libyaml 0.2.5 source model conditionally traces a selected scalar's content and length into the existing Psych String-constructor site. It does not establish the deployed library or add primary gem coverage.

The layered ledger has **14 main conditional records and two partials**, still **four main conditional sites/three mechanisms**, plus **one separately version-conditioned auxiliary flow/site**. The new partial and auxiliary continuation describe the same CI-lint request case. All earlier snapshots remain unchanged; the broad iteration6 graph is unchanged.

## Reviewed JSON request-input evidence

The [JSON request-flow companion](gitlab-c-ext-json-request-flow.tar.gz) (**91,776 bytes**; [index](JSON_REQUEST_FLOW_INDEX.txt)) extends the separate conditional input ledger to **14 terminal-flow records plus one partial**, covering **four native sites and three mechanisms**. The new Rails parsing phase reuses the existing passkeys route: it adds no external route. Under the reviewed source conditions, request string bytes determine a JSON parser's buffer-capacity argument and pre-escape prefix-copy length. Capacity is not exact heap consumption.

Independent review checks the complete route/framework/native chain, including parameter-cache behavior, parser backend and action-callback ordering. Outer middleware admission and matching backend/runtime remain conditions; this is not a runtime, unauthenticated-reachability or vulnerability claim. A separate six-path review finds VersionSorter arguments derive from persisted records selected by the request; no direct request-byte/count flow was established, and pagination occurs after sorting. The iteration6 broad graph below is unchanged.

## Latest: iterations 5/6

The [new compact delta](gitlab-c-ext-iteration5-6.tar.gz) (**17,581,849 bytes**; [index](ITERATION5_6_INDEX.txt)) preserves all **38,499** baseline records while applying source-backed branch, registration-activation and deferred-callback constraints. The latest overlay has **119 candidates, 24,070 partial paths and 14,310 conditional exclusions**. No source trees are uploaded.

Rechecking the earlier 151-record census now leaves **99 conditionally source-supported candidates plus 20 dependent on unreviewed ICU contracts**, covering **43 profile-specific entrypoints and 42 physical sites**. All six known census contradictions are excluded under explicit initialization/header contracts; 26 unresolved witnesses are partial. This is **development reuse of the census**, not fresh holdout accuracy. Candidate status does not establish runtime feasibility or input control. The separate request-flow ledger remains **12 conditional records, eight frontend cases, two native mechanisms/sites, plus one partial continuation**.

The delta contains full per-path decisions, source evidence, tests, independent reviews and reproducible scripts. Earlier archives and history remain intact. Source versions, deployed initialization, backend activation, external contracts and unresolved calls remain material limitations.

## Bounded controller callback coverage

[Direct callback evidence](gitlab-c-ext-direct-callbacks.tar.gz) (**4,328,412 bytes**; [index](DIRECT_CALLBACKS_INDEX.txt)) adds **1,754 partial invocation edges** (912 CE / 842 EE), retaining all 96,171 omission/unresolved rows. The fresh 24-edge independent review supports each stated declaration/own-method relation; activation remains unresolved for every sampled edge. The deliberately nonuniform sample supplies no population precision estimate. These are partial edges, not new complete paths or input-flow records.

## Preserved iteration3 candidate census and input flows

The [census and flow companion](gitlab-c-ext-census-and-flows.tar.gz) (**5,470,414 bytes**; [index](CENSUS_AND_FLOWS_INDEX.txt)) independently reviews every one of frozen iteration3's **151 surviving candidates**, covering **52 profile-specific entrypoints and 51 distinct physical sites**. Results are **99 conditionally source-supported**, **20 dependent on unreviewed ICU contracts**, **26 otherwise unresolved**, and **6 contradicted**. These are disjoint path counts; distinct entrypoint/site sets overlap. Reviewer judgments and uncertainty are retained, including one disagreement among eight blind duplicate reviews. There is no sampling uncertainty for this selected census, but it is not a runtime accuracy estimate or global recall measurement.

This preserved reference ledger has **12 conditional request-to-memory-argument records plus one partial**, covering eight frontend cases in CE/EE controllers, middleware, Grape and GraphQL. They still represent only **two native influence mechanisms and two physical sites**: JSON-key content/derived length and compressed-chunk content/derived length. Authentication, version, encoding, callback/cache and branch conditions remain explicit. A conversion-site call can also be nonallocating: seven census paths share one `LONG2NUM(sf)` site whose valid nanosecond argument fits an immediate integer. No site count implies fresh allocation, arbitrary input control or vulnerability.

This archive preserves the audited iteration3 population and adds zero-path-classification-change iteration4 binding evidence. Later repairs are published separately below their own immutable revisions. Extract beside the prior V3 and iteration3 companions; their archives and source versions remain unchanged.

## Preserved iteration3

[Iteration3 delta](gitlab-c-ext-iteration3.tar.gz) (**10,593,149 bytes**; [index](ITERATION3_INDEX.txt)) retains **151 candidates**, **24,074 partial paths**, and **14,274 rejected paths** across the separate CE/EE profiles. Of the previous candidates, 112 were rejected by new source-argument guards and 1,870 became partial because their guards/transfers remain unresolved. Withholding uncertain chains is not proof of improved coverage.

The fresh 20-path holdout found one conditionally supported survivor, 18 partial paths, and one correct rejection; no supported sampled path was rejected. In the first holdout's five previously contradicted survivors, two now have detected contradictions and three remain partial. The two previously unresolved survivors also remain partial. H002 is rejected by an earlier absent-key guard, not by detection of its separate JWT issue. No population precision estimate follows from these novelty samples.

The reference ledger now contains **nine conditional input-argument records** across five source-case families and **two native sites**, plus one partial decompression record. Ruby3.3.11 source supports narrow constructor/ASCII-conversion contracts; matching-runtime, authentication and branch conditions remain. No runtime execution, unconditional allocation or vulnerability claim. Extract this delta alongside the earlier V3 companion; earlier archives and frozen datasets remain unchanged.

## Iterative repairs and request argument traces

The [V3 companion](gitlab-c-ext-v3.tar.gz) (21,842,757 bytes; see [index](V3_INDEX.txt)) adds conservative method-lookup, deferred-execution and argument/branch repairs. Across the two separate profiles, the overlay retains **2,133 candidates**, marks **22,459 partial**, and rejects **13,907** baseline paths. Surviving candidates still include known false positives; these are not verified routes. Original sources, datasets and history remain unchanged.

Four independently reviewed conditional request-to-memory records cover two mechanisms in CE and EE: JSON key content/derived length and compressed input content/derived chunk length. They explicitly retain authentication, branch and external Ruby-core model assumptions. One decompression continuation remains partial. Input influence is not a vulnerability claim. Route/super/closure coverage additions remain separate from complete path counts. The archive includes evidence, scripts, tests, schemas and an independent heldout review; synthetic and integrity checks are not semantic accuracy estimates.

```sh
sha256sum -c SHA256SUMS
tar -xzf gitlab-c-ext-v3.tar.gz
```

## Frozen datasets audited

Dataset identity: `97267dd258e01a46620e45d398eee914e53c46e431bae5b4ff5f1354bab1a849`.

| Profile | Candidate paths | Distinct entrypoints with paths | Distinct candidate primitive sites |
|---|---:|---:|---:|
| CE | 15,068 | 151 / 5,814 examined | 540 |
| Full EE mirror | 23,431 | 246 / 11,264 examined | 549 |

These profiles are separate coherent source snapshots. The full frozen v2 results are **103,374,544 bytes compressed**, split into three parts (40 MiB, 40 MiB, 19,488,464 bytes). Every retained complete/partial/candidate path row is included, with normalized hops, selected support records, source manifests, schemas and scripts. Full source trees and full Ruby AST/call dumps remain local, not uploaded. The graph remains unchanged after sampling; semantic audit verdicts are an overlay. The generator label `complete_source_evidenced_static_witness` does not certify accuracy.

```sh
git clone --depth 1 --branch results-20260930 https://github.com/0x73746F70626F74686572696E676D65/gitlab_c_ext_trace.git
cd gitlab_c_ext_trace
sha256sum -c SHA256SUMS
tar -xzf gitlab-path-audit.tar.gz
cat gitlab-frozen-v2-path-results.tar.xz.part01 gitlab-frozen-v2-path-results.tar.xz.part02 gitlab-frozen-v2-path-results.tar.xz.part03 > gitlab-frozen-v2-path-results.tar.xz
sha256sum -c FROZEN_V2_ARCHIVE_SHA256SUMS
tar -xJf gitlab-frozen-v2-path-results.tar.xz
```

Start full results at `corrected-results/CORRECTED_INDEX.txt` and `corrected-results/audit/end_to_end_20260930/RESULTS.txt`. Profile counts and breakdowns are under `profiles/{ce,ee}/reports/frontend_counts_v2.json`. Files named “corrected” repair earlier exposure/dispatch bookkeeping; the subsequent audit still found semantic defects. They are not an accuracy-certified revision.

## What coverage means

742/820 primary locked entries have accepted version-associated sources; 78 have documented blockers. The independent production Ruby filter covers 12,489/12,489 CE and 23,088/23,088 EE tracked files, but excludes some vendored/generated/embedded source. File coverage is not call-graph recall. In 24 no-complete-path reviews, six omitted links were found, seven had no additional miss within the stated bounds, and eleven were unresolved. Callback, `super`, route namespace, dynamic dispatch, source, parser and traversal gaps remain.

The analysis retains one shortest encountered Ruby witness per entrypoint/registration and representative C tails, not all paths. New Ruby exploration is capped at depth 8 and 256 methods per entrypoint; reused suffixes may be longer. CE349/EE665 entrypoints hit bounds. Repeated-method cycles collapse. Conditional allocation/conversion and stack arrays are included; a listed primitive need not allocate on every invocation. Runtime feasibility, authorization and user input control are unproven.

CE source: GitHub `gitlabhq/gitlabhq` master `8d0e57e5f49543c53614b299aef70f7e5bb916ac`, retrieved 2026-09-30 03:07:55 UTC. EE source: `aro-local-test-2/kg-size-gitlab-2` main `27d0646f9b00468d5863549115dababa56334923`, asserting upstream `c8f4a898692aac83fbab0e1dcf90b398d3770db1`. Neither is verified latest canonical upstream; published/platform package equivalence remains unverified. No network bypass was used. Full sources remain in `/workspace/gitlab_c_ext_trace` and the related local profile directories.

## Preserved earlier outputs

`gitlab-native-results.tar.gz` remains unchanged (34,453,906 bytes), containing the expanded native/source inventory. The older `gitlab-frontend-results.tar.xz.part*` snapshot remains available with `FRONTEND_ARCHIVE_SHA256SUMS`; its 23,894 receiver-supported and 2,062,103 name-only chains are superseded candidate counts and were not the population audited here. Its integrity checks never established semantic accuracy. All previous Git history is preserved.

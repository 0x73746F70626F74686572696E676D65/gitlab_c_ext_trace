# Front-end inventory and map of listed gem APIs

GitLab canonical default branch: `origin/master` at `d75e5afaa21d45bc04139d4a538ea5954be1ef4f`.

Input: `../gem_api_groups_known_memory_effects.min.json`; SHA-256 `2eb65a1ee10f55bf6b609c7fc27713e0001992c794c59246066534834b83684c`. The original schema and file are unchanged.

This is a heuristic spelling/receiver map. A match does not establish runtime dispatch, native loading, authorization success, input control, a memory effect on that invocation, or a vulnerability.

## Counts

| Classification | Examined | With any match | With qualified match |
|---|---:|---:|---:|
| unauthenticated | 331 | 191 | 4 |
| authenticated | 3401 | 2461 | 37 |
| unknown | 10113 | 3101 | 19 |

Entrypoints examined: **13845**. Unmatched: **8092**. Without qualified matches: **13785**.

Inventory API identities: **1959**. Zero entrypoint matches: **1412**. Zero qualified entrypoint matches: **1929**.

| Entrypoint type | Examined | With any match | With qualified match |
|---|---:|---:|---:|
| grape_endpoint | 1721 | 1465 | 44 |
| graphql_field | 7063 | 1101 | 3 |
| graphql_mutation | 712 | 691 | 0 |
| graphql_query | 175 | 140 | 0 |
| graphql_resolver | 1117 | 1040 | 0 |
| graphql_subscription | 48 | 0 | 0 |
| http_registration | 420 | 5 | 0 |
| rails_action | 2403 | 1311 | 13 |
| rails_route | 186 | 0 | 0 |

## Tables and records

- `entrypoints.csv`: all examined entrypoint candidates and route templates.
- `matches.csv.gz`: flattened entrypoint/API rows with gem identity, source site, confidence and helper path.
- `entrypoints.jsonl.gz`: complete records, auth evidence, API IDs, file/line matches, hop depths and helper paths; join `api_ids` to `api_catalog.jsonl`.
- `api_catalog.jsonl`: unchanged input objects, one API identity per row. Versions remain distinct and are not verified against this GitLab lockfile.
- `zero_match_apis.jsonl` and `zero_qualified_match_apis.jsonl`: complete input objects with no matching entrypoint in each confidence population.
- `bodies.jsonl.gz`: extracted method/block source spans. `files_examined.jsonl` records source hashes and parser errors.
- `summary.json`: source revision, input hash, bounds, aggregate counts and coverage counts.

## Method and confidence

Tree-sitter parses tracked Ruby/Rack source. It never loads the application or gems. C-extension files are not opened. Controllers include public methods as candidates and statically named route actions (including inherited or missing bodies). Grape endpoints are HTTP DSL blocks. GraphQL includes declared query/mutation/subscription fields, object fields and resolver implementations. Registrations include mounts, Rack map/run/use and authentication-engine DSLs. CE and EE are combined; candidate counts are not independent deployed URLs. Controller helpers/overrides can appear among public-method candidates; orphan resolver bodies and mutation output fields are retained with their discovery labels.

Helper traversal follows explicit same-owner/inherited/mixin calls, constant-qualified calls, and variables assigned a literal `Constant.new`. It stops at **2 helper hops**, **64 bodies per entrypoint**, or more than **8 helper candidates per call**. No global method-name helper search is used. Repeated bodies are visited once. `super`, reflective sends and metaprogramming are gaps. Calls after a dynamic site remain searchable, but the dynamic target is never followed.

`direct` means a qualified API receiver at hop zero. `helper` means a qualified receiver in an explicitly resolved helper. `name-only` means only the method spelling matches; all corresponding inventory IDs are candidates. Literal constant aliases and local constructor assignments are accepted; literal class construction also considers that class's listed instance initialize API. Factory overrides remain unproven. `CGI` to `CGI::EscapeExt` is the sole built-in public-module alias. Generic operator/subscript matches require an inferred receiver; other operators, setters and bare-identifier gem matches are skipped. Native internal wrapper expansion (for example Psych private parsing or BCrypt internals) is not attempted.

Hop zero is the selected action/endpoint/resolver body. Callbacks are inspected for authentication but are not added as API-matching roots. No branch/path feasibility, argument flow, callback execution graph, model association type inference or external gem wrapper traversal is computed. Helper matches retain one shortest encountered path per site.

## Authentication rules

`authenticated` requires a recognized unconditional mandatory auth filter or body/Grape-before call. Rails inherited filters, `only`/`except`, explicit skips and conditional declarations are inspected. `authenticate_non_get!` applies only to statically identified non-read verbs. Optional sessionless/token discovery is not treated as a login requirement. `unauthenticated` requires an explicit mandatory-filter skip with no unresolved replacement auth evidence; it means anonymous access is a static candidate, not a guarantee that permissions or data availability allow it. Other cases remain `unknown`.

GraphQL mutation implementations inheriting `Mutations::BaseMutation` are classified from the `execute_graphql_mutation` gate and the GlobalPolicy anonymous prevention, with source evidence; singleton authorized? overrides keep the result unknown. Other fields keep `authorize` and token-scope evidence but remain unknown: resource permissions or API scopes alone do not prove a login requirement. Parent object/schema reachability and EE policy overrides are not solved. No claim of authorization bypass is made.

## Coverage appendix

| Coverage category | Records |
|---|---:|---:|
| dynamic_dispatch | 166 |
| dynamic_dispatch_definitions | 35 |
| helper_depth_cutoff | 48503 |
| helper_method_cutoff | 2 |
| helper_name_collision | 179 |
| indexed_dynamic_dispatch_sites | 987 |
| missing_bodies | 6240 |
| name_collisions | 125 |
| resolver_factories | 27 |
| skipped_files | 32219 |
| super_dispatch | 1425 |
| unknown_auth | 10113 |
| unresolved_receiver | 117997 |
| unresolved_registrations | 205 |

Every category above has a `coverage_<category>.jsonl.gz` appendix with locations or entrypoint IDs. `skipped_files` enumerates excluded tracked Ruby/Rack files. Non-Ruby files are outside the parser scope, including C/C++, JavaScript/TypeScript front-end code and Go Workhorse. Parse errors are recorded while unaffected syntax nodes are retained. Unknown-auth records list every undecided entrypoint and collected evidence. Dispatch/cutoff records are per entrypoint/body; repeated source sites may therefore occur. Name collisions group same-spelling APIs from different namespaces; versions also remain separate. Unresolved receivers list other calls that cannot be followed.

Routes are local static DSL templates. Draw inclusion prefixes, concerns, mounted Grape prefixes/versions, plural inflection, constraints, environment switches, organization scopes and DSL-generated routes may be incomplete. Default GraphQL object-property resolution, field/type inheritance, dynamic resolver factories, EE prepend composition, callbacks, external engines, generated Ruby and runtime autoload/monkey patches can add or replace behavior. A missing body or zero match is not evidence of absence. Unsupported operators and dynamically computed receivers/names can hide inventory calls. Name-only matches have high false-positive rates; do not treat the any-match totals as established API reachability.

## Reproduce

```sh
python -m pip install -r frontend_gem_api_map/requirements.txt
git clone --depth 1 --single-branch https://gitlab.com/gitlab-org/gitlab.git /workspace/gitlab-frontend-source
git -C /workspace/gitlab-frontend-source checkout d75e5afaa21d45bc04139d4a538ea5954be1ef4f
python frontend_gem_api_map/map_frontend.py --source /workspace/gitlab-frontend-source --inventory gem_api_groups_known_memory_effects.min.json --output frontend_gem_api_map
python frontend_gem_api_map/validate_map.py --source /workspace/gitlab-frontend-source --output frontend_gem_api_map --inventory gem_api_groups_known_memory_effects.min.json
```

If the pinned commit has left the shallow default-branch tip, fetch that SHA before checkout. Parser dependency versions are pinned. The inventory and GitLab revision govern the results; earlier archives in the analysis repository are not reused by this mapper.

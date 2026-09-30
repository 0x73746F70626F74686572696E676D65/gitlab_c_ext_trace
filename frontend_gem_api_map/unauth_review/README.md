# Review of the original 191 unauthenticated candidates

All 191 original candidates and their 933 original match sites were reviewed. Eight candidates have qualified API references, including four newly qualified candidates. Every original match for 70 candidates was rejected; 113 candidates retain unresolved original matches. These groups partition the original candidates. A rejection applies to the reviewed name matches, not to all possible application behavior.

Of the eight qualified candidates, **one registered action retains an unauthenticated classification** and **seven have unknown authentication**. Qualification identifies a listed receiver/API in Ruby source; it does not prove application admission, an executable request path, native loading, or an effect on that invocation.

The earlier 191 figure was an extraction-candidate count, not an established anonymous-path count: **7 entries were callback blocks miscounted as actions**, **42 were public methods with unresolved HTTP registration**, and **142 have static route declarations**. The original machine-readable results are retained so each correction can be traced.

## Qualified candidates

| Class/action | Reviewed auth | Newly qualified | Listed APIs |
|---|---|---|---|
| Groups::UploadsController#show | unknown | false | `CGI::EscapeExt.unescape` |
| Projects::UploadsController#show | unknown | false | `CGI::EscapeExt.unescape` |
| Banzai::DiagramProxyController#proxy | unknown | true | `Oj.load`, `Oj.sc_parse` |
| Oauth::DynamicRegistrationsController#create | unauthenticated | true | `Oj.load`, `Oj.sc_parse` |
| Groups::BillingsController#index | unknown | true | `Oj.load`, `Oj.sc_parse` |
| SmartcardController#extract_certificate | unknown | false | `CGI::EscapeExt.escape` |
| SmartcardController#verify_certificate | unknown | false | `CGI::EscapeExt.unescape` |
| Users::RegistrationsIdentityVerificationController#verify_arkose_labs_session | unknown | true | `Oj.load` |

The retained unauthenticated classification is conditional on instance settings, rate limits and ordinary route handling. Token/certificate/resource permission checks keep the other seven unknown. Source location and helper evidence are in each record. All qualified candidates have static route declarations; public-method candidates without routes are counted separately.

## Records

- `reviews.csv`: one row for every original candidate, entrypoint status, reviewed authentication, API outcome, original-site verdict counts and gaps.
- `reviews.jsonl.gz`: complete per-candidate records, original API-ID verdict partitions, qualified sites, source evidence, helper paths and active callbacks.
- `gaps.jsonl.gz`: every recorded limitation encountered, linked to the original entrypoint ID and source location where available.
- `source_files.jsonl`: hashes of Ruby/Rack files opened during targeted body review. The initial index covers the original 23,370 production Ruby/Rack files.
- `summary.json`, `validation.json`, `synthetic_checks.txt`, and `SHA256SUMS`: aggregate results, integrity verification, 17 synthetic tests and artifact hashes.
- Join API IDs to `../api_catalog.jsonl`. The input JSON and all its identities/versions remain unchanged.

## Attempts and bounds

Ruby AST review traced **five helper hops**, at most **256 bodies per trace**, and at most **8 helper candidates per call**. Authentication callback traces use four helper hops. Simple return inference is capped at two hops. Dynamic dispatch and `super` are recorded without following their targets. Operator sites not rediscovered by the expanded pass retain their original API candidates as unresolved.

Receiver inference uses literal constants and aliases, constructors, literal values, local assignments, a small set of Ruby conversion conventions, and simple method returns. Branch assignments and caller-supplied optional arguments are not given a fixed type from their defaults. Same-owner calls in inherited methods use the actual candidate controller to account for directly indexed overrides. No global method-name call-graph search or full interprocedural solver is used. Ruby definitions found in GitLab reject same-spelling gem ownership at that call; their bodies may still contain separately qualified listed APIs.

Unknown inventory namespaces remain unresolved unless an actual GitLab Ruby definition identifies the call owner. A name match to another class, such as Rails `render` versus `Redcarpet::Markdown#render`, is rejected. Same-gem namespace differences remain unresolved as possible public aliases. Literal construction also considers the exact class’s listed instance `initialize` API. The explicit CGI/EscapeExt alias from the original mapper is retained.

Authentication review inspects inherited active filters, inline lambdas, applicable `only`/`except`, skips and their called helpers. It records permission, verification-user, token, certificate and Workhorse gates rather than treating a login-filter skip as permission to enter every body. Ordinary LDAP checks guarded by `current_user`, front-end gon settings and impersonation-only checks were source-reviewed as compatible with an anonymous request. The rules are tied to the located callback owner, so an indexed override is reviewed separately.

## Coverage appendix

| Gap category | Records |
|---|---:|
| HTTP_registration_unresolved | 42 |
| baseline_site_not_rediscovered | 19 |
| branch_and_call_order_unverified | 8 |
| callback_miscounted_as_action | 7 |
| conditional_callback_skip | 8 |
| dynamic_callback_selector | 24 |
| dynamic_dispatch | 43 |
| helper_depth_cap | 1511 |
| inventory_namespace_unknown | 67 |
| super_dispatch | 112 |
| unknown_receiver | 9153 |
| unresolved_auth_callback | 1 |

Gap records are per entrypoint/phase, so one source site may appear repeatedly. Every original candidate received an attempted source review. Unresolved receiver types, polymorphic parameters, association return types, dynamic names, reflective calls, `super`, native owners missing from the inventory, depth limits, callback selectors and uncertain HTTP registration are retained explicitly. Five hops remain insufficient for some Ruby wrapper chains. External gem Ruby wrappers and engines are not expanded. C-extension source was neither opened nor classified.

Branch feasibility, actual argument flow, callback halting order, current deployment settings, parent routing context, Rails generated action rules, policy outcomes and CE/EE runtime prepend composition remain unverified. Resource permissions can admit anonymous readers in some configurations, so a permission check alone is not labeled mandatory authentication. A missing match or a rejected original spelling does not establish zero runtime gem calls. The qualified count also remains a static candidate count.

## Reproduce

Use the original pinned GitLab checkout and inventory with the parent requirements file. A cache is optional and belongs outside the analysis repository; it is only a locally generated Python source-index cache.

```sh
python frontend_gem_api_map/unauth_review/review_candidates.py --source /workspace/gitlab-frontend-source --inventory gem_api_groups_known_memory_effects.min.json --baseline frontend_gem_api_map --output frontend_gem_api_map/unauth_review
python frontend_gem_api_map/unauth_review/validate_review.py --source /workspace/gitlab-frontend-source --inventory gem_api_groups_known_memory_effects.min.json --baseline frontend_gem_api_map --output frontend_gem_api_map/unauth_review
python -m unittest discover -s frontend_gem_api_map/unauth_review -p test_review.py -v
```

GitLab revision: `d75e5afaa21d45bc04139d4a538ea5954be1ef4f`. No application or gems were executed. Integrity checks and synthetic tests establish record consistency, not runtime precision or recall.

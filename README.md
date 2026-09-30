# GitLab static native results

Two results-only snapshots are retained here. No source trees, full AST dumps or credentials are committed.

## Frontend entrypoint paths

The new frontend archive is **120,340,756 bytes** compressed, split into three parts of at most 40MiB. It contains all retained 2,085,997 complete constructed path records and 423,720 partial records, normalized evidence hops, 29 structured tables, schemas, source manifests, reproducible scripts and coverage reports. No path records were omitted to reduce upload size.

**Confidence matters:** 23,894 receiver-supported possible static witnesses cover 324 entrypoint candidates and 483 primitive records. Separately, 2,062,103 chains contain a speculative method-name-only hop. Neither class proves runtime execution or public endpoint exposure.

```sh
git clone --depth 1 --branch results-20260930 https://github.com/0x73746F70626F74686572696E676D65/gitlab_c_ext_trace.git
cd gitlab_c_ext_trace
sha256sum -c SHA256SUMS
cat gitlab-frontend-results.tar.xz.part01 gitlab-frontend-results.tar.xz.part02 gitlab-frontend-results.tar.xz.part03 > gitlab-frontend-results.tar.xz
sha256sum -c FRONTEND_ARCHIVE_SHA256SUMS
tar -xJf gitlab-frontend-results.tar.xz
python frontend-results/scripts/expand_frontend_path.py --root frontend-results --sample
```

Start with `frontend-results/INDEX.txt`, `reports/frontend_validation.json` and `reports/frontend_breakdowns.json`. 10,184 declaration/handler records were examined; 5,482 have no discovered complete path. Counts distinguish route-mapped handlers from unexposed candidates. Search is bounded and retains one representative Ruby prefix per entrypoint/registration/evidence class, composed with retained native tails—not all execution walks.

Validation passed 20,783,302 checks with zero errors. The missing EE tree, 78 unresolved dependency sources, 579 accepted source roots absent from baseline Ruby parsing, dynamic dispatch, parser limitations and traversal limits remain explicit coverage gaps. YARD/RBI/loader evidence is inventoried, not treated as a resolved type system. Full sources and complete baseline tables remain local at `/workspace/gitlab_c_ext_trace`.

Reproduction requires that retained local corpus and baseline tables. Run the included Rails/Grape/GraphQL extractors and dynamic/native-tail scripts, then `build_frontend_paths.py`, `frontend_appendix.py`, `frontend_support.py --confirm-frontend-frozen`, and validators. The archive's standalone path expander works without source trees. No application, endpoint, extension or target build hook was executed.

## Prior native/source inventory

`gitlab-native-results.tar.gz` remains unchanged: 34,453,906 bytes. Extract it with `tar -xzf gitlab-native-results.tar.gz`; start at `results/INDEX.txt`. 742/820 primary locked entries have accepted source-derived classifications; 78 remain unresolved with individual attempt/blocker evidence. No static native evidence does not prove a pure-Ruby published package.

Both snapshots use GitHub mirror master commit `8d0e57e5f49543c53614b299aef70f7e5bb916ac`, retrieved 2026-09-30 03:07:55 UTC. Canonical upstream and published/platform-package equivalence remain unverified. Previous result commits remain in Git history.

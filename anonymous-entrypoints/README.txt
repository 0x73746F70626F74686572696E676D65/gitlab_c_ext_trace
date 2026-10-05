Anonymous entrypoint metadata

entries/<type>/<handler-or-field>__<edition>__<stable-id>.json

Each file represents one existing entrypoint record. Records are organized by
controller/Rails action, Grape API, GraphQL query/field, HTTP registration,
middleware, dedicated health listener, or WebSocket registration. CE/EE and
organization aliases retain separate saved identities. GraphQL records share
their HTTP transport; fields are not additional URLs.

Every file includes path/methods, edition, pinned GitLab revision, handler or
GraphQL field metadata, registration file/line, available implementation
file/line citations, auth classifications/conditions, and the saved auth
evidence/callback metadata. GraphQL files also cite the HTTP transport's
registration. Source file/line citations refer to GitLab at the stated revision;
they are not paths to a new source checkout in this analysis repository.
An evidence item without its own source line retains its original facts and a
JSON-pointer citation to the saved evidence dictionary; no line is invented.

Selection: existing source_supported unauthenticated or conditional_anonymous
classifications, a concrete path and no recorded auth gaps. This includes
5,426 public/application records and 12 error-only handlers. The manifest lists
all 5,438 files, counts and SHA-256 hashes. There are 1,310 unauthenticated and
4,128 conditional_anonymous records. Conditions must be retained when using
the data. anonymous_access=false on an included record means error_only;
its saved auth label does not establish a successful application response.

"Supported" here is the saved bounded static source review. No record is
runtime-confirmed; all retain runtime_verified=false. Unknown, authenticated
and legacy-only candidates are excluded. Authentication completeness remains
unproven. No GitLab code, source-analysis generator or endpoint was executed
to produce this directory: this is metadata reformatting only.

manifest.json is a file index, not an entrypoint. The one-record JSON files are
under entries/. Their provenance pins the original artifact bytes and JSON
array position, so each record can be checked against the unchanged inventory.

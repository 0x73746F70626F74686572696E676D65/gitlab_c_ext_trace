# GitLab locked native gem sources

`packages/e313eacf/gitlab-locked-native-sources-e313eacf.tar.gz` contains only
C/C++ source files, headers, include fragments and native source templates from
the gem versions in GitLab's primary `Gemfile.lock` at commit
`e313eacff054bc8f780225523f68e97992733578`. The canonical `master` branch was
freshly cloned for this collection. GitLab specifies Ruby 3.3.11.

All **821 locked entries** were inspected: **781 published packages** and
**40 local path gems**, covering **770 gem names** and every locked platform
variant. Each published package matched its lockfile SHA256. Local path gems
were inspected in that exact GitLab checkout. **72 gems**, across **94 package
variants**, contained native source files; the archive contains **8,312 files**.
Bundled vendor source archives were unpacked, including the libraries shipped
with Nokogiri, GPGME and RE2. No gem, extension or build code was executed.

The archive root is `gitlab-locked-native-sources/<gem>-<locked-version>/`.
Original file paths, bytes and line numbering are preserved. Nested vendor
archives appear under `<original-archive-name>.sources/`. The retained source
files include C++ code used by native gems such as gRPC and RE2. Ruby files,
gemspecs, binaries, build scripts, Rust files and metadata are excluded from
the tarball. The collection retains shipped sources, including native test and
example files, and does not apply build-time patches to vendor source archives.

The scope is the application's main resolved bundle, including all dependency
groups and platforms in its lockfile. Separate QA/example bundles and the
alternative `Gemfile.next.lock` are outside this collection. The inventory
records which packages are defined by that bundle, not which optional
extensions execute in a particular deployment. System libraries installed
outside gem packages and Ruby interpreter sources are outside the gem archive.

Version and integrity evidence is stored alongside the tarball:

- `Gemfile.lock`: exact input lockfile.
- `packages.jsonl`: every locked entry, its dependencies, source location,
  package checksum, metadata and source inventory, including entries with no
  C/C++ files.
- `source-files.jsonl`: archive paths, source hashes and nested archive provenance.
- `manifest.json`: pinned commit, scope, counts and archive SHA256.
- `validation.json`: independent lock checksum and source-only archive checks.
- `SHA256SUMS`: tarball digest.

Reproduce with Python and PyYAML (the recorded run used PyYAML 6.0.3):

```sh
git clone --depth 1 --filter=blob:none --sparse \
  https://gitlab.com/gitlab-org/gitlab.git /path/to/gitlab
git -C /path/to/gitlab sparse-checkout set gems vendor/gems
python native-source-bundle/scripts/collect.py \
  --gitlab /path/to/gitlab \
  --cache /path/to/source-cache \
  --out native-source-bundle/packages/<commit-prefix>
```

For this exact bundle, use the recorded commit rather than a later `master` tip.
Package restoration resumes from verified cache records. Any failed download,
checksum mismatch or missing path gem prevents archive emission.

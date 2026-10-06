#!/usr/bin/env python3
"""Package source files for saved app/lib/ee Ruby-to-native flow matches."""
import argparse
import collections
import gzip
import hashlib
import io
import json
import re
import tarfile
from pathlib import Path, PurePosixPath

ROOTS = ('app/', 'lib/', 'ee/app/', 'ee/lib/')
INCLUDES = re.compile(rb'^\s*#\s*include\s*(["<])([^">\r\n]+)[">]', re.M)


def encode(row):
    return (json.dumps(row, sort_keys=True, separators=(',', ':')) + '\n').encode()


def rows(path):
    with path.open() as stream:
        for line in stream:
            if line.strip():
                yield json.loads(line)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--repo', type=Path, default=Path(__file__).resolve().parents[2])
    ap.add_argument('--archive', type=Path, required=True)
    args = ap.parse_args()
    repo = args.repo.resolve()
    results = repo / 'ruby-callsite-analysis/results'
    native = repo / 'argument-taint-analysis'
    packages = {}
    for p in json.loads((native / 'results/source-manifest.json').read_text()):
        key = p['gem'] + '@' + p['locked_version']
        if p.get('source_variant'):
            key += ':' + p['source_variant']
        packages[key] = p
    inventory = {key: {f['file']: f for f in p['source_files']}
                 for key, p in packages.items()}
    sites = [r for r in rows(results / 'callsites.jsonl')
             if r['source']['file'].startswith(ROOTS)]
    assert sites
    sites.sort(key=lambda r: (r['source']['file'], r['source']['line'], r['callsite_id']))
    site_ids = {s['callsite_id'] for s in sites}
    wanted = {id for s in sites for h in s['native_flows'] for id in h['c_flow_ids']}
    original = {r['flow_id']: r for f in sorted((results / 'c-flow-library').glob('*.jsonl'))
                for r in rows(f) if r['flow_id'] in wanted}
    assert set(original) == wanted
    chains = {}
    with tarfile.open(native / 'packages/gem-api-memory-flow-chains.tar.gz', mode='r|gz') as archive:
        for member in archive:
            id = PurePosixPath(member.name).stem
            if member.isfile() and id in wanted:
                chain = json.load(archive.extractfile(member))
                assert chain['chain_id'] == id and id not in chains
                assert [e['id'] for e in chain['flow']] == original[id]['event_chain']
                chains[id] = chain
    assert set(chains) == wanted
    print(f'Selected {len(sites)} Ruby callsites and {len(chains)} complete C witnesses.', flush=True)

    files, contents, refs = {}, {}, collections.defaultdict(set)
    payload = {}
    used_paths = set()

    def source_path(key, relative):
        slug = re.sub(r'[^A-Za-z0-9@._-]', '_', key)
        path = PurePosixPath(relative)
        assert not path.is_absolute() and '..' not in path.parts
        return 'sources/' + slug + '/' + relative

    def add_source(key, relative, reason, expected=None, local_path=None):
        pair = (key, relative)
        if pair not in files:
            p = packages[key]
            path = local_path or (Path(p['directory']) / relative)
            raw = path.read_bytes()
            sha = digest(raw)
            known = inventory[key].get(relative)
            if known:
                assert sha == known['sha256'], (key, relative)
            name = source_path(key, relative)
            assert name not in used_paths
            used_paths.add(name)
            files[pair] = dict(package=key, file=relative, archive_path=name,
                               source_sha256=sha, bytes=len(raw), reasons=set(),
                               original_file_metadata=known)
            contents[pair] = raw
        entry = files[pair]
        if expected:
            assert entry['source_sha256'] == expected, pair
        entry['reasons'].add(reason)
        return pair

    def citations(value):
        if isinstance(value, dict):
            if all(k in value for k in ('package', 'file', 'source_sha256')):
                yield value
            for v in value.values():
                yield from citations(v)
        elif isinstance(value, list):
            for v in value:
                yield from citations(v)

    for id, chain in sorted(chains.items()):
        payload['chains/' + id + '.json'] = encode(chain)
        for cite in citations(chain):
            pair = add_source(cite['package'], cite['file'], 'chain_citation', cite['source_sha256'])
            if cite.get('line'):
                assert 1 <= cite['line'] <= len(contents[pair].splitlines()), cite
            refs[id].add(pair)
    cited_pairs = set(files)

    wrappers = json.loads((results / 'gem-ruby-source-manifest.json').read_text())
    wrappers = {(r['gem'], r['locked_version'], r['file'], r['source_sha256']): r for r in wrappers}
    for site in sites:
        events = site['receiver']['proof'] + [e for h in site['native_flows'] for e in h['ruby_binding_path']]
        for event in events:
            p = event.get('source_package')
            if not p:
                continue
            key = p['gem'] + '@' + p['version']
            wrapper = wrappers[(p['gem'], p['version'], p['file'], event['source_sha256'])]
            assert packages[key]['package_sha256'] == wrapper['package_sha256']
            add_source(key, p['file'], 'ruby_binding', event['source_sha256'], Path(wrapper['path']))

    # Retain resolvable local header dependencies, without importing unrelated C units.
    include_edges, pending, visited = [], list(sorted(files)), set()
    while pending:
        key, relative = pending.pop()
        pair = (key, relative)
        if pair in visited or Path(relative).suffix == '.rb':
            continue
        visited.add(pair)
        p = packages[key]
        for match in INCLUDES.finditer(contents[pair]):
            token = match[2].decode('utf-8', 'replace')
            line = contents[pair][:match.start()].count(b'\n') + 1
            edge = dict(package=key, file=relative, line=line, include=token)
            candidates = []
            direct = [PurePosixPath(relative).parent / token] if match[1] == b'"' else []
            direct += [PurePosixPath(token), PurePosixPath('include') / token]
            for candidate in direct:
                normalized = Path(p['directory']) / str(candidate)
                resolved = normalized.resolve()
                base = Path(p['directory']).resolve()
                if resolved.is_relative_to(base) and resolved.is_file():
                    candidates = [resolved.relative_to(base).as_posix()]
                    break
            if not candidates:
                candidates = sorted(f for f in inventory[key]
                                    if f == token or f.endswith('/' + token))
            if len(candidates) == 1:
                target = add_source(key, candidates[0], 'local_include')
                pending.append(target)
                edge.update(status='included', target=files[target]['archive_path'])
            else:
                edge.update(status='external_or_missing' if not candidates else 'ambiguous', candidates=candidates)
            include_edges.append(edge)
    for key in sorted({key for key, _ in files}):
        directory = Path(packages[key]['directory'])
        for path in sorted(directory.iterdir()):
            if path.is_file() and re.match(r'^(LICENSE|LICENCE|COPYING|COPYRIGHT)([._-]|$)', path.name, re.I):
                add_source(key, path.name, 'package_license')

    source_entries = []
    for pair in sorted(files):
        entry = dict(files[pair], reasons=sorted(files[pair]['reasons']))
        payload[entry['archive_path']] = contents[pair]
        source_entries.append(entry)
    selected_packages = []
    for key in sorted({key for key, _ in files}):
        p = {k: v for k, v in packages[key].items() if k not in ('directory', 'source_files')}
        p.update(package=key, archive_directory=source_path(key, '').rstrip('/'),
                 files=[e for e in source_entries if e['package'] == key])
        selected_packages.append(p)
    payload['source-packages.json'] = encode(selected_packages)
    payload['source-files.jsonl'] = b''.join(encode(e) for e in source_entries)
    payload['include-dependencies.jsonl'] = b''.join(encode(e) for e in sorted(include_edges, key=lambda e: (e['package'], e['file'], e['line'], e['include'])))
    payload['callsites.jsonl'] = b''.join(encode(s) for s in sites)
    for site in sites:
        payload['callsites/' + site['source']['file'] + '/' + site['callsite_id'] + '.json'] = encode(site)
    flow_sites = collections.defaultdict(set)
    for site in sites:
        for h in site['native_flows']:
            for id in h['c_flow_ids']:
                flow_sites[id].add(site['callsite_id'])
    flow_map = [dict(flow_id=id, chain='chains/' + id + '.json',
                     callsite_ids=sorted(flow_sites[id]),
                     source_files=sorted(files[pair]['archive_path'] for pair in refs[id]))
                for id in sorted(chains)]
    payload['flow-source-map.jsonl'] = b''.join(encode(row) for row in flow_map)
    summary = dict(format_version=1, gitlab_commit=sites[0]['gitlab_commit'],
                   ruby_source_roots=list(ROOTS), ruby_callsites=len(sites), c_flow_chains=len(chains),
                   gems=len({p['gem'] for p in selected_packages}), source_variants=len(selected_packages),
                   chain_cited_source_files=len(cited_pairs), source_files=len(source_entries),
                   source_bytes=sum(e['bytes'] for e in source_entries),
                   callsites_by_root={root: sum(s['source']['file'].startswith(root) for s in sites) for root in ROOTS},
                   include_dependency_statuses=dict(sorted(collections.Counter(e['status'] for e in include_edges).items())),
                   sources_by_reason={reason: sum(reason in e['reasons'] for e in source_entries)
                                      for reason in sorted({r for e in source_entries for r in e['reasons']})},
                   input_sha256={name: digest((repo / name).read_bytes()) for name in (
                       'ruby-callsite-analysis/results/callsites.jsonl',
                       'argument-taint-analysis/results/source-manifest.json',
                       'argument-taint-analysis/packages/gem-api-memory-flow-chains.tar.gz')})
    payload['manifest.json'] = encode(summary)
    payload['README.txt'] = (
        'Source review bundle for saved GitLab Ruby-to-native memory flows.\n'
        'Scope: callsites whose source path starts app/, lib/, ee/app/, or ee/lib/.\n'
        'callsites/: one original JSON per selected Ruby callsite; callsites.jsonl aggregates them.\n'
        'chains/: only their complete original saved C flow witness JSONs.\n'
        'sources/: complete files cited by those C chains, Ruby wrapper evidence, and resolvable local includes.\n'
        'Every retained source file has its original bytes and line numbering, not extracted snippets.\n'
        'flow-source-map.jsonl maps C witnesses and Ruby callsites to their complete source files.\n'
        'source-packages.json pins published gem versions/package hashes and upstream Git commits/gitlinks.\n'
        'source-files.jsonl lists source SHA256s and inclusion reasons.\n'
        'include-dependencies.jsonl records local header resolution and external/missing/ambiguous includes.\n'
        'This is a review source slice, not a buildable checkout or a new tracing run.\n'
        'Published gems and recorded upstream Git variants are distinct; use the package identity in each chain.\n'
        'The original C interrupted-checkpoint status is retained in every chain.\n'
    ).encode()
    payload['SHA256SUMS'] = ''.join(digest(data) + '  ' + name + '\n'
                                  for name, data in sorted(payload.items())).encode()
    root = 'gitlab-app-lib-gem-memory-review-sources/'
    args.archive.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.archive.with_suffix(args.archive.suffix + '.tmp')
    with temporary.open('wb') as raw, gzip.GzipFile(fileobj=raw, mode='wb', filename='', mtime=0, compresslevel=9) as zipped, tarfile.open(fileobj=zipped, mode='w|', format=tarfile.PAX_FORMAT) as archive:
        for name, data in sorted(payload.items()):
            member = tarfile.TarInfo(root + name)
            member.size = len(data)
            member.mode = 0o644
            member.mtime = member.uid = member.gid = 0
            archive.addfile(member, io.BytesIO(data))
    temporary.replace(args.archive)
    # Re-open the completed artifact and verify every payload, citation, and selection.
    seen = set()
    with tarfile.open(args.archive, mode='r|gz') as archive:
        for member in archive:
            name = member.name.removeprefix(root)
            assert name in payload and name not in seen and member.isfile()
            raw = archive.extractfile(member).read()
            assert digest(raw) == digest(payload[name]), name
            seen.add(name)
    assert seen == set(payload)
    assert all(set(r['callsite_ids']) <= site_ids for r in flow_map)
    assert all(s['source']['file'].startswith(ROOTS) for s in sites)
    report = dict(summary, archive_sha256=digest(args.archive.read_bytes()),
                  archive_bytes=args.archive.stat().st_size, archive_files=len(payload),
                  validation='passed: all payloads, original source hashes, citations, chains, and Ruby scope')
    args.archive.with_suffix(args.archive.suffix + '.json').write_bytes(encode(report))
    print(json.dumps(report, indent=2, sort_keys=True), flush=True)


if __name__ == '__main__':
    main()

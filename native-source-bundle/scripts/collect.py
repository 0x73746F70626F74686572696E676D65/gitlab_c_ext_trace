#!/usr/bin/env python3
"""Collect source-only native files from every package in GitLab's lockfile."""
import argparse
import concurrent.futures
import gzip
import hashlib
import io
import json
import posixpath
import re
import subprocess
import tarfile
import time
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath

import yaml

SUFFIXES = {'.c', '.h', '.cc', '.cpp', '.cxx', '.hpp', '.hh', '.hxx', '.inc', '.inl', '.ipp', '.tcc'}
ARCHIVES = ('.tar', '.tar.gz', '.tgz', '.tar.bz2', '.tbz2', '.tar.xz', '.txz', '.zip')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(row):
    return (json.dumps(row, sort_keys=True, separators=(',', ':')) + '\n').encode()


def keep(path):
    p = PurePosixPath(path)
    return p.suffix.lower() in SUFFIXES or any(p.name.lower().endswith(s + '.in') for s in SUFFIXES)


def safe(path):
    p = PurePosixPath(path)
    assert not p.is_absolute() and '..' not in p.parts, path
    return p.as_posix().removeprefix('./')


def parse_lock(text):
    records, section, source, current = [], None, None, None
    checks = {(m[1], m[2]): m[3] for m in re.finditer(
        r'^  (\S+) \(([^)]+)\) sha256=([0-9a-f]{64})$', text, re.M)}
    direct = set()
    for number, line in enumerate(text.splitlines(), 1):
        if line and not line.startswith(' '):
            section, source, current = line, {}, None
        elif section in {'GEM', 'GIT', 'PATH'}:
            if line.startswith('  remote: '):
                source['remote'] = line[10:]
            elif line.startswith('  revision: '):
                source['revision'] = line[12:]
            elif match := re.fullmatch(r'    (\S+) \(([^)]+)\)', line):
                name, locked = match.groups()
                version = re.fullmatch(r'([0-9][0-9A-Za-z.]*)(?:-(.+))?', locked)
                assert version, locked
                current = dict(gem=name, locked_version=locked, version=version[1],
                               platform=version[2] or 'ruby', source_type=section,
                               source=dict(source), lockfile_line=number, dependencies=[])
                if section == 'GEM':
                    current['expected_package_sha256'] = checks[(name, locked)]
                records.append(current)
            elif current is not None and (match := re.fullmatch(r'      (\S+)(?: \(([^)]+)\))?', line)):
                current['dependencies'].append(dict(gem=match[1], requirement=match[2]))
        elif section == 'DEPENDENCIES' and (match := re.fullmatch(r'  ([^ (!]+)(?: \([^)]*\))?!?', line)):
            direct.add(match[1])
    for r in records:
        r['direct_dependency'] = r['gem'] in direct
    assert len({(r['gem'], r['locked_version'], r['source_type']) for r in records}) == len(records)
    return records


def fetch(url, path, expected):
    if path.exists():
        data = path.read_bytes()
        assert sha(data) == expected, path
        return data
    last = None
    for attempt in range(4):
        try:
            request = urllib.request.Request(url, headers={'User-Agent': 'GitLab-pinned-native-source-collector/1'})
            with urllib.request.urlopen(request, timeout=60) as response:
                data = response.read()
            assert sha(data) == expected, ('Gemfile.lock checksum mismatch', url)
            path.parent.mkdir(parents=True, exist_ok=True)
            temporary = path.with_suffix(path.suffix + '.tmp')
            temporary.write_bytes(data)
            temporary.replace(path)
            return data
        except Exception as error:
            last = error
            if attempt < 3:
                time.sleep(attempt + 1)
    raise last


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--gitlab', type=Path, required=True)
    ap.add_argument('--cache', type=Path, required=True)
    ap.add_argument('--out', type=Path, required=True)
    ap.add_argument('--reuse-packages', type=Path)
    ap.add_argument('--jobs', type=int, default=10)
    args = ap.parse_args()
    args.cache.mkdir(parents=True, exist_ok=True)
    args.out.mkdir(parents=True, exist_ok=True)
    commit = subprocess.check_output(['git', '-C', str(args.gitlab), 'rev-parse', 'HEAD'], text=True).strip()
    raw_lock = (args.gitlab / 'Gemfile.lock').read_bytes()
    specs = parse_lock(raw_lock.decode())
    (args.out / 'Gemfile.lock').write_bytes(raw_lock)
    print(f'GitLab {commit}: {len(specs)} locked specs / {len({s["gem"] for s in specs})} gems', flush=True)
    files_root = args.cache / 'sources'

    def restore(spec):
        name = spec['gem'] + '-' + spec['locked_version']
        saved = args.cache / 'records' / (name + '.json')
        if saved.exists():
            record = json.loads(saved.read_text())
            assert record['gitlab_commit'] == commit and record['locked_spec'] == spec
            for f in record['source_files']:
                assert sha((files_root / f['archive_path']).read_bytes()) == f['source_sha256']
            return record
        record = dict(locked_spec=spec, gitlab_commit=commit, source_files=[], nested_archives=[])
        prefix = name + '/'
        seen = set()

        def retain(relative, data, provenance):
            relative = safe(relative)
            archive_path = prefix + relative
            assert keep(relative) and archive_path not in seen, archive_path
            seen.add(archive_path)
            dest = files_root / archive_path
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
            record['source_files'].append(dict(archive_path=archive_path, file=relative,
                                              bytes=len(data), source_sha256=sha(data),
                                              provenance=provenance))

        def unpack(blob, path_prefix='', ancestors=()):
            with tarfile.open(fileobj=io.BytesIO(blob), mode='r:*') as archive:
                members = {safe(m.name): m for m in archive.getmembers() if m.name not in ('.', './')}

                def read(member_name, visited=frozenset()):
                    assert member_name not in visited
                    member = members[member_name]
                    if member.isfile():
                        return archive.extractfile(member).read()
                    if member.issym() or member.islnk():
                        link = member.linkname if member.islnk() else posixpath.join(posixpath.dirname(member_name), member.linkname)
                        target = safe(posixpath.normpath(link))
                        return read(target, visited | {member_name})
                    raise ValueError('not a regular source member: ' + member_name)

                for relative, member in sorted(members.items()):
                    if not (member.isfile() or member.issym() or member.islnk()):
                        continue
                    if keep(relative):
                        retain(path_prefix + relative, read(relative), dict(member=relative, containers=list(ancestors),
                                                                          link_target=member.linkname if member.issym() or member.islnk() else None))
                    elif relative.lower().endswith(ARCHIVES):
                        nested = read(relative)
                        citation = dict(member=path_prefix + relative, sha256=sha(nested), bytes=len(nested))
                        before = len(record['source_files'])
                        if relative.lower().endswith('.zip'):
                            with zipfile.ZipFile(io.BytesIO(nested)) as zipped:
                                for z in sorted(zipped.infolist(), key=lambda z: z.filename):
                                    if not z.is_dir() and keep(z.filename):
                                        retain(path_prefix + relative + '.sources/' + safe(z.filename), zipped.read(z),
                                               dict(member=z.filename, containers=list(ancestors) + [citation], link_target=None))
                        else:
                            unpack(nested, path_prefix + relative + '.sources/', ancestors + (citation,))
                        record['nested_archives'].append(dict(citation, native_files=len(record['source_files']) - before))

        if spec['source_type'] == 'GEM':
            expected = spec['expected_package_sha256']
            cached = (args.reuse_packages / (name + '.gem')) if args.reuse_packages else None
            package_path = cached if cached and cached.exists() else args.cache / 'packages' / (name + '.gem')
            url = spec['source']['remote'].rstrip('/') + '/downloads/' + name + '.gem'
            raw = fetch(url, package_path, expected)
            with tarfile.open(fileobj=io.BytesIO(raw)) as package:
                metadata_raw = gzip.decompress(package.extractfile('metadata.gz').read())
                meta = yaml.load(metadata_raw, Loader=yaml.BaseLoader)
                assert meta['name'] == spec['gem'] and meta['version']['version'] == spec['version']
                record.update(source_url=url, package_sha256=sha(raw), checksum_status='matches_Gemfile.lock',
                              gem_metadata=dict(name=meta['name'], version=meta['version']['version'],
                                                platform=meta['platform'], extensions=meta.get('extensions', []),
                                                source_code_uri=meta.get('metadata', {}).get('source_code_uri'),
                                                licenses=meta.get('licenses', [])))
                unpack(package.extractfile('data.tar.gz').read())
        elif spec['source_type'] == 'PATH':
            directory = args.gitlab / spec['source']['remote']
            assert directory.is_dir(), directory
            record.update(source_url='https://gitlab.com/gitlab-org/gitlab/-/tree/' + commit + '/' + spec['source']['remote'],
                          checksum_status='pinned_GitLab_commit', gitlab_path=spec['source']['remote'])
            for path in sorted(directory.rglob('*')):
                if path.is_file() and keep(path.name):
                    relative = path.relative_to(directory).as_posix()
                    assert path.resolve().is_relative_to(args.gitlab.resolve())
                    retain(relative, path.read_bytes(), dict(gitlab_commit=commit, gitlab_file=spec['source']['remote'] + '/' + relative))
        else:
            raise ValueError('Unexpected GIT source: ' + str(spec))
        record['source_files'].sort(key=lambda f: f['archive_path'])
        record['status'] = 'native_sources_collected' if record['source_files'] else 'no_C_or_Cxx_source_in_locked_package'
        saved.parent.mkdir(parents=True, exist_ok=True)
        saved.write_bytes(encoded(record))
        return record

    collected, failures = [], []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futures = {pool.submit(restore, spec): spec for spec in specs}
        for i, future in enumerate(concurrent.futures.as_completed(futures), 1):
            spec = futures[future]
            try:
                r = future.result()
                collected.append(r)
                if r['source_files']:
                    print(f'{spec["gem"]} {spec["locked_version"]}: {len(r["source_files"])} native files', flush=True)
            except Exception as error:
                failures.append(dict(spec=spec, error=f'{type(error).__name__}: {error}'))
                print(f'FAILED {spec["gem"]} {spec["locked_version"]}: {error}', flush=True)
            if i % 50 == 0 or i == len(specs):
                print(f'Inspected {i}/{len(specs)} packages; failures={len(failures)}', flush=True)
    (args.out / 'failures.json').write_bytes(encoded(failures))
    assert not failures, 'Package collection has failures; no archive emitted'
    collected.sort(key=lambda r: (r['locked_spec']['gem'], r['locked_spec']['locked_version']))
    assert len(collected) == len(specs)
    (args.out / 'packages.jsonl').write_bytes(b''.join(encoded(r) for r in collected))
    source_files = [dict(f, gem=r['locked_spec']['gem'], locked_version=r['locked_spec']['locked_version'])
                    for r in collected for f in r['source_files']]
    source_files.sort(key=lambda f: f['archive_path'])
    (args.out / 'source-files.jsonl').write_bytes(b''.join(encoded(f) for f in source_files))
    archive_path = args.out / ('gitlab-locked-native-sources-' + commit[:8] + '.tar.gz')
    temporary = archive_path.with_suffix(archive_path.suffix + '.tmp')
    root = 'gitlab-locked-native-sources/'
    with temporary.open('wb') as raw, gzip.GzipFile(fileobj=raw, mode='wb', filename='', mtime=0, compresslevel=9) as zipped, tarfile.open(fileobj=zipped, mode='w|', format=tarfile.PAX_FORMAT) as archive:
        for f in source_files:
            data = (files_root / f['archive_path']).read_bytes()
            assert sha(data) == f['source_sha256']
            member = tarfile.TarInfo(root + f['archive_path'])
            member.size = len(data)
            member.mode = 0o644
            member.mtime = member.uid = member.gid = 0
            archive.addfile(member, io.BytesIO(data))
    temporary.replace(archive_path)
    expected = {f['archive_path']: f for f in source_files}
    seen = set()
    with tarfile.open(archive_path, mode='r|gz') as archive:
        for member in archive:
            name = member.name.removeprefix(root)
            assert member.isfile() and keep(name) and name in expected and name not in seen
            assert sha(archive.extractfile(member).read()) == expected[name]['source_sha256']
            seen.add(name)
    assert seen == set(expected)
    native = [r for r in collected if r['source_files']]
    summary = dict(gitlab_commit=commit, gitlab_repository='https://gitlab.com/gitlab-org/gitlab.git',
                   ruby_version=(args.gitlab / '.ruby-version').read_text().strip(),
                   lockfile='Gemfile.lock', lockfile_sha256=sha(raw_lock), scope='All primary Gemfile.lock specs, including all groups and locked platform variants',
                   locked_specs=len(specs), locked_gems=len({s['gem'] for s in specs}),
                   checked_published_packages=sum(r['locked_spec']['source_type'] == 'GEM' for r in collected),
                   checked_path_packages=sum(r['locked_spec']['source_type'] == 'PATH' for r in collected),
                   native_source_gems=len({r['locked_spec']['gem'] for r in native}), native_source_packages=len(native),
                   nested_source_archives=sum(len(r['nested_archives']) for r in collected), source_files=len(source_files),
                   source_bytes=sum(f['bytes'] for f in source_files),
                   archive=archive_path.name, archive_bytes=archive_path.stat().st_size, archive_sha256=sha(archive_path.read_bytes()),
                   retained_suffixes=sorted(SUFFIXES), retained_native_templates=True,
                   archive_contents='Only C/C++ source, headers, includes and native source templates; provenance is in sidecar files',
                   source_semantics='Exact shipped package bytes; nested vendor archives unpacked without applying build patches',
                   target_code_executed=False, failures=failures,
                   validation='passed: every locked package inspected; all published package lockfile SHA256s and every archive member verified')
    (args.out / 'manifest.json').write_bytes(encoded(summary))
    (args.out / 'SHA256SUMS').write_text(sha(archive_path.read_bytes()) + '  ' + archive_path.name + '\n')
    print(json.dumps(summary, indent=2, sort_keys=True), flush=True)


if __name__ == '__main__':
    main()

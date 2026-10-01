#!/usr/bin/env python3
"""Download package bytes and inspect archives; never load gemspecs or run Ruby."""
import argparse, concurrent.futures, csv, hashlib, io, json, pathlib, re
import subprocess, tarfile, time, urllib.request

NATIVE = {'.c', '.cc', '.cpp', '.h'}
META = {'extconf.rb', 'CMakeLists.txt', 'Makefile', 'Rakefile', 'MANIFEST'}

def write_csv(path, records, fields):
    with path.open('w', newline='') as f:
        writer = csv.DictWriter(f, fields, extrasaction='ignore', lineterminator='\n')
        writer.writeheader()
        writer.writerows(records)

def lock_specs(text):
    records, section, remote, revision = [], None, None, None
    for line in text.splitlines():
        if line and not line.startswith(' '):
            section, remote, revision = line, None, None
        elif line.startswith('  remote: '):
            remote = line[10:]
        elif line.startswith('  revision: '):
            revision = line[12:]
        elif section in {'PATH', 'GIT', 'GEM'}:
            match = re.fullmatch(r'    (\S+) \(([^)]+)\)', line)
            if match:
                name, locked = match.groups()
                version = re.split(r'-(?=(?:aarch64|arm64|x86|java|universal))', locked)[0]
                records.append(dict(gem=name, version=version, locked_version=locked,
                                    source_type=section, remote=remote, revision=revision))
    return records

def members_from_gem(data):
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:*') as outer:
        payload = outer.extractfile('data.tar.gz').read()
    with tarfile.open(fileobj=io.BytesIO(payload), mode='r:gz') as archive:
        return [(m.name, archive.extractfile(m).read() if keep(m.name) and m.isfile() else None,
                 'symlink' if m.issym() or m.islnk() else 'file' if m.isfile() else 'directory')
                for m in archive]

def keep(name):
    p = pathlib.PurePosixPath(name)
    return p.suffix in NATIVE or p.suffix == '.gemspec' or p.name in META or p.suffix in {'.mk', '.cmake'}

def download(url, target):
    if target.exists():
        return target.read_bytes()
    for attempt in range(3):
        try:
            with urllib.request.urlopen(url, timeout=90) as response:
                data = response.read()
            target.write_bytes(data)
            return data
        except Exception:
            if attempt == 2:
                raise
            time.sleep(attempt + 1)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--gitlab', type=pathlib.Path, required=True)
    ap.add_argument('--cache', type=pathlib.Path, required=True)
    ap.add_argument('--out', type=pathlib.Path, required=True)
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    (args.cache / 'packages').mkdir(parents=True, exist_ok=True)
    lock = (args.gitlab / 'Gemfile.lock').read_text()
    (args.out / 'Gemfile.lock').write_text(lock)
    specs = lock_specs(lock)
    write_csv(args.out / 'locked-gems.csv', specs,
              ['gem', 'version', 'locked_version', 'source_type', 'remote', 'revision'])
    sha = subprocess.check_output(['git', '-C', str(args.gitlab), 'rev-parse', 'HEAD'], text=True).strip()
    checksums = {(m[1], m[2]): m[3] for m in re.finditer(
        r'^  (\S+) \(([^)]+)\) sha256=([0-9a-f]+)$', lock, re.M)}
    paths = [s['remote'] for s in specs if s['source_type'] == 'PATH']
    if paths:
        subprocess.run(['git', '-C', str(args.gitlab), 'sparse-checkout', 'set', '--no-cone',
                        '/Gemfile.lock', *('/' + p + '/' for p in paths)], check=True)

    def fetch(spec):
        record = dict(spec)
        key = spec['gem'] + '-' + spec['locked_version']
        directory = args.cache / 'sources' / key
        directory.mkdir(parents=True, exist_ok=True)
        try:
            if spec['source_type'] == 'PATH':
                source = args.gitlab / spec['remote']
                if not source.is_dir():
                    raise FileNotFoundError('PATH source absent in pinned GitLab checkout')
                members = [(str(p.relative_to(source)), p.read_bytes() if keep(str(p)) and p.is_file()
                            and not p.is_symlink() else None,
                            'symlink' if p.is_symlink() else 'file' if p.is_file() else 'directory')
                           for p in source.rglob('*')]
                record['source_url'] = f'https://gitlab.com/gitlab-org/gitlab/-/tree/{sha}/{spec["remote"]}'
                record['sha256'] = ''
            elif spec['source_type'] == 'GEM':
                url = spec['remote'].rstrip('/') + '/downloads/' + key + '.gem'
                data = download(url, args.cache / 'packages' / (key + '.gem'))
                digest = hashlib.sha256(data).hexdigest()
                expected = checksums.get((spec['gem'], spec['locked_version']))
                if expected and digest != expected:
                    raise ValueError('Gemfile.lock SHA256 mismatch')
                members = members_from_gem(data)
                record.update(source_url=url, sha256=digest,
                              checksum_status='matches_lock' if expected else 'not_in_lock')
            else:
                raise ValueError('GIT source unsupported by this fetcher; no GIT entries in pinned lock')
            inventory = []
            for name, contents, kind in members:
                path = pathlib.PurePosixPath(name)
                if path.is_absolute() or '..' in path.parts:
                    raise ValueError('unsafe archive path')
                inventory.append(dict(path=name, kind=kind))
                if contents is not None:
                    target = directory / name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(contents)
            (directory / '_inventory.json').write_text(json.dumps(inventory))
            record.update(status='fetched', source_directory=str(directory), error='')
        except Exception as exc:
            record.update(status='fetch_failed', error=f'{type(exc).__name__}: {exc}')
        return record

    fetched = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
        futures = [pool.submit(fetch, s) for s in specs]
        for i, future in enumerate(concurrent.futures.as_completed(futures), 1):
            result = future.result()
            fetched.append(result)
            if i % 50 == 0 or result['status'] != 'fetched':
                print(f'Fetched {i}/{len(specs)}: {result["gem"]} {result["status"]}', flush=True)
    # Generic packages can supply published source omitted from binary platform packages.
    covered = {(r['gem'], r['version']) for r in fetched if r['status'] == 'fetched'
               and any(p.suffix in NATIVE for p in pathlib.Path(r['source_directory']).rglob('*'))}
    supplementary = {}
    for r in fetched:
        if r['status'] != 'fetched' or (r['gem'], r['version']) in covered:
            continue
        inv = json.loads((pathlib.Path(r['source_directory']) / '_inventory.json').read_text())
        if any(pathlib.PurePosixPath(p['path']).suffix in {'.so', '.bundle', '.dll'} for p in inv):
            key = (r['gem'], r['version'])
            if not any(s['gem'] == key[0] and s['locked_version'] == key[1] for s in specs):
                supplementary[key] = dict(r, locked_version=r['version'], source_type='GEM',
                                          remote='https://rubygems.org/', supplementary=True)
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        for result in pool.map(fetch, supplementary.values()):
            fetched.append(result)
            print(f'Supplementary source: {result["gem"]} {result["status"]}', flush=True)
    fetched.sort(key=lambda r: (r['gem'], r['locked_version']))
    (args.out / 'fetch-manifest.json').write_text(json.dumps(fetched, indent=2) + '\n')
    write_csv(args.out / 'fetch-failures.csv', [r for r in fetched if r['status'] != 'fetched'],
              ['gem', 'version', 'locked_version', 'source_type', 'remote', 'supplementary', 'error'])
    (args.out / 'provenance.json').write_text(json.dumps(dict(
        gitlab_url='https://gitlab.com/gitlab-org/gitlab.git', gitlab_sha=sha,
        default_branch='master', lock_sha256=hashlib.sha256(lock.encode()).hexdigest()), indent=2) + '\n')
    print(f'Finished: {len(specs)} locked entries, {len(fetched)} fetch records', flush=True)

if __name__ == '__main__':
    main()

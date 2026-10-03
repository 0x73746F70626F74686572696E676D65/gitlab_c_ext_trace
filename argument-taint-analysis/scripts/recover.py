#!/usr/bin/env python3
"""Restore inert, version-pinned published native sources; execute no target code."""
import argparse, concurrent.futures, csv, hashlib, io, json, tarfile, urllib.request
from pathlib import Path, PurePosixPath

NATIVE = {'.c', '.h', '.cc', '.cpp', '.cxx', '.hpp', '.hh', '.inc', '.inl', '.m', '.mm', '.in', '.y', '.rl'}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--repo', type=Path, required=True)
    ap.add_argument('--cache', type=Path, required=True)
    ap.add_argument('--native-data', type=Path, required=True)
    ap.add_argument('--out', type=Path, required=True)
    args = ap.parse_args()
    cat = args.repo / 'static-catalog'
    manifest = json.loads((cat / 'fetch-manifest.json').read_text())
    current = {(r['gem'], r['locked_version']): r for r in manifest}
    scanned = list(csv.DictReader((cat / 'files-scanned.csv').open()))
    needed = {(r['gem'], r['source_variants'].split(';')[0]) for r in scanned}
    gems = {r['gem_id']: r for l in (args.native_data / 'gems.jsonl').open()
            if (r := json.loads(l))}
    for l in (args.native_data / 'c_registrations.jsonl').open():
        r = gems[json.loads(l)['gem_id']]
        needed.add((r['name'], r['version']))
    args.cache.mkdir(parents=True, exist_ok=True)
    (args.cache / 'packages').mkdir(exist_ok=True)
    frozen_path = args.out / 'source-manifest.json'
    published_frozen=args.out/'published-source-manifest.json'
    frozen_basis=published_frozen if published_frozen.exists() else frozen_path
    frozen = {(r['gem'], r['locked_version']): r for r in
              json.loads(frozen_basis.read_text()) if 'package_sha256' in r} if frozen_basis.exists() else {}

    def restore(key):
        gem, version = key
        old = current.get(key, {})
        url = old.get('source_url', f'https://rubygems.org/downloads/{gem}-{version}.gem')
        assert url.startswith('https://rubygems.org/downloads/')
        package = args.cache / 'packages' / f'{gem}-{version}.gem'
        if not package.exists():
            with urllib.request.urlopen(url, timeout=60) as response:
                package.write_bytes(response.read())
        data = package.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        expected = old.get('sha256') or frozen.get(key, {}).get('package_sha256')
        if expected and digest != expected:
            raise ValueError(f'package digest mismatch: {key}')
        directory = args.cache / 'sources' / f'{gem}-{version}'
        sources, metadata = [], []
        with tarfile.open(fileobj=io.BytesIO(data)) as outer:
            payload = outer.extractfile('data.tar.gz').read()
        with tarfile.open(fileobj=io.BytesIO(payload), mode='r:gz') as inner:
            for member in inner:
                if not member.isfile():
                    continue
                rel = PurePosixPath(member.name.removeprefix('./'))
                if rel.is_absolute() or '..' in rel.parts:
                    raise ValueError('unsafe archive member')
                if rel.name == 'extconf.rb':
                    metadata.append(str(rel))
                if rel.suffix not in NATIVE and rel.name != 'extconf.rb':
                    continue
                contents = inner.extractfile(member).read()
                path = directory / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(contents)
                if rel.suffix in NATIVE:
                    sources.append(dict(file=str(rel), sha256=hashlib.sha256(contents).hexdigest(),
                                        bytes=len(contents)))
        hashes = {r['file']: r['sha256'] for r in sources}
        required = [r for r in scanned if (r['gem'], r['source_variants'].split(';')[0]) == key]
        for r in required:
            assert hashes[r['file']] == r['sha256'], (key, r['file'])
        record = dict(gem=gem, version=old.get('version', version), locked_version=version,
                      source_url=url, package_sha256=digest, directory=str(directory),
                      hash_basis='work_catalogue' if old else 'frozen_published_version',
                      verified_catalogue_files=len(required), source_files=sorted(sources, key=lambda r:r['file']),
                      extension_metadata=sorted(metadata))
        print(f'{gem} {version}: {len(sources)} source files, {len(required)} catalogue hashes checked', flush=True)
        return record

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        records = list(pool.map(restore, sorted(needed)))
    args.out.mkdir(parents=True, exist_ok=True)
    frozen_path.write_text(json.dumps(records, indent=2, sort_keys=True) + '\n')
    print(f'RESTORED {len(records)} packages; {sum(r["verified_catalogue_files"] for r in records)} catalogue files verified', flush=True)

if __name__ == '__main__':
    main()

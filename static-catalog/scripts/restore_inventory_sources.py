#!/usr/bin/env python3
"""Restore only catalogued native-source variants from locked package bytes."""
import concurrent.futures, csv, hashlib, json, pathlib, urllib.request
from fetch_sources import members_from_gem

OUT = pathlib.Path(__file__).resolve().parents[1]

def main():
    files = list(csv.DictReader((OUT / 'files-scanned.csv').open()))
    manifest = json.loads((OUT / 'fetch-manifest.json').read_text())
    needed = {(r['gem'], r['source_variants'].split(';')[0]) for r in files}
    selected = [r for r in manifest if (r['gem'], r['locked_version']) in needed]
    locked = {(r['gem'], r['locked_version']) for r in csv.DictReader((OUT / 'locked-gems.csv').open())}
    cache = pathlib.Path('/workspace/static-catalog-cache/packages')
    cache.mkdir(parents=True, exist_ok=True)

    def restore(record):
        directory = pathlib.Path(record['source_directory'])
        required = [r for r in files if (r['gem'], r['source_variants'].split(';')[0]) ==
                    (record['gem'], record['locked_version'])]
        present = all((directory / r['file']).is_file() and
                      hashlib.sha256((directory / r['file']).read_bytes()).hexdigest() == r['sha256']
                      for r in required)
        result = dict(gem=record['gem'], version=record['version'],
                      locked_version=record['locked_version'], source_url=record['source_url'],
                      source_directory=str(directory), source_files=len(required))
        if present:
            return dict(result, action='reused', status='verified')
        if record['source_type'] != 'GEM' or (record['gem'], record['locked_version']) not in locked:
            raise ValueError('Missing source is not a locked GEM package: ' + record['gem'])
        package = cache / (record['gem'] + '-' + record['locked_version'] + '.gem')
        if package.exists():
            data = package.read_bytes()
        else:
            with urllib.request.urlopen(record['source_url'], timeout=60) as response:
                data = response.read()
            package.write_bytes(data)
        digest = hashlib.sha256(data).hexdigest()
        if digest != record['sha256']:
            raise ValueError('Package SHA256 mismatch: ' + record['gem'])
        members = members_from_gem(data)
        for name, contents, kind in members:
            path = pathlib.PurePosixPath(name)
            if path.is_absolute() or '..' in path.parts:
                raise ValueError('Unsafe archive path')
            if contents is not None:
                target = directory / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(contents)
        directory.mkdir(parents=True, exist_ok=True)
        (directory / '_inventory.json').write_text(json.dumps(
            [dict(path=name, kind=kind) for name, _, kind in members]))
        for r in required:
            if hashlib.sha256((directory / r['file']).read_bytes()).hexdigest() != r['sha256']:
                raise ValueError('Catalog source digest mismatch: ' + r['file'])
        return dict(result, action='downloaded_locked_package', package_sha256=digest, status='verified')

    restored = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        for result in pool.map(restore, selected):
            restored.append(result)
            print(f"{len(restored)}/{len(selected)} {result['gem']}: {result['action']}", flush=True)
    (OUT / 'argument-inventory-sources.json').write_text(json.dumps(restored, indent=2) + '\n')

if __name__ == '__main__':
    main()

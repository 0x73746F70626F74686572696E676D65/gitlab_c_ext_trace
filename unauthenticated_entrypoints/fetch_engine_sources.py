#!/usr/bin/env python3
"""Fetch locked routing-framework Ruby sources; do not install or execute gems."""
import argparse, hashlib, io, json, re, tarfile, urllib.request
from pathlib import Path

ENGINES = ['devise', 'doorkeeper', 'doorkeeper-openid_connect', 'doorkeeper-device_authorization_grant']

def fetch(source, destination):
    lock = (source / 'Gemfile.lock').read_text()
    destination.mkdir(parents=True, exist_ok=True)
    for name in ENGINES:
        match = re.search(r'^  ' + re.escape(name) + r' \(([^)]+)\) sha256=([0-9a-f]{64})$', lock, re.M)
        if not match:
            raise ValueError('Missing locked version/checksum: ' + name)
        version, expected = match.groups()
        url = f'https://rubygems.org/downloads/{name}-{version}.gem'
        with urllib.request.urlopen(url, timeout=60) as response:
            data = response.read()
        if hashlib.sha256(data).hexdigest() != expected:
            raise ValueError('Gem archive checksum mismatch: ' + name)
        with tarfile.open(fileobj=io.BytesIO(data)) as archive:
            payload = archive.extractfile('data.tar.gz').read()
        root = destination / f'{name}-{version}'
        root.mkdir(exist_ok=True)
        with tarfile.open(fileobj=io.BytesIO(payload), mode='r:gz') as archive:
            for member in archive.getmembers():
                path = root / member.name
                if not path.resolve().is_relative_to(root.resolve()) or member.issym() or member.islnk():
                    raise ValueError('Unsafe archive member: ' + member.name)
                if member.isdir():
                    path.mkdir(parents=True, exist_ok=True)
                elif member.isfile():
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(archive.extractfile(member).read())
        manifest = {'gem': name, 'version': version, 'url': url, 'sha256': expected,
                    'compiled_or_executed': False,
                    'source_files': {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
                                     for p in sorted(root.rglob('*')) if p.is_file()}}
        (destination / f'{name}-{version}.json').write_text(json.dumps(manifest, indent=2) + '\n')
        print(name, version, expected)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, default=Path('/workspace/gitlab-frontend-source'))
    parser.add_argument('--output', type=Path, default=Path('/workspace/auth-route-engine-sources'))
    args = parser.parse_args()
    fetch(args.source, args.output)

#!/usr/bin/env python3
"""Inventory every work-branch data container, retaining native/flow evidence.

Archives and pickle files are read as bytes only. No saved scripts are executed.
"""
import argparse, csv, gzip, hashlib, io, json, lzma, tarfile
from pathlib import Path

class DigestReader:
    def __init__(self, f): self.f, self.h, self.n = f, hashlib.sha256(), 0
    def read(self, n=-1):
        b = self.f.read(n); self.h.update(b); self.n += len(b); return b
    def readable(self): return True
    def seekable(self): return False
    def close(self): pass

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--repo', type=Path, required=True)
    ap.add_argument('--out', type=Path, required=True)
    ap.add_argument('--cache', type=Path, required=True)
    args = ap.parse_args(); args.out.mkdir(parents=True, exist_ok=True); args.cache.mkdir(parents=True, exist_ok=True)
    inventory, retained, seen = [], [], set()
    reg_ids, api_ids = set(), set()
    def inspect(stream, container, name, size):
        d = DigestReader(stream)
        packed = name.endswith('.gz') and not name.endswith('.tar.gz')
        data = gzip.GzipFile(fileobj=d) if packed else d
        suffix = Path(name.removesuffix('.gz')).suffix
        record = dict(container=container, member=name, bytes=size)
        native = Path(name).name.startswith('native_') or any(w in name.lower() for w in ['c_registrations', 'c_functions', 'c_primitives', 'c_calls', 'c_reachability', 'c_files', 'c_wrappers', 'c_namespaces', 'gems.json', 'source_aliases', 'gem_source_coverage', 'retained_source_coverage',
                     'native_source', 'argument', 'input_flow', 'mechanism', 'census_results', 'gem_api'])
        # Complete native tables are copied once, for analysis/joining. Other ledgers
        # are kept by digest with their original path; frontend connectivity stays inventory-only.
        if native and suffix in {'.jsonl', '.csv', '.json'}:
            chunks = []
            try:
                while chunk := data.read(65536): chunks.append(chunk)
            except (EOFError, OSError) as exc:
                record['container_error'] = str(exc)
            b = b''.join(chunks); digest = hashlib.sha256(b).hexdigest()
            if digest not in seen:
                seen.add(digest)
                target = args.cache / (digest + suffix)
                target.write_bytes(b)
                retained.append(dict(container=container, member=name, sha256=digest, path=str(target)))
            try:
                if suffix == '.jsonl':
                    rows = []
                    for line in b.splitlines():
                        if not line.strip(): continue
                        try: rows.append(json.loads(line))
                        except ValueError:
                            record['malformed_jsonl_lines'] = record.get('malformed_jsonl_lines', 0) + 1
                elif suffix == '.csv':
                    rows = list(csv.DictReader(io.StringIO(b.decode('utf-8', errors='replace'))))
                else:
                    obj = json.loads(b); rows = obj if isinstance(obj, list) else [obj]
                record['records'] = len(rows)
                record['fields'] = sorted({k for r in rows[:500] if isinstance(r, dict) for k in r})
                for r in rows:
                    if not isinstance(r, dict): continue
                    for k in ('registration_id', 'c_registration_id', 'native_registration_id'):
                        if r.get(k): reg_ids.add(str(r[k]))
                    for k in ('api_id', 'gem_api_id'):
                        if r.get(k): api_ids.add(str(r[k]))
                    reg_ids.update(str(x) for x in r.get('registration_ids', []) if isinstance(r.get('registration_ids'), list))
            except Exception as exc:
                record['parse_error'] = str(exc)[:240]
        else:
            # Only candidate evidence requires decompression; hash other members as saved.
            while d.read(1024*1024): pass
        # Consume any trailing compressed bytes, ensuring the checksum covers the whole member.
        while d.read(1024*1024): pass
        record['sha256'] = d.h.hexdigest(); inventory.append(record)

    files = sorted(p for p in args.repo.rglob('*') if p.is_file() and '.git' not in p.parts
                   and 'argument-taint-analysis' not in p.parts)
    archives, ordinary, parts = [], [], {}
    for p in files:
        if '.tar.' in p.name and '.part' in p.name:
            stem = p.name.split('.part')[0]; parts.setdefault((p.parent, stem), []).append(p)
        elif p.name.endswith(('.tar.gz', '.tar.xz')): archives.append(p)
        else: ordinary.append(p)
    for (parent, stem), group in sorted(parts.items()):
        target = args.cache / stem
        with target.open('wb') as out:
            for p in sorted(group):
                with p.open('rb') as f:
                    while b := f.read(1024*1024): out.write(b)
        archives.append(target)
    for p in sorted(archives):
        print('Scavenging archive:', p.name, flush=True)
        with tarfile.open(p, mode='r|*') as archive:
            for member in archive:
                if member.isfile(): inspect(archive.extractfile(member), p.name, member.name, member.size)
    for p in ordinary:
        rel = str(p.relative_to(args.repo))
        with p.open('rb') as f: inspect(f, 'work-tree', rel, p.stat().st_size)
    inventory.sort(key=lambda r:(r['container'],r['member']))
    retained.sort(key=lambda r:(r['container'],r['member']))
    for name, rows in [('scavenged-files.jsonl', inventory), ('scavenged-native-evidence.jsonl', retained)]:
        with (args.out/name).open('w') as f:
            for r in rows: f.write(json.dumps(r,sort_keys=True)+'\n')
    summary = dict(containers=len(archives), files=len(inventory), native_evidence_files=len(retained),
                   registration_ids=sorted(reg_ids), api_ids=sorted(api_ids),
                   parse_errors=[r for r in inventory if any(k in r for k in ('parse_error','container_error','malformed_jsonl_lines'))])
    (args.out/'scavenge-summary.json').write_text(json.dumps(summary,indent=2,sort_keys=True)+'\n')
    print('SCAVENGED', len(inventory), 'files;', len(retained), 'distinct native evidence datasets', flush=True)

if __name__ == '__main__': main()

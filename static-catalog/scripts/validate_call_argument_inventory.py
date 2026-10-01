#!/usr/bin/env python3
"""Check inventory/source integrity using parsers and inert fixtures only."""
import collections, csv, gzip, hashlib, json, pathlib, re, unittest
from call_argument_inventory import (FIELDS, Inventory, dedup_key, slots, store_parts)
from catalog import PARSERS, arguments, callee, compact, text, walk
from entry_catalog import select_source_files

OUT = pathlib.Path(__file__).resolve().parents[1]
JSON_FIELDS = {'argument_labels', 'slot_labels', 'visible_parameters'}
INT_FIELDS = {'argument_index', 'site_line', 'hop_count', 'slot_argument_index', 'registration_line'}

def csv_records(path):
    with path.open(newline='') as handle:
        return list(csv.DictReader(handle))

def json_records(path):
    with path.open() as handle:
        return [json.loads(line) for line in handle if line.strip()]

def main():
    sources, data, lines = {}, {}, {}
    for record in select_source_files(OUT):
        key = record['gem'], record['file']
        blob = pathlib.Path(record['absolute_path']).read_bytes()
        assert hashlib.sha256(blob).hexdigest() == record['sha256'], key
        sources[key], data[key], lines[key] = record, blob, blob.splitlines()
    summary = json.loads((OUT / 'summary.json').read_text())
    assert summary['lock_sha256'] == hashlib.sha256((OUT / 'Gemfile.lock').read_bytes()).hexdigest()
    checksums = {(m[1], m[2]): m[3] for m in re.finditer(
        r'^  (\S+) \(([^)]+)\) sha256=([0-9a-f]+)$', (OUT / 'Gemfile.lock').read_text(), re.M)}
    restored = json.loads((OUT / 'argument-inventory-sources.json').read_text())
    for record in restored:
        package = pathlib.Path('/workspace/static-catalog-cache/packages') / (
            record['gem'] + '-' + record['locked_version'] + '.gem')
        if package.exists():
            assert hashlib.sha256(package.read_bytes()).hexdigest() == checksums[(record['gem'], record['locked_version'])]

    entries = csv_records(OUT / 'entry-points.csv')
    entry_map = {e['entry_id']: e for e in entries}
    roots = json_records(OUT / 'argument-inventory-roots.jsonl')
    assert len(roots) == len(entries) == summary['roots']
    assert {r['entry_id'] for r in roots} == set(entry_map)
    for entry in entries:
        key = entry['gem'], entry['registration_file']
        line = int(entry['registration_line'])
        assert entry['registration'].encode() in lines[key][line-1], entry['entry_id']

    rows = json_records(OUT / 'entry-argument-sites.jsonl')
    normalized = [{k: json.loads(v) if k in JSON_FIELDS else int(v) if k in INT_FIELDS else v
                   for k, v in row.items()} for row in csv_records(OUT / 'entry-argument-sites.csv')]
    assert normalized == rows
    assert len(rows) == summary['rows'] == summary['kept_rows']
    assert len({dedup_key(r) for r in rows}) == len(rows)
    assert dict(collections.Counter(r['slot'] for r in rows)) == summary['rows_by_slot']
    assert dict(collections.Counter(r['argument_label'].split('(')[0] for r in rows)) == summary['rows_by_argument_label']
    nodes_by_file = {}

    def check_row(row):
        assert set(row) == set(FIELDS)
        assert row['entry_id'] in entry_map
        entry = entry_map[row['entry_id']]
        for key in ['gem', 'version', 'ruby_method_name', 'ruby_receiver', 'c_function', 'registration_file']:
            assert row[key] == entry[key]
        assert row['argument_index'] >= 0 and row['hop_count'] >= 0
        if int(entry['arity']) >= 0:
            assert row['argument_index'] < int(entry['arity'])
        assert row['slot'] in {'length', 'size', 'index', 'format'}
        assert row['argument_label'].split('(')[0] in {'param', 'sizeof', 'literal', 'local', 'other'}
        assert row['argument_index'] in {p['index'] for p in row['visible_parameters']}
        assert len(row['path'].split(' -> ')) == row['hop_count'] + 1
        key = row['gem'], row['site_file']
        assert 0 < row['site_line'] <= len(lines[key])
        if key not in nodes_by_file:
            blob = data[key]
            tree = PARSERS[sources[key]['parser']].parse(blob)
            nodes = collections.defaultdict(list)
            for node in walk(tree.root_node):
                if node.type == 'call_expression' or store_parts(node, blob):
                    nodes[node.start_point.row+1].append(node)
            nodes_by_file[key] = (tree, nodes)
        blob, candidates = data[key], nodes_by_file[key][1][row['site_line']]
        matching = False
        for node in candidates:
            if row['callee_or_store'] == 'indexed-store':
                store = store_parts(node, blob)
                if not store:
                    continue
                left, index = store
                rhs = node.child_by_field_name('right')
                aa = [left] + ([rhs] if rhs else [])
                ss = [('index', -1, index)]
            else:
                if node.type != 'call_expression' or callee(node, blob) != row['callee_or_store']:
                    continue
                aa, ss = arguments(node), slots(callee(node, blob), arguments(node))
            if [compact(text(a, blob)) for a in aa] != [a['expression'] for a in row['argument_labels']]:
                continue
            for kind, position, expression in ss:
                if kind != row['slot'] or position != row['slot_argument_index']:
                    continue
                expected = compact(text(expression, blob)) if expression else 'sizeof(' + text(aa[0], blob) + ')'
                if expected == row['slot_expression']:
                    matching = True
        assert matching, (key, row['site_line'], row['callee_or_store'], row['slot_expression'])
        assert any(s['slot'] == row['slot'] and s['argument_index'] == row['slot_argument_index']
                   and s['expression'] == row['slot_expression'] for s in row['slot_labels'])

    for row in rows:
        check_row(row)
    collisions = json_records(OUT / 'argument-inventory-dedup-collisions.jsonl')
    assert len(collisions) == summary['dedup_keys_with_distinct_alternatives']
    by_key = {dedup_key(r): r for r in rows}
    alternative_count = 0
    for collision in collisions:
        key = tuple(collision['key'])
        assert collision['representative'] == by_key[key]
        for row in collision['alternatives']:
            assert dedup_key(row) == key
            check_row(row)
            alternative_count += 1

    unresolved_count, reasons, hop_keys = 0, collections.Counter(), set()
    with gzip.open(OUT / 'unresolved-hops.csv.gz', 'rt', newline='') as handle:
        for hop in csv.DictReader(handle):
            unresolved_count += 1
            reasons[hop['reason']] += 1
            key = hop['gem'], hop['file']
            assert hop['entry_id'] in entry_map
            assert 0 < int(hop['line']) <= len(lines[key]), (key, hop['line'])
            assert len(hop['path'].split(' -> ')) == int(hop['hop_count'])+1
            unique = hop['entry_id'], hop['file'], hop['line'], hop['target'], hop['reason']
            assert unique not in hop_keys
            hop_keys.add(unique)
            assert all(isinstance(i, int) and i >= 0 for i in json.loads(hop['argument_indices']))
    assert unresolved_count == summary['unresolved_hops']
    assert dict(reasons) == summary['unresolved_hops_by_reason']
    suite = unittest.defaultTestLoader.discover(str(OUT / 'scripts'), pattern='test_*.py')
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    assert result.wasSuccessful()
    validation = dict(status='passed', source_digests_verified=len(sources),
        restored_locked_package_variants=len(restored), registrations_checked=len(entries),
        inventory_rows_checked=len(rows), collision_alternatives_checked=alternative_count,
        unresolved_source_references_checked=unresolved_count, parser_tests=result.testsRun,
        csv_jsonl_agreement=True, requested_deduplication_key_verified=True,
        target_code_executed=False)
    (OUT / 'validation.json').write_text(json.dumps(validation, indent=2) + '\n')
    files = sorted(p for p in OUT.rglob('*') if p.is_file() and p.name != 'SHA256SUMS'
                   and '__pycache__' not in p.parts and p.suffix != '.pyc')
    (OUT / 'SHA256SUMS').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest() +
        '  ' + str(p.relative_to(OUT)) + '\n' for p in files))
    print(json.dumps(validation, indent=2))

if __name__ == '__main__':
    main()

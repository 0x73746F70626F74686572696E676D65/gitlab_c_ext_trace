#!/usr/bin/env python3
"""Document evidence limits of saved rows; never load or analyze target code."""
import argparse
import collections
import csv
import hashlib
import io
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
CATALOG = HERE.parent
INPUTS = ('entry-argument-sites.jsonl', 'entry-argument-sites.csv',
          'argument-inventory-roots.jsonl', 'summary.json',
          'scripts/call_argument_inventory.py')


def digest(blob):
    return hashlib.sha256(blob).hexdigest()


def annotate(row, root, line, root_line, raw):
    depth = row['hop_count']
    path = row['path'].split(' -> ')
    assert depth >= 0 and len(path) == depth + 1
    assert path[0] == row['c_function'] and path[-1] == row['site_function']
    index = row['argument_index']
    names = root['parameter_names']
    fixed = (int(root['arity']) >= 0 and index < int(root['arity'])
             and index + 1 < len(names) and names[index + 1] == row['parameter_name'])
    assert {'index': index, 'name': row['parameter_name']} in row['visible_parameters']
    return dict(
        inventory_line=line, inventory_row_sha256=digest(raw),
        inventory_evidence=f'../entry-argument-sites.jsonl:{line}',
        root_evidence=f'../argument-inventory-roots.jsonl:{root_line}',
        argument_origin=('fixed_arity_root_formal' if fixed else
                         'positional_binding_exact_extraction_not_serialized'),
        origin_scope='ruby_positional_identity_only',
        call_depth=depth, call_depth_basis='saved_shortest_syntactic_helper_context',
        parameter_identity=f"{row['entry_id']}#ruby_argument[{index}]",
        parameter_name_semantics='origin_binding_label_not_value_identity',
        nested_parameter_identity=('no_helper_hops' if depth == 0 else
                                   'per_hop_formal_bindings_not_serialized'),
        value_preservation='not_established',
        local_checks='not_assessed_by_saved_inventory',
        local_checks_evidence='../scripts/call_argument_inventory.py:345-398',
        source_reinspection='not_performed_source_cache_absent',
    )


def generate(catalog=CATALOG):
    blobs = {name: (catalog / name).read_bytes() for name in INPUTS}
    roots = {r['entry_id']: (line, r)
             for line, raw in enumerate(blobs['argument-inventory-roots.jsonl'].splitlines(), 1)
             for r in [json.loads(raw)]}
    rows = [json.loads(raw) for raw in blobs['entry-argument-sites.jsonl'].splitlines()]
    csv_rows = list(csv.DictReader(io.StringIO(blobs['entry-argument-sites.csv'].decode())))
    ints = {'argument_index', 'site_line', 'hop_count', 'slot_argument_index', 'registration_line'}
    arrays = {'argument_labels', 'slot_labels', 'visible_parameters'}
    normalized = [{k: int(v) if k in ints else json.loads(v) if k in arrays else v
                   for k, v in row.items()} for row in csv_rows]
    assert normalized == rows
    assert len(rows) == json.loads(blobs['summary.json'])['rows']
    result = []
    for line, (row, raw) in enumerate(zip(rows, blobs['entry-argument-sites.jsonl'].splitlines()), 1):
        root_line, root = roots[row['entry_id']]
        result.append(annotate(row, root, line, root_line, raw))
    jsonl = ''.join(json.dumps(r, sort_keys=True) + '\n' for r in result)
    output = io.StringIO(newline='')
    writer = csv.DictWriter(output, fieldnames=list(result[0]), lineterminator='\n')
    writer.writeheader()
    writer.writerows(result)
    report = dict(status='passed_saved_metadata_checks', rows=len(result),
                  input_sha256={name: digest(blob) for name, blob in blobs.items()},
                  csv_jsonl_agreement=True, root_joins_checked=len(result),
                  depth_and_endpoint_checks=len(result),
                  counts={key: dict(sorted(collections.Counter(str(r[key]) for r in result).items()))
                          for key in ('argument_origin', 'call_depth', 'nested_parameter_identity', 'local_checks')},
                  source_reinspection=False, target_code_executed=False,
                  full_source_validator='blocked: source cache and tree_sitter dependency absent')
    unresolved = []
    for row in result:
        gaps = ['local_checks_not_assessed', 'value_preservation_not_established',
                'source_reinspection_not_performed']
        if row['argument_origin'] != 'fixed_arity_root_formal':
            gaps.append('exact_positional_extraction_not_serialized')
        if row['call_depth']:
            gaps.append('per_hop_formal_identity_not_serialized')
        unresolved.append(dict(inventory_line=row['inventory_line'],
                               inventory_row_sha256=row['inventory_row_sha256'],
                               inventory_evidence=row['inventory_evidence'],
                               status='open_evidence_gap', gaps=gaps,
                               assessment='unknown_not_absent_or_unsafe'))
    report['unresolved_rows'] = len(unresolved)
    report['overlapping_gap_counts'] = dict(sorted(collections.Counter(
        gap for row in unresolved for gap in row['gaps']).items()))
    return {'rows.jsonl': jsonl, 'rows.csv': output.getvalue(),
            'unresolved-rows.jsonl': ''.join(json.dumps(r, sort_keys=True) + '\n' for r in unresolved),
            'validation.json': json.dumps(report, indent=2, sort_keys=True) + '\n'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true', help='compare saved outputs without writing')
    args = parser.parse_args()
    outputs = generate()
    for name, content in outputs.items():
        if args.check:
            assert (HERE / name).read_bytes() == content.encode(), name
        else:
            (HERE / name).write_bytes(content.encode())
    print('PASS: 353-row metadata regeneration and evidence joins' if args.check else 'Wrote metadata companion')


if __name__ == '__main__':
    main()

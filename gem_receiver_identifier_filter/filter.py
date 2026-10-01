#!/usr/bin/env python3
"""Filter saved rows by source syntax; never traverse the entrypoint graph."""
import collections
import csv
import gzip
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(REPO / 'depth_limited_name_match'))
from walk import Walker, arguments, descendants, field, text, underscore

SOURCE = Path('/workspace/gitlab')
INPUT = REPO / 'depth_limited_name_match/matches.csv.gz'
CATALOG = REPO / 'static-catalog/entry-argument-sites.csv'
OWNERSHIP = REPO / 'frontend_gem_api_map/api_catalog.jsonl'
BASE_SHA = 'ed3b8897982d4b040858cb8c74a9a9d0860d73b1'
IDENTIFIERS = {'identifier', 'constant', 'scope_resolution', 'instance_variable', 'class_variable', 'global_variable', 'self'}
CONSTANT = re.compile(r'^(?:::)?[A-Z]\w*(?:::[A-Z]\w*)*$')
CORE = {'Object', 'Kernel', 'Array', 'Hash', 'String', 'Symbol', 'Integer', 'Float', 'Regexp',
        'Time', 'IO', 'TrueClass', 'FalseClass', 'NilClass', 'BasicObject', 'Class', 'Module'}
CONDITIONAL = {'if', 'unless', 'if_modifier', 'unless_modifier', 'case', 'when', 'while', 'until',
               'for', 'rescue', 'conditional', 'elsif'}


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def scopes(node):
    ancestors = []
    p = node.parent
    while p:
        if p.type in {'class', 'module'}:
            ancestors.append(p)
        p = p.parent
    result = []
    for n in reversed(ancestors):
        name = text(field(n, 'name'))
        owner = name.lstrip(':') if name.startswith('::') or not result else result[-1] + '::' + name
        result.append(owner)
    return tuple(reversed(result))


def namespace_manifest():
    owners = collections.defaultdict(set)
    ids = collections.defaultdict(list)
    for line in OWNERSHIP.read_text().splitlines():
        row = json.loads(line)
        namespace = row.get('namespace')
        if row.get('identity_status') != 'recorded_single_owner' or not namespace or not CONSTANT.fullmatch(namespace):
            continue
        root = namespace.split('::')[0]
        # Generic Ruby classes have registrations supplied by several extensions;
        # their name alone does not attribute ordinary calls to an extension.
        if root in CORE:
            if namespace == root:
                continue
            prefix = namespace
        else:
            prefix = root
        owners[prefix].add(row['gem'])
        ids[prefix].append(row['id'])
    resolved = {p: next(iter(gems)) for p, gems in owners.items() if len(gems) == 1}
    manifest = {'source': str(OWNERSHIP.relative_to(REPO)), 'source_sha256': sha(OWNERSHIP),
                'accepted_prefixes': [{'prefix': p, 'gem': g, 'api_ids': sorted(set(ids[p]))}
                                      for p, g in sorted(resolved.items())],
                'ambiguous_prefixes_dropped': {p: sorted(g) for p, g in owners.items() if len(g) > 1},
                'generic_core_constants_excluded': sorted(CORE)}
    return resolved, manifest


class SourceFilter:
    def __init__(self, source, providers, expected_hashes):
        self.source = source
        # Reuse the saved row generator's syntax extractor only. Never call
        # root, lookup, target, or any method that follows another Ruby body.
        self.syntax = Walker(source)
        self.providers = providers
        self.expected_hashes = expected_hashes
        self.facts = {}
        self.site_cache = {}
        self.constant_cache = {}

    def load(self, file):
        info = self.syntax.load(file)
        if not info:
            return None
        if file in self.expected_hashes:
            assert info['sha256'] == self.expected_hashes[file], ('Source changed', file)
        if file not in self.facts:
            facts = collections.defaultdict(list)
            for n in descendants(info['tree'].root_node):
                if n.type in {'class', 'module'}:
                    name = text(field(n, 'name'))
                    lexical = scopes(n)
                    full = name.lstrip(':') if name.startswith('::') or not lexical else lexical[0] + '::' + name
                    facts[full].append(('declaration', n))
                elif n.type == 'assignment' and CONSTANT.fullmatch(text(field(n, 'left'))):
                    name = text(field(n, 'left'))
                    lexical = scopes(n)
                    full = name.lstrip(':') if name.startswith('::') or not lexical else lexical[0] + '::' + name
                    facts[full].append(('alias', n))
            self.facts[file] = facts
        return info

    def provider(self, name):
        matches = [(p, g) for p, g in self.providers.items() if name == p or name.startswith(p + '::')]
        gems = {g for _, g in matches}
        return next(iter(gems)) if len(gems) == 1 else None

    def conventional_files(self, name):
        rel = underscore(name) + '.rb'
        return [base + '/' + rel for base in self.syntax.bases + ['ee/' + b for b in self.syntax.bases]
                if (self.source / (base + '/' + rel)).is_file()]

    def constant(self, name, node, file, seen=()):
        if not CONSTANT.fullmatch(name):
            return None, 'non_constant'
        lexical = scopes(node)
        key = (file, lexical, name)
        if key in seen:
            return None, 'constant_alias_cycle'
        if key in self.constant_cache:
            return self.constant_cache[key]
        names = [name.lstrip(':')] if name.startswith('::') else [p + '::' + name for p in lexical] + [name]
        result = (None, 'constant_owner_unresolved')
        self.load(file)
        for candidate in names:
            bindings = list(self.facts[file].get(candidate, []))
            # Read only conventional files for a receiver/alias constant. No
            # content search or Ruby-call traversal discovers additional files.
            if not bindings and not self.provider(candidate):
                for p in self.conventional_files(candidate):
                    self.load(p)
                    bindings.extend(self.facts[p].get(candidate, []))
            if bindings:
                aliases = [(kind, n) for kind, n in bindings if kind == 'alias']
                if len(aliases) == 1 and len(bindings) == 1:
                    n = aliases[0][1]
                    if self.conditional(n, None):
                        result = (None, 'conditional_constant_alias')
                    else:
                        alias_file = next((p for p, facts in self.facts.items()
                                           if any(other == n for _, other in facts.get(candidate, []))), file)
                        gem, why = self.value(field(n, 'right'), n, alias_file, None, seen + (key,))
                        result = (gem, 'constant_alias:' + why if gem else why)
                elif all(kind == 'declaration' for kind, _ in bindings):
                    gem = self.provider(candidate)
                    result = (gem, 'gem_namespace' if gem else 'gitlab_defined_constant')
                else:
                    result = (None, 'ambiguous_constant_binding')
                break
            gem = self.provider(candidate)
            if gem:
                result = (gem, 'gem_namespace')
                break
        self.constant_cache[key] = result
        return result

    def conditional(self, node, boundary):
        p = node.parent
        while p and p != boundary:
            if p.type in CONDITIONAL:
                return True
            p = p.parent
        return False

    def value(self, value, call, file, unit, seen=()):
        if not value:
            return None, 'no_receiver'
        raw = text(value)
        if CONSTANT.fullmatch(raw):
            return self.constant(raw, value, file, seen)
        if value.type == 'self':
            if unit and unit['node'].type == 'singleton_method':
                owner = field(unit['node'], 'object')
                if owner and CONSTANT.fullmatch(text(owner)):
                    gem, why = self.constant(text(owner), owner, file, seen)
                    return gem, 'singleton_self:' + why if gem else why
            lexical = scopes(value)
            if not lexical:
                return None, 'self_owner_unresolved'
            gem = self.provider(lexical[0])
            return gem, 'self_gem_namespace' if gem else 'self_not_gem'
        if value.type == 'call' and text(field(value, 'method')) == 'new':
            receiver = field(value, 'receiver')
            if receiver and CONSTANT.fullmatch(text(receiver)):
                gem, why = self.constant(text(receiver), receiver, file, seen)
                return gem, 'constructor:' + why if gem else why
            return None, 'constructor_owner_unresolved'
        if value.type in {'identifier', 'instance_variable', 'class_variable', 'global_variable'} and unit:
            variable_key = ('variable', file, unit['node'].start_byte, raw)
            if variable_key in seen:
                return None, 'variable_alias_cycle'
            assignments = [n for n in descendants(unit['body'], ('method', 'singleton_method', 'class', 'module', 'lambda'))
                           if n.type in {'assignment', 'operator_assignment'} and text(field(n, 'left')) == raw]
            if len(assignments) != 1 or assignments[0].end_byte >= call.start_byte:
                return None, 'variable_binding_unresolved'
            assignment = assignments[0]
            if assignment.type != 'assignment' or self.conditional(assignment, unit['body']):
                return None, 'conditional_variable_binding'
            def blocks(n):
                result = []
                p = n.parent
                while p and p != unit['body']:
                    if p.type in {'do_block', 'block'}:
                        result.append(p.start_byte)
                    p = p.parent
                return list(reversed(result))
            assigned_blocks, call_blocks = blocks(assignment), blocks(call)
            if assigned_blocks != call_blocks[:len(assigned_blocks)]:
                return None, 'variable_assignment_in_another_block'
            # Block parameters and nested lexical scopes can shadow a local.
            p = call.parent
            while p and p != unit['body']:
                if p.type in {'do_block', 'block'}:
                    params = field(p, 'parameters')
                    if any(text(n) == raw for n in descendants(params)):
                        return None, 'block_parameter_shadow'
                p = p.parent
            gem, why = self.value(field(assignment, 'right'), assignment, file, unit, seen + (variable_key,))
            return gem, 'local_alias:' + why if gem else why
        return None, 'receiver_value_unresolved'

    def candidates(self, row):
        chain = json.loads(row['call_chain'])
        tail = chain[-1]
        key = (row['file'], tail['line'], tail['method'], int(row['line']), row['ruby_method'])
        if key in self.site_cache:
            return self.site_cache[key]
        info = self.load(row['file'])
        if not info:
            self.site_cache[key] = []
            return []
        units = [u for u in info['definitions'] if u['line'] == tail['line']
                 and u['owner'] + '#' + u['name'] == tail['method']]
        if tail['method'].endswith('#<endpoint>'):
            for n, owner in info['declarations']:
                if n.start_point.row + 1 == tail['line'] and owner + '#<endpoint>' == tail['method'] and field(n, 'block'):
                    units.append({'owner': owner, 'name': '<endpoint>', 'file': row['file'], 'line': tail['line'],
                                  'node': n, 'body': field(field(n, 'block'), 'body')})
        results = []
        for unit in units:
            for call, name, receiver, argv in self.syntax.calls(unit):
                if call.start_point.row + 1 == int(row['line']) and name == row['ruby_method']:
                    results.append((unit, call, receiver, argv))
        self.site_cache[key] = results
        return results

    def decide(self, row):
        idx = int(row['argument_index'])
        candidates = []
        for unit, call, receiver, argv in self.candidates(row):
            visible = 0 <= idx < len(argv) and not any(a.type in {'splat_argument', 'hash_splat_argument'}
                                                      for a in argv[:idx + 1] if a)
            arg = argv[idx] if visible else None
            if text(arg) != row['expression']:
                continue
            gem, why = self.value(receiver, call, row['file'], unit)
            candidates.append((gem, why, receiver, arg, call))
        if not candidates:
            return 'receiver', 'saved_call_not_uniquely_located', '', '', ''
        if any(gem != row['gem'] for gem, *_ in candidates):
            first = candidates[0]
            reason = 'ambiguous_saved_call_receiver' if len(candidates) > 1 else first[1]
            if first[0] and first[0] != row['gem']:
                reason = 'receiver_resolves_to_different_gem'
            return 'receiver', reason, text(first[2]), first[0] or '', ''
        gem, why, receiver, arg, call = candidates[0]
        receivers = list(dict.fromkeys(text(c[2]) for c in candidates))
        receiver_text = ' | '.join(receivers)
        columns = ','.join(str(c[4].start_point.column + 1) for c in candidates)
        if any(a is None or a.type not in IDENTIFIERS for _, _, _, a, _ in candidates):
            if arg is None or not text(arg):
                why = 'empty_or_splat_obscured_argument'
            elif row['expression_kind'] == 'literal':
                why = 'literal_argument'
            elif arg.type == 'call' and text(field(arg, 'method')) in {'sizeof', 'size', 'bytesize', 'length'}:
                why = 'sizeof_equivalent_or_size_expression'
            else:
                why = 'non_identifier_expression'
            return 'argument', why, receiver_text, gem, columns
        if len(candidates) > 1:
            why = 'all_same_line_candidates_resolve_to_same_gem'
        return 'kept', why, receiver_text, gem, columns


def main():
    for p in [INPUT, CATALOG, OWNERSHIP]:
        original = subprocess.check_output(['git', '-C', str(REPO), 'show', BASE_SHA + ':' + str(p.relative_to(REPO))])
        assert hashlib.sha256(original).hexdigest() == sha(p), ('Input differs from requested commit', p)
    providers, manifest = namespace_manifest()
    expected = {r['file']: r['sha256'] for r in map(json.loads, (REPO / 'depth_limited_name_match/files_read.jsonl').read_text().splitlines())}
    sf = SourceFilter(SOURCE, providers, expected)
    with CATALOG.open(newline='') as f:
        catalog = {i: r for i, r in enumerate(csv.DictReader(f), 2)}
    counts = collections.Counter()
    reasons = collections.Counter()
    auth = collections.Counter()
    decision_cache = {}
    extra = ['receiver', 'resolved_gem', 'receiver_resolution', 'call_source_column', 'input_row']
    with gzip.open(INPUT, 'rt', newline='') as inf, \
         gzip.open(HERE / 'filtered_matches.csv.gz', 'wt', newline='') as outf, \
         gzip.open(HERE / 'decisions.csv.gz', 'wt', newline='') as df:
        reader = csv.DictReader(inf)
        writer = csv.DictWriter(outf, fieldnames=reader.fieldnames + extra, lineterminator='\n')
        writer.writeheader()
        dw = csv.writer(df, lineterminator='\n')
        dw.writerow(['input_row', 'decision', 'reason', 'receiver', 'resolved_gem'])
        for number, row in enumerate(reader, 2):
            counts['rows_in'] += 1
            table = catalog[int(row['argument_table_line'])]
            for out, src in [('gem', 'gem'), ('ruby_method', 'ruby_method_name'), ('argument_index', 'argument_index'), ('slot', 'slot')]:
                assert row[out] == table[src], ('Catalog mismatch', number)
            key = (row['file'], row['line'], row['ruby_method'], row['argument_index'], row['gem'], row['expression'], row['call_chain'])
            if key not in decision_cache:
                decision_cache[key] = sf.decide(row)
            decision, reason, receiver, gem, column = decision_cache[key]
            counts[decision] += 1
            reasons[(decision, reason)] += 1
            dw.writerow([number, decision, reason, receiver, gem])
            if decision == 'kept':
                auth[row['auth']] += 1
                writer.writerow(dict(row, receiver=receiver, resolved_gem=gem, receiver_resolution=reason,
                                     call_source_column=column, input_row=number))
            if counts['rows_in'] % 500000 == 0:
                print(f"{counts['rows_in']} rows filtered; {counts['kept']} kept", flush=True)
    summary = {'analysis_base_sha': BASE_SHA, 'branch': 'work',
               'gitlab_tree': str(SOURCE), 'gitlab_sha': subprocess.check_output(['git', '-C', str(SOURCE), 'rev-parse', 'HEAD'], text=True).strip(),
               'inputs': [{'path': str(p), 'repository_path': str(p.relative_to(REPO)), 'sha256': sha(p), 'repository_sha': BASE_SHA}
                          for p in [INPUT, CATALOG, OWNERSHIP]],
               'rows_in': counts['rows_in'], 'rows_kept': counts['kept'], 'dropped_for_receiver': counts['receiver'],
               'dropped_for_literal_argument': counts['argument'],
               'anonymous_kept': auth['unauthenticated'] + auth['conditional_anonymous'], 'unknown_kept': auth['unknown'],
               'kept_by_auth': dict(auth),
               'drop_and_keep_reasons': [{'decision': d, 'reason': r, 'rows': n} for (d, r), n in sorted(reasons.items())],
               'counting_rule': 'Receiver first; argument drops include every remaining non-identifier expression, literal, size expression, and empty argument.',
               'source_files_read': len(sf.syntax.files), 'entrypoints_rewalked': False, 'target_code_executed': False,
               'gem_or_c_sources_fetched': False}
    assert counts['rows_in'] == counts['kept'] + counts['receiver'] + counts['argument']
    summary['literal_argument_drops'] = reasons[('argument', 'literal_argument')]
    summary['empty_argument_drops'] = reasons[('argument', 'empty_or_splat_obscured_argument')]
    summary['other_non_identifier_argument_drops'] = counts['argument'] - summary['literal_argument_drops'] - summary['empty_argument_drops']
    with gzip.open(HERE / 'filtered_matches.csv.gz', 'rb') as f:
        (HERE / 'filtered_matches.csv').write_bytes(f.read())
    (HERE / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    (HERE / 'receiver_namespace_manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    with (HERE / 'source_files_read.jsonl').open('w') as f:
        for file, info in sorted(sf.syntax.files.items()):
            f.write(json.dumps({'file': file, 'sha256': info['sha256']}) + '\n')
    print(json.dumps({k: summary[k] for k in ['rows_in', 'rows_kept', 'dropped_for_receiver', 'dropped_for_literal_argument',
                                            'anonymous_kept', 'unknown_kept']}), flush=True)


if __name__ == '__main__':
    main()

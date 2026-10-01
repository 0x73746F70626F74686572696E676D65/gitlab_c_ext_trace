#!/usr/bin/env python3
"""Read Ruby syntax only; never import, evaluate, or boot the target repository."""
import argparse
import collections
import csv
import gzip
import hashlib
import json
import re
import subprocess
from pathlib import Path

from tree_sitter import Language, Parser
import tree_sitter_ruby

MAX_DEPTH = 4
DYNAMIC = {'send', 'public_send', '__send__', 'method_missing'}
CONST = re.compile(r'^(?:::)?[A-Z]\w*(?:::[A-Z]\w*)*$')


def text(n):
    return n.text.decode('utf-8', 'replace') if n else ''


def field(n, k):
    return n.child_by_field_name(k) if n else None


def descendants(n, prune=()):
    if n is None:
        return
    yield n
    for c in n.named_children:
        if c.type not in prune:
            yield from descendants(c, prune)


def arguments(n):
    a = field(n, 'arguments')
    return a.named_children if a else []


def literal(n):
    if not n:
        return None
    if n.type in ('simple_symbol', 'hash_key_symbol', 'bare_symbol'):
        return text(n).lstrip(':')
    if n.type == 'string' and not any(c.type == 'interpolation' for c in descendants(n)):
        return ''.join(text(c) for c in n.named_children if c.type == 'string_content')
    return None


def underscore(s):
    s = re.sub(r'([A-Z]+)([A-Z][a-z])', r'\1_\2', s)
    s = re.sub(r'([a-z\d])([A-Z])', r'\1_\2', s)
    return s.replace('::', '/').lower()


def digest(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


class Walker:
    def __init__(self, source):
        self.source = source.resolve()
        self.parser = Parser(Language(tree_sitter_ruby.language()))
        self.files = {}
        self.methods = collections.defaultdict(list)
        self.owners = collections.defaultdict(list)
        self.lookups = {}
        self.call_cache = {}
        self.target_cache = {}
        self.paths = {}
        # Directory names only; no global Ruby definition or API-name search.
        self.bases = ['lib', 'app/graphql', 'app/channels']
        self.bases += [str(p.relative_to(self.source)) for p in sorted((self.source / 'app').iterdir())
                       if p.is_dir() and p.name not in {'assets', 'views', 'javascript', 'frontend_islands'}]
        self.bases += ['app/models/concerns', 'app/controllers/concerns', 'app/helpers', 'lib/api']

    def load(self, path):
        if path in self.files:
            return self.files[path]
        p = self.source / path
        if p.suffix != '.rb' or not p.is_file() or not p.resolve().is_relative_to(self.source):
            return None
        data = p.read_bytes()
        tree = self.parser.parse(data)
        info = {'path': path, 'tree': tree, 'data': data, 'definitions': [], 'declarations': [],
                'sha256': hashlib.sha256(data).hexdigest(), 'parse_error': tree.root_node.has_error}
        self.files[path] = info

        def index(node, owner='', singleton=False):
            if node.type in ('class', 'module'):
                name = text(field(node, 'name'))
                current = name.lstrip(':') if '::' in name or not owner else owner + '::' + name
                parent = field(node, 'superclass')
                parent_name = text(parent).removeprefix('<').strip()
                fact = {'owner': current, 'file': path, 'parent': parent_name, 'mixins': []}
                self.owners[current].append(fact)
                for c in (field(node, 'body').named_children if field(node, 'body') else []):
                    if c.type == 'call' and text(field(c, 'method')) in {'include', 'prepend', 'extend'}:
                        fact['mixins'].extend((text(a), text(field(c, 'method'))) for a in arguments(c)
                                             if CONST.fullmatch(text(a)))
                    index(c, current)
                return
            if node.type == 'singleton_class':
                for c in (field(node, 'body').named_children if field(node, 'body') else []):
                    index(c, owner, True)
                return
            if node.type in ('method', 'singleton_method'):
                name = text(field(node, 'name'))
                unit = {'owner': owner, 'name': name, 'singleton': singleton or node.type == 'singleton_method',
                        'file': path, 'node': node, 'body': field(node, 'body'), 'line': node.start_point.row + 1}
                info['definitions'].append(unit)
                self.methods[(owner, name, unit['singleton'])].append(unit)
                return
            if node.type == 'call':
                info['declarations'].append((node, owner))
            for c in node.named_children:
                index(c, owner, singleton)

        index(tree.root_node)
        return info

    def owner_paths(self, owner, edition):
        key = (owner, edition)
        if key in self.paths:
            return self.paths[key]
        rel = underscore(owner.lstrip(':')) + '.rb'
        candidates = []
        prefixes = ['', 'ee/'] if edition != 'ce' else ['']
        for prefix in prefixes:
            for base in self.bases:
                p = prefix + base + '/' + rel
                if (self.source / p).is_file():
                    candidates.append(p)
        # Conventional mappings only; no recursive filename or content search.
        candidates = list(dict.fromkeys(candidates))
        self.paths[key] = candidates
        return candidates

    def qualify(self, name, context, edition):
        if not CONST.fullmatch(name):
            return None
        bare = name.lstrip(':')
        if name.startswith('::'):
            names = [bare]
        else:
            namespaces = context.split('::')[:-1]
            names = ['::'.join(namespaces[:i] + [bare]) for i in range(len(namespaces), -1, -1)]
        for candidate in names:
            paths = self.owner_paths(candidate, edition)
            for p in paths:
                self.load(p)
            if candidate in self.owners:
                return candidate
        return None

    def lookup(self, owner, name, singleton, edition, seen=()):
        key = (owner, name, singleton, edition)
        if not seen and key in self.lookups:
            return self.lookups[key]
        result = self._lookup(owner, name, singleton, edition, seen)
        if not seen:
            self.lookups[key] = result
        return result

    def _lookup(self, owner, name, singleton, edition, seen):
        if owner in seen:
            return None
        for p in self.owner_paths(owner, edition):
            self.load(p)
        units = self.methods.get((owner, name, singleton), [])
        # Reopened/overridden competing definitions remain unresolved.
        if len(units) == 1:
            return units[0]
        if len(units) > 1:
            return None
        facts = self.owners.get(owner, [])
        results = []
        for fact in facts:
            for mixin, kind in fact['mixins']:
                if (singleton and kind != 'extend') or (not singleton and kind == 'extend'):
                    continue
                target = self.qualify(mixin, owner, edition)
                if target:
                    result = self.lookup(target, name, False, edition, seen + (owner,))
                    if result:
                        results.append(result)
            target = self.qualify(fact['parent'], owner, edition)
            if target:
                result = self.lookup(target, name, singleton, edition, seen + (owner,))
                if result:
                    results.append(result)
        unique = {(u['file'], u['line']): u for u in results}
        return next(iter(unique.values())) if len(unique) == 1 else None

    def root(self, ep):
        registration = ep.get('registration', {})
        info = self.load(registration.get('file', ''))
        edition = ep['edition']
        kind = ep['type']
        if kind == 'rails_action':
            hits = []
            for loc in ep.get('action_sources', []):
                source = self.load(loc['file'])
                if source:
                    hits.extend(u for u in source['definitions'] if u['owner'] == loc['owner']
                                and u['name'] == ep['action'] and not u['singleton'])
            hits = list({(u['file'], u['line']): u for u in hits}.values())
            if len(hits) == 1:
                return hits[0], 'recorded_action_source'
            result = self.lookup(ep.get('controller', ''), ep.get('action', ''), False, edition)
            return result, 'controller_action_not_resolved' if not result else 'controller_action_convention'
        if kind.startswith('graphql'):
            g = ep['graphql']
            owner = g['resolver_class']
            # GraphQL's explicit resolver binding selects resolve; ordinary field
            # bindings use their recorded Ruby method. No model/generated fallback.
            name = 'resolve' if g.get('resolver_expression') else g.get('resolver_method', '')
            result = self.lookup(owner, name, False, edition)
            return result, 'graphql_method_not_resolved' if not result else 'recorded_graphql_binding'
        if kind == 'grape_endpoint' and info:
            candidates = []
            verbs = {s.lower() for s in ep.get('http_methods', [])}
            for n, owner in info['declarations']:
                name = text(field(n, 'method'))
                block = field(n, 'block')
                if block and (name in verbs or name == 'route' and 'any' in verbs):
                    candidates.append((n, owner))
            # Inventory lines are from a different revision: accept an exact
            # line anchor only when the endpoint's verb still agrees.
            def compatible(n):
                routes = [literal(a) for a in arguments(n) if literal(a) is not None]
                if text(field(n, 'method')) == 'route':
                    routes = routes[1:]
                path = ep.get('path') or ''
                return any(not r.strip('/') or path.rstrip('/').endswith('/' + r.strip('/')) for r in routes)
            exact = [(n, o) for n, o in candidates if n.start_point.row + 1 == registration.get('line') and compatible(n)]
            if len(exact) != 1:
                return None, 'grape_registration_revision_drift'
            n, owner = exact[0]
            return {'owner': owner, 'name': '<endpoint>', 'singleton': False, 'file': info['path'],
                    'line': n.start_point.row + 1, 'node': n, 'body': field(field(n, 'block'), 'body')}, 'grape_line_and_verb'
        if kind == 'middleware_endpoint':
            return self.lookup(ep['class'], 'call', False, edition), 'middleware_call_binding'
        if kind == 'health_listener_endpoint' and info:
            hits = [u for u in info['definitions'] if u['name'] == 'call']
            return (hits[0] if len(hits) == 1 else None), 'health_listener_call_binding'
        return None, 'registration_has_no_ordinary_ruby_handler_binding'

    def calls(self, unit):
        key = (unit['file'], unit['line'])
        if key in self.call_cache:
            return self.call_cache[key]
        result = []
        locals_ = set()
        for n in descendants(field(unit['node'], 'parameters')):
            if n.type == 'identifier':
                locals_.add(text(n))
        for n in descendants(unit['body'], ('method', 'singleton_method', 'class', 'module', 'lambda')):
            if n.type in {'assignment', 'operator_assignment'}:
                left = field(n, 'left')
                if left and left.type == 'identifier':
                    locals_.add(text(left))
            if n.type in {'block_parameters', 'rescue_variable'}:
                locals_.update(text(c) for c in descendants(n) if c.type == 'identifier')
        def visit(n):
            if n is None or n.type in {'method', 'singleton_method', 'class', 'module', 'lambda'}:
                return
            if n.type == 'call':
                name = text(field(n, 'method'))
                args = list(arguments(n))
                result.append((n, name, field(n, 'receiver'), args))
                if name in DYNAMIC or '#{' in name:
                    return
            elif n.type == 'super':
                if not n.parent or field(n.parent, 'method') != n:
                    result.append((n, 'super', None, []))
            elif n.type == 'identifier' and text(n) not in locals_:
                parent = n.parent
                if not (parent and (field(parent, 'method') == n or field(parent, 'name') == n
                                   or parent.type in {'method_parameters', 'block_parameters', 'keyword_parameter'})):
                    result.append((n, text(n), None, []))
            elif n.type == 'binary':
                result.append((n, text(field(n, 'operator')), field(n, 'left'), [field(n, 'right')]))
            elif n.type == 'element_reference':
                # Assignment is []= rather than a separate [] invocation.
                assignment = n.parent if n.parent and n.parent.type == 'assignment' and field(n.parent, 'left') == n else None
                args = [c for c in n.named_children if c != field(n, 'object')]
                if assignment:
                    result.append((n, '[]=', field(n, 'object'), args + [field(assignment, 'right')]))
                else:
                    result.append((n, '[]', field(n, 'object'), args))
            elif n.type == 'assignment' and field(n, 'left') and field(n, 'left').type == 'call':
                left = field(n, 'left')
                result.append((n, text(field(left, 'method')) + '=', field(left, 'receiver'), [field(n, 'right')]))
                visit(field(left, 'receiver'))
                visit(field(n, 'right'))
                return
            for c in n.named_children:
                visit(c)
        visit(unit['body'])
        self.call_cache[key] = result
        return result

    def target(self, unit, node, name, receiver, edition):
        key = (unit['file'], unit['line'], node.start_byte, name, edition)
        if key not in self.target_cache:
            self.target_cache[key] = self._target(unit, node, name, receiver, edition)
        return self.target_cache[key]

    def _target(self, unit, node, name, receiver, edition):
        if name == 'super':
            parents = {self.qualify(f['parent'], unit['owner'], edition)
                       for f in self.owners.get(unit['owner'], []) if f['parent']}
            parents.discard(None)
            if len(parents) == 1:
                return self.lookup(next(iter(parents)), unit['name'], unit['singleton'], edition)
            return None
        if receiver is None or text(receiver) == 'self':
            return self.lookup(unit['owner'], name, unit['singleton'], edition)
        if CONST.fullmatch(text(receiver)):
            owner = self.qualify(text(receiver), unit['owner'], edition)
            if owner:
                return self.lookup(owner, 'initialize' if name == 'new' else name,
                                   name != 'new', edition)
        if receiver.type == 'call' and text(field(receiver, 'method')) == 'new':
            owner = self.qualify(text(field(receiver, 'receiver')), unit['owner'], edition)
            if owner:
                return self.lookup(owner, name, False, edition)
        if receiver.type == 'identifier':
            bindings = [n for n in descendants(unit['body'], ('method', 'singleton_method', 'class', 'module', 'lambda'))
                        if n.type == 'assignment' and text(field(n, 'left')) == text(receiver)]
            if len(bindings) == 1 and bindings[0].start_byte < node.start_byte:
                value = field(bindings[0], 'right')
                if value and value.type == 'call' and text(field(value, 'method')) == 'new':
                    owner = self.qualify(text(field(value, 'receiver')), unit['owner'], edition)
                    if owner:
                        return self.lookup(owner, name, False, edition)
        return None


def expression_kind(n):
    if n is None:
        return 'not_visible'
    if n.type in {'identifier', 'instance_variable', 'class_variable', 'global_variable', 'constant', 'scope_resolution', 'self'}:
        return 'identifier'
    if n.type == 'unary' and text(n).startswith(('-', '+')) and len(n.named_children) == 1:
        return 'literal' if n.named_children[0].type in {'integer', 'float'} else 'expression'
    if n.type in {'array', 'hash'}:
        values = [c for c in n.named_children if c.type != 'comment']
        if n.type == 'hash':
            values = [v for c in values for v in c.named_children]
        return 'literal' if all(expression_kind(c) == 'literal' or c.type == 'hash_key_symbol' for c in values) else 'expression'
    if n.type in {'integer', 'float', 'true', 'false', 'nil', 'simple_symbol', 'bare_symbol', 'string', 'regex'}:
        return 'expression' if any(c.type == 'interpolation' for c in descendants(n)) else 'literal'
    return 'expression'


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--source', type=Path, default=Path('/workspace/gitlab'))
    ap.add_argument('--output', type=Path, default=Path(__file__).resolve().parent)
    cfg = ap.parse_args()
    repo = Path(__file__).resolve().parent.parent
    entries_path = repo / 'unauthenticated_entrypoints/entrypoints.json'
    table_path = repo / 'static-catalog/entry-argument-sites.csv'
    entries = json.loads(entries_path.read_text())['entrypoints']
    with table_path.open(newline='') as f:
        catalog = list(csv.DictReader(f))
    by_name = collections.defaultdict(list)
    for i, row in enumerate(catalog, 2):
        by_name[row['ruby_method_name']].append((i, row))
    w = Walker(cfg.source)
    cfg.output.mkdir(exist_ok=True)
    columns = ['entrypoint', 'auth', 'file', 'line', 'call_chain_depth', 'gem', 'ruby_method',
               'argument_index', 'slot', 'expression', 'expression_kind', 'edition', 'entrypoint_type',
               'entrypoint_path', 'anonymous_access', 'argument_table_line', 'call_chain']
    matches = 0
    matched_names = set()
    matched_catalog = set()
    matched_eps = set()
    match_auth = collections.Counter()
    ep_auth = collections.Counter(e['auth']['classification'] for e in entries)
    stops = collections.Counter()
    root_reasons = collections.Counter()
    roots = 0
    cache = {}
    with gzip.open(cfg.output / 'matches.csv.gz', 'wt', newline='') as mf, \
         gzip.open(cfg.output / 'unresolved_stops.jsonl.gz', 'wt') as sf, \
         gzip.open(cfg.output / 'entrypoints_walked.jsonl.gz', 'wt') as ef:
        writer = csv.DictWriter(mf, fieldnames=columns)
        writer.writeheader()
        for count, ep in enumerate(entries, 1):
            root, reason = w.root(ep)
            root_reasons[reason] += 1
            if not root:
                ef.write(json.dumps({'entrypoint': ep['id'], 'auth': ep['auth']['classification'],
                                     'status': 'unresolved_root', 'reason': reason,
                                     'registration': ep.get('registration')}) + '\n')
                continue
            roots += 1
            root_key = (root['file'], root['line'], ep['edition'])
            if root_key not in cache:
                queue = collections.deque([(root, 0, [])])
                seen = set()
                found = []
                unresolved = []
                while queue:
                    unit, depth, chain = queue.popleft()
                    identity = (unit['file'], unit['line'])
                    if identity in seen:
                        continue
                    seen.add(identity)
                    hop = {'file': unit['file'], 'line': unit['line'], 'method': unit['owner'] + '#' + unit['name']}
                    chain = chain + [hop]
                    if unit['node'].has_error:
                        unresolved.append({'reason': 'parser_error', 'file': unit['file'], 'line': unit['line'],
                                           'depth': depth, 'call_chain': chain})
                        continue
                    for node, name, recv, argv in w.calls(unit):
                        loc = {'file': unit['file'], 'line': node.start_point.row + 1, 'depth': depth,
                               'ruby_method': name, 'call_chain': chain}
                        if name in by_name:
                            for table_line, row in by_name[name]:
                                idx = int(row['argument_index'])
                                # Splats prevent positional visibility at/after the splat.
                                visible = 0 <= idx < len(argv) and not any(a.type in {'splat_argument', 'hash_splat_argument'}
                                                                         for a in argv[:idx + 1] if a)
                                arg = argv[idx] if visible else None
                                found.append(dict(loc, gem=row['gem'], argument_index=row['argument_index'], slot=row['slot'],
                                                  expression=text(arg), expression_kind=expression_kind(arg),
                                                  argument_table_line=table_line))
                        if name in DYNAMIC or '#{' in name:
                            unresolved.append(dict(loc, reason='dynamic_dispatch'))
                            continue
                        target = w.target(unit, node, name, recv, ep['edition'])
                        if target:
                            if depth < MAX_DEPTH:
                                queue.append((target, depth + 1, chain))
                            else:
                                unresolved.append(dict(loc, reason='depth_limit'))
                        elif name not in by_name:
                            unresolved.append(dict(loc, reason='ordinary_call_not_resolved'))
                cache[root_key] = (found, unresolved, len(seen))
            found, unresolved, visited = cache[root_key]
            for row in found:
                out = dict(row)
                out['call_chain_depth'] = out.pop('depth')
                out['ruby_method'] = out.pop('ruby_method')
                out.update(entrypoint=ep['id'], auth=ep['auth']['classification'], edition=ep['edition'],
                           entrypoint_type=ep['type'], entrypoint_path=ep.get('path'),
                           anonymous_access=ep['anonymous_access'])
                out['call_chain'] = json.dumps(out['call_chain'], separators=(',', ':'))
                writer.writerow(out)
                matches += 1
                match_auth[out['auth']] += 1
                matched_names.add(out['ruby_method'])
                matched_catalog.add(out['argument_table_line'])
                matched_eps.add(ep['id'])
            for stop in unresolved:
                stops[stop['reason']] += 1
                sf.write(json.dumps(dict(stop, entrypoint=ep['id'])) + '\n')
            ef.write(json.dumps({'entrypoint': ep['id'], 'auth': ep['auth']['classification'], 'status': 'walked',
                                 'binding': reason, 'root_file': root['file'], 'root_line': root['line'],
                                 'methods_walked': visited, 'matches': len(found), 'unresolved_stops': len(unresolved)}) + '\n')
            if count % 5000 == 0:
                print(f'{count}/{len(entries)} entries; {matches} rows; {len(w.files)} source files', flush=True)
    with (cfg.output / 'methods_with_no_match.csv').open('w', newline='') as f:
        cw = csv.writer(f, lineterminator='\n')
        cw.writerow(['gem', 'ruby_method', 'argument_index', 'slot', 'argument_table_line'])
        for line, row in enumerate(catalog, 2):
            if line not in matched_catalog:
                cw.writerow([row['gem'], row['ruby_method_name'], row['argument_index'], row['slot'], line])
    with (cfg.output / 'files_read.jsonl').open('w') as f:
        for p, info in sorted(w.files.items()):
            f.write(json.dumps({'file': p, 'sha256': info['sha256'], 'parse_error': info['parse_error']}) + '\n')
    git = lambda root, *args: subprocess.check_output(['git', '-C', str(root), *args], text=True).strip()
    summary = {'analysis_start_sha': '7675bfa2b401cf5097546452d50f2d38a87fbde5',
               'analysis_input_sha': git(repo, 'rev-parse', 'HEAD'),
               'gitlab_sha': git(cfg.source, 'rev-parse', 'HEAD'),
               'gitlab_default_branch': 'master', 'gitlab_shallow': git(cfg.source, 'rev-parse', '--is-shallow-repository'),
               'entrypoint_inventory': str(entries_path.relative_to(repo)), 'entrypoint_inventory_sha256': digest(entries_path),
               'call_argument_table': str(table_path.relative_to(repo)), 'call_argument_table_sha256': digest(table_path),
               'inventory_gitlab_shas': sorted({e['gitlab_commit_sha'] for e in entries}),
               'depth_limit': MAX_DEPTH, 'entrypoints_considered': len(entries), 'entrypoints_walked': roots,
               'unresolved_entrypoint_roots': len(entries) - roots, 'entrypoints_with_matches': len(matched_eps),
               'matches': matches, 'anonymous_matches': match_auth['unauthenticated'] + match_auth['conditional_anonymous'],
               'unknown_matches': match_auth['unknown'], 'matches_by_auth': dict(match_auth),
               'entrypoints_by_auth': dict(ep_auth), 'catalog_rows': len(catalog), 'catalog_method_names': len(by_name),
               'matched_method_names': len(matched_names), 'methods_with_no_match': sorted(set(by_name) - matched_names),
               'catalog_rows_with_no_match': len(catalog) - len(matched_catalog),
               'unresolved_stops': dict(stops), 'unresolved_stops_total': sum(stops.values()),
               'root_binding_counts': dict(root_reasons), 'source_files_read': len(w.files),
               'target_code_executed': False, 'gem_or_c_sources_fetched': False}
    (cfg.output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps({k: summary[k] for k in ['entrypoints_walked', 'matches', 'anonymous_matches', 'unknown_matches',
                                            'unresolved_entrypoint_roots', 'unresolved_stops']}), flush=True)


if __name__ == '__main__':
    main()

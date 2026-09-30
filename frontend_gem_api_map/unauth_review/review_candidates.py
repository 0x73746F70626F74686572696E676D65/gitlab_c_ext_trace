#!/usr/bin/env python3
"""Source-ownership review overlay for the original 191 anonymous candidates."""
import argparse
import collections
import csv
import functools
import gzip
import hashlib
import json
import pickle
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from map_frontend import (Mapper, AUTH_REQUIRED, AUTH_OPTIONAL, CONSTANT, DYNAMIC, FILTERS,
                          args, block_body, conditional, fld, literal, location, method_name,
                          options, positional, symbols, txt, walk)

DEPTH = 5
BODY_CAP = 256
AUTH_DEPTH = 4
RETURN_DEPTH = 2
CALL_CANDIDATE_CAP = 8
CORE = {'String', 'Array', 'Hash', 'Integer', 'Float', 'Symbol', 'Regexp', 'NilClass', 'TrueClass', 'FalseClass'}
GUEST_SAFE_CALLBACKS = {
    ('ApplicationController', 'ldap_security_check'): 'LDAP check is nested under current_user && current_user.requires_ldap_check?',
    ('Gitlab::GonHelper', 'add_gon_variables'): 'sets front-end configuration; token-prefix values do not require a login',
    ('Impersonation', 'check_impersonation_availability'): 'returns unless a session is already impersonating a user',
}


def jsonl(path):
    with (gzip.open(path, 'rt') if path.suffix == '.gz' else open(path)) as f:
        return [json.loads(line) for line in f]


def write_jsonl(path, rows):
    opener = gzip.open if path.suffix == '.gz' else open
    with opener(path, 'wt') as out:
        for row in rows:
            out.write(json.dumps(row, sort_keys=True, separators=(',', ':')) + '\n')


class Review:
    def __init__(self, source, inventory, baseline, output, cache=None):
        self.source, self.inventory, self.baseline, self.output = source, inventory, baseline, output
        self.m = Mapper(source, inventory, output)
        state_keys = ['classes', 'units', 'method_index', 'aliases', 'files', 'global_helpers']
        if cache and cache.exists():
            state = pickle.loads(cache.read_bytes())
            if state['sha'] != self.m.sha or state['inventory_sha256'] != hashlib.sha256(inventory.read_bytes()).hexdigest():
                raise ValueError('stale source cache')
            for k in state_keys:
                setattr(self.m, k, state[k])
        else:
            self.m.parse()
            if cache:
                state = {k: dict(getattr(self.m, k)) if k in {'classes', 'method_index'} else getattr(self.m, k) for k in state_keys}
                state['sha'] = self.m.sha
                state['inventory_sha256'] = hashlib.sha256(inventory.read_bytes()).hexdigest()
                cache.write_bytes(pickle.dumps(state, protocol=5))
        self.m.lookup = functools.lru_cache(maxsize=None)(self.m.lookup)
        self.m.resolve_constant = functools.lru_cache(maxsize=None)(self.m.resolve_constant)
        self.entries = [e for e in jsonl(baseline / 'entrypoints.jsonl.gz')
                        if e['auth']['classification'] == 'unauthenticated' and e['matches']]
        assert len(self.entries) == 191
        self.api = {a['id']: a for a in self.m.apis}
        self.tree_cache = {}
        self.enriched, self.return_cache, self.callback_cache = {}, {}, {}
        self.gaps, self.touched = [], set()

    def tree(self, file):
        self.touched.add(file)
        if file not in self.tree_cache:
            self.tree_cache[file] = self.m.parser.parse((self.source / file).read_bytes()).root_node
        return self.tree_cache[file]

    def unit_node(self, uid):
        file, line, column, _name = uid.rsplit(':', 3)
        for n in walk(self.tree(file)):
            if n.start_point.row + 1 == int(line) and n.start_point.column + 1 == int(column):
                if n.type in {'method', 'singleton_method', 'call'}:
                    return n
        return None

    def type_value(self, typ, kind='instance', evidence=None):
        return {'type': typ, 'kind': kind, 'evidence': evidence or []}

    def infer(self, node, env, unit, budget=RETURN_DEPTH):
        if node is None:
            return None
        s, kind = txt(node), node.type
        if s in env:
            return env[s]
        if kind in {'string', 'heredoc_body', 'string_concatenation'}:
            return self.type_value('String', evidence=[location(unit['file'], node) | {'basis': 'literal string'}])
        if kind in {'simple_symbol', 'bare_symbol'}:
            return self.type_value('Symbol')
        if kind in {'array', 'string_array', 'symbol_array'}:
            return self.type_value('Array')
        if kind == 'hash':
            return self.type_value('Hash')
        if kind in {'integer', 'float', 'regex', 'nil', 'true', 'false'}:
            return self.type_value({'integer': 'Integer', 'float': 'Float', 'regex': 'Regexp',
                                    'nil': 'NilClass', 'true': 'TrueClass', 'false': 'FalseClass'}[kind])
        if CONSTANT.fullmatch(s):
            cls = self.m.expand_alias(s.lstrip(':'), unit['owner'])
            return self.type_value(self.m.resolve_constant(cls, unit['owner']), 'singleton',
                                   [location(unit['file'], node) | {'basis': 'literal constant/alias'}])
        if kind in {'assignment', 'operator_assignment'}:
            return self.infer(fld(node, 'right'), env, unit, budget)
        if kind == 'parenthesized_statements' and node.named_children:
            return self.infer(node.named_children[-1], env, unit, budget)
        if kind in {'return', 'then', 'else', 'body_statement', 'block_body'} and node.named_children:
            last = node.named_children[-1]
            if kind == 'return' and last.type == 'argument_list' and last.named_children:
                last = last.named_children[0]
            return self.infer(last, env, unit, budget)
        if kind == 'identifier':
            if s in {'params', 'request', 'response', 'flash', 'headers'} and s not in env:
                typ = {'params': 'ActionController::Parameters', 'request': 'ActionDispatch::Request',
                       'response': 'ActionDispatch::Response', 'flash': 'ActionDispatch::Flash::FlashHash',
                       'headers': 'ActionDispatch::Response::Header'}[s]
                return self.type_value(typ, evidence=[{'basis': 'Rails controller convention', 'name': s}])
            if budget:
                hits = self.m.lookup(unit['owner'], s, unit['kind'])
                if len(hits) == 1:
                    return self.return_type(hits[0], budget - 1)
            return None
        if kind == 'call':
            name = method_name(node)
            rec = fld(node, 'receiver')
            value = self.infer(rec, env, unit, budget) if rec else None
            typ = value['type'] if value else None
            if name == 'new' and value and value['kind'] == 'singleton':
                return self.type_value(typ, evidence=value['evidence'] + [location(unit['file'], node) | {'basis': 'literal constructor'}])
            if name in {'to_s', 'to_str'}:
                return self.type_value('String', evidence=[location(unit['file'], node) | {'basis': 'Ruby string-conversion convention'}])
            if name in {'to_h', 'to_hash'}:
                return self.type_value('Hash', evidence=[location(unit['file'], node) | {'basis': 'Ruby hash-conversion convention'}])
            if name in {'to_a', 'to_ary', 'split'}:
                return self.type_value('Array')
            if name in {'to_i', 'length', 'size', 'bytesize'}:
                return self.type_value('Integer')
            if typ == 'ActionController::Parameters' and name in {'require', 'permit', 'permit!', 'slice', 'except', 'merge'}:
                return value
            if typ in CORE and name in {'dup', 'clone', 'freeze', 'itself', 'tap'}:
                return value
            if typ == 'Hash' and name in {'merge', 'merge!', 'except', 'slice', 'compact', 'transform_keys', 'transform_values'}:
                return value
            if typ == 'Array' and name in {'map', 'select', 'reject', 'compact', 'flatten', 'uniq', 'sort'}:
                return value
            if typ == 'String' and name in {'encode', 'downcase', 'upcase', 'chomp', 'strip', 'sub', 'gsub', 'html_safe', 'delete', 'delete_prefix', 'delete_suffix'}:
                return value
            if name in {'url', 'fullpath', 'path', 'host', 'remote_ip', 'ip'} and typ == 'ActionDispatch::Request':
                return self.type_value('String')
            if budget:
                hits = self.targets(unit, name, txt(rec), value)
                if len(hits) == 1:
                    return self.return_type(hits[0], budget - 1)
        return None

    def return_type(self, uid, budget):
        key = uid, budget
        if key in self.return_cache:
            return self.return_cache[key]
        self.return_cache[key] = None
        u, node = self.m.units[uid], self.unit_node(uid)
        body = fld(node, 'body') if node and node.type in {'method', 'singleton_method'} else block_body(node)
        if body is None:
            return None
        env = {}
        for n in walk(body, ('method', 'singleton_method', 'class', 'module')):
            if n.type == 'assignment':
                env[txt(fld(n, 'left'))] = self.infer(fld(n, 'right'), env, u, budget)
        # Do not infer a return type when explicit early returns introduce alternatives.
        if any(n.type == 'return' for n in walk(body)):
            return None
        value = self.infer(body, env, u, budget)
        if value:
            value = value | {'evidence': value['evidence'] + [location(u['file'], node) | {'basis': 'simple Ruby method return'}]}
        self.return_cache[key] = value
        return value

    def targets(self, unit, name, receiver, value):
        if name in DYNAMIC:
            return []
        if receiver in {'', 'self'}:
            return self.m.lookup(unit['owner'], name, unit['kind'])
        if value:
            return self.m.lookup(value['type'], name, value['kind'])
        return []

    def enriched_unit(self, uid):
        if uid in self.enriched:
            return self.enriched[uid]
        u, node = self.m.units[uid], self.unit_node(uid)
        if node is None:
            result = {'calls': [], 'gaps': [{'kind': 'missing_AST_body', 'unit_id': uid}]}
            self.enriched[uid] = result
            return result
        body = fld(node, 'body') if node.type in {'method', 'singleton_method'} else block_body(node)
        calls, gaps, env = [], [], {}
        params = fld(node, 'parameters')
        if params:
            for p in walk(params):
                if p.type == 'identifier':
                    env[txt(p)] = None
                if p.type in {'optional_parameter', 'keyword_parameter'}:
                    name, value = fld(p, 'name'), fld(p, 'value')
                    if name and value:
                        # Defaults do not establish the type of a caller-supplied argument.
                        env[txt(name)] = None
        for n in walk(body, ('method', 'singleton_method', 'class', 'module')):
            if n.type in {'assignment', 'operator_assignment'}:
                name = txt(fld(n, 'left'))
                value = self.infer(fld(n, 'right'), env, u)
                # Assignments inside branches do not fix the type after a merge.
                env[name] = None if conditional(n, body) else value
            elif n.type == 'call':
                name, rec = method_name(n), fld(n, 'receiver')
                value = self.infer(rec, env, u)
                call = {**location(u['file'], n), 'method': name, 'receiver': txt(rec),
                        'type': value, 'unit_id': uid, 'conditional': conditional(n, body),
                        'expression': txt(n).split('\n')[0][:300]}
                if fld(n, 'method'):
                    call['line'] = fld(n, 'method').start_point.row + 1
                call['targets'] = self.targets(u, name, txt(rec), value)
                if name in DYNAMIC:
                    gaps.append({'kind': 'dynamic_dispatch', **{k: call[k] for k in ('file', 'line', 'method', 'expression')}})
                elif rec is not None and not value:
                    gaps.append({'kind': 'unknown_receiver', **{k: call[k] for k in ('file', 'line', 'method', 'receiver')}})
                if len(call['targets']) > CALL_CANDIDATE_CAP:
                    gaps.append({'kind': 'helper_candidate_cap', 'file': u['file'], 'line': call['line'],
                                 'candidates': call['targets'], 'cap': CALL_CANDIDATE_CAP})
                    call['targets'] = []
                calls.append(call)
            elif n.type == 'identifier':
                name = txt(n)
                if name in env:
                    continue
                p = n.parent
                if p and p.type in {'call', 'assignment', 'operator_assignment', 'method_parameters',
                                   'optional_parameter', 'keyword_parameter', 'pair', 'block_parameters',
                                   'element_reference', 'scope_resolution'}:
                    if not (p.type == 'call' and fld(p, 'receiver') == n):
                        continue
                hits = self.targets(u, name, '', None)
                if hits or p.type != 'call':
                    calls.append({**location(u['file'], n), 'method': name, 'receiver': '', 'type': None,
                                  'unit_id': uid, 'conditional': conditional(n, body), 'expression': name,
                                  'targets': hits, 'bare_identifier': True})
            elif n.type == 'super':
                gaps.append({'kind': 'super_dispatch', **location(u['file'], n), 'unit_id': uid})
        result = {'calls': calls, 'gaps': gaps}
        self.enriched[uid] = result
        return result

    def verdict(self, call, ids=None):
        candidates = [self.api[i] for i in ids] if ids is not None else self.m.api_by_name.get(call['method'], [])
        value = call.get('type')
        typ, kind = (value['type'], value['kind']) if value else (None, None)
        if call['method'] == 'new' and typ and kind == 'singleton' and ids is None:
            candidates = list(candidates) + [a for a in self.m.api_by_name.get('initialize', [])
                                             if a['namespace'] == typ and 'instance' in a['kinds']]
        if not candidates:
            return None
        supported, rejected, unresolved = [], [], []
        for api in candidates:
            ns = api['namespace']
            if call['method'] in DYNAMIC:
                unresolved.append(api['id'])
            elif call.get('targets'):
                # A located GitLab Ruby definition excludes same-spelling gem ownership at this call.
                rejected.append(api['id'])
            elif typ and ns == typ and (not api['kinds'] or kind in api['kinds'] or
                    (call['method'] == 'new' and api['method'] == 'initialize' and 'instance' in api['kinds'])):
                supported.append(api['id'])
            elif typ == 'CGI' and ns == 'CGI::EscapeExt':
                supported.append(api['id'])
            elif ns is None:
                unresolved.append(api['id'])
            elif typ:
                unresolved.append(api['id']) if typ.split('::')[0] == ns.split('::')[0] and typ not in CORE else rejected.append(api['id'])
            elif call['receiver'] in {'', 'self'} and call['method'] == 'render':
                rejected.append(api['id'])
            else:
                unresolved.append(api['id'])
        status = 'supported' if supported else 'unresolved' if unresolved else 'rejected'
        evidence = list(value['evidence']) if value else []
        for uid in call.get('targets', []):
            evidence.append({k: self.m.units[uid][k] for k in ('file', 'line', 'end_line', 'owner', 'name')})
        if supported:
            reason = 'receiver/type or explicit CGI public alias matches listed API'
        elif unresolved:
            reason = 'receiver, native API owner, or same-gem public alias not resolved'
        else:
            reason = 'located GitLab Ruby method or inferred receiver differs from listed API owners'
        return {**{k: call.get(k) for k in ('file', 'line', 'method', 'receiver', 'expression', 'unit_id')},
                'status': status, 'supported_api_ids': supported, 'rejected_api_ids': rejected,
                'unresolved_api_ids': unresolved, 'receiver_inference': value, 'evidence': evidence, 'reason': reason}

    def trace(self, roots, max_depth=DEPTH, context_owner=None):
        queue = collections.deque((uid, 0, []) for uid in roots)
        visited, sites, gaps = set(), [], []
        while queue:
            uid, depth, path = queue.popleft()
            if uid in visited:
                continue
            if len(visited) >= BODY_CAP:
                gaps.append({'kind': 'body_cap', 'cap': BODY_CAP, 'remaining': len(queue) + 1})
                break
            visited.add(uid)
            u = self.m.units[uid]
            facts = self.enriched_unit(uid)
            gaps.extend(g | {'unit_id': uid, 'hop_depth': depth} for g in facts['gaps'])
            for c in facts['calls']:
                if context_owner and u['kind'] == 'instance' and u['owner'] in self.m.ancestry(context_owner) and c['receiver'] in {'', 'self'}:
                    c = c | {'targets': self.m.lookup(context_owner, c['method'])}
                verdict = self.verdict(c)
                if verdict:
                    sites.append(verdict | {'hop_depth': depth, 'helper_path': path})
                if depth >= max_depth:
                    for target in c['targets']:
                        if target not in visited:
                            gaps.append({'kind': 'helper_depth_cap', 'file': c['file'], 'line': c['line'],
                                         'target': target, 'cap': max_depth})
                else:
                    for target in c['targets']:
                        queue.append((target, depth + 1, path + [{'from': uid, 'target': target,
                                      'file': c['file'], 'line': c['line'], 'method': c['method']}]))
        return sites, gaps, visited

    def active_callbacks(self, owner, action):
        active, gaps = [], []
        for cls in reversed(self.m.ancestry(owner)):
            for file in set(self.m.classes.get(cls, {}).get('files', [])):
                root = self.tree(file)
                for n in walk(root):
                    if n.type != 'call' or method_name(n) not in FILTERS:
                        continue
                    p = n.parent
                    enclosing = None
                    while p:
                        if p.type in {'class', 'module'}:
                            enclosing = self.m.qualify(txt(fld(p, 'name')), '')
                            # Match source metadata by declaration location instead of re-deriving nested names.
                            break
                        p = p.parent
                    known = self.m.classes.get(cls, {}).get('macros', [])
                    if not any(m['file'] == file and m['line'] == n.start_point.row + 1 and m['name'] == method_name(n) for m in known):
                        continue
                    opts = options(n)
                    only, exc = symbols(opts.get('only')), symbols(opts.get('except'))
                    selector_unknown = ('only' in opts and opts['only'].type not in {'array', 'symbol_array', 'simple_symbol', 'string'}) or (
                        'except' in opts and opts['except'].type not in {'array', 'symbol_array', 'simple_symbol', 'string'})
                    if not selector_unknown and (('only' in opts and action not in only) or action in exc):
                        continue
                    names = [literal(a) for a in positional(n) if literal(a)]
                    body = block_body(n)
                    lambdas = [a for a in positional(n) if a.type == 'lambda']
                    conditional_macro = 'if' in opts or 'unless' in opts or conditional(n) or selector_unknown
                    if method_name(n).startswith('skip_'):
                        if conditional_macro:
                            gaps.append({'kind': 'conditional_callback_skip', **location(file, n), 'names': names})
                        else:
                            active = [c for c in active if c['callback_name'] not in names]
                        continue
                    for name in names:
                        targets = self.m.lookup(owner, name)
                        active.append({'callback_name': name, 'owner': cls, 'roots': targets,
                                       'conditional': conditional_macro, 'source': location(file, n),
                                       'expression': txt(n).split('\n')[0][:240]})
                    for inline in ([body] if body else []) + lambdas:
                        inline_body = fld(inline, 'body') if inline.type == 'lambda' else inline
                        if inline_body is not None and inline_body.type in {'block', 'do_block'}:
                            inline_body = fld(inline_body, 'body')
                        uid = self.m.unit(n, inline_body, file, cls, '@review_callback')
                        # Inline callback facts need their actual lambda AST, not the outer call's block.
                        u = self.m.units[uid]
                        extra = self.m.facts(inline_body, file, cls)
                        calls = []
                        for call in extra:
                            if call.get('bare_identifier'):
                                continue
                            value = self.type_value(call['receiver_type'], call['receiver_kind']) if call['receiver_type'] else None
                            calls.append({'file': file, 'line': call['line'], 'method': call['name'], 'receiver': call['receiver'],
                                'expression': call['expression'], 'unit_id': uid, 'conditional': call['conditional'], 'type': value,
                                'targets': self.targets(u, call['name'], call['receiver'], value)})
                        self.enriched[uid] = {'calls': calls, 'gaps': []}
                        active.append({'callback_name': '@inline', 'owner': cls, 'roots': [uid],
                                       'conditional': conditional_macro, 'source': location(file, n),
                                       'expression': txt(n).split('\n')[0][:240]})
                    if selector_unknown:
                        gaps.append({'kind': 'dynamic_callback_selector', **location(file, n), 'expression': txt(n).split('\n')[0][:240]})
        unique = {json.dumps(c, sort_keys=True): c for c in active}
        return list(unique.values()), gaps

    def auth_review(self, e, callbacks):
        evidence, gaps, blockers, mandatory = [], [], [], []
        sensitive = re.compile(r'authenticate|authoriz|permission|verification_user|certificate|token|sign_in|can\?|verify_workhorse')
        for cb in callbacks:
            if cb['callback_name'] in AUTH_REQUIRED and not cb['conditional']:
                mandatory.append(cb)
            if not cb['roots'] and sensitive.search(cb['callback_name']):
                blockers.append(cb)
                gaps.append({'kind': 'unresolved_auth_callback', **cb['source'], 'callback': cb['callback_name']})
                continue
            if len(cb['roots']) == 1:
                root_unit = self.m.units[cb['roots'][0]]
                benign = GUEST_SAFE_CALLBACKS.get((root_unit['owner'], cb['callback_name']))
                if benign:
                    evidence.append(cb | {'guest_safe_source_review': benign})
                    continue
            sites, trace_gaps, bodies = self.trace(cb['roots'], AUTH_DEPTH, e['class_or_field'])
            interesting = []
            for uid in bodies:
                for c in self.enriched_unit(uid)['calls']:
                    if sensitive.search(c['method']) and c['method'] not in AUTH_OPTIONAL:
                        interesting.append({k: c[k] for k in ('file', 'line', 'method', 'receiver', 'conditional')})
            if interesting:
                evidence.append(cb | {'sensitive_calls': interesting})
                blockers.append(cb)
            elif sensitive.search(cb['callback_name']) and cb['callback_name'] not in AUTH_OPTIONAL:
                blockers.append(cb)
                evidence.append(cb | {'reason': 'auth-related callback requires further gate/return analysis'})
            if sensitive.search(cb['callback_name']) and trace_gaps:
                gaps.extend(g | {'phase': 'auth_callback'} for g in trace_gaps)
        if mandatory:
            return {'classification': 'authenticated', 'reason': 'active unconditional mandatory authentication filter',
                    'evidence': mandatory}, gaps
        if blockers:
            return {'classification': 'unknown', 'reason': 'replacement resource/token/certificate/permission gates need policy or deployment resolution',
                    'evidence': evidence + [b for b in blockers if not b['roots']]}, gaps
        return {'classification': 'unauthenticated',
                'reason': 'explicit login-filter skip retained; no additional mandatory login gate established by this bounded callback review',
                'evidence': e['auth']['evidence']}, gaps

    def review_entry(self, e):
        owner, action = e['class_or_field'], e['action']
        kind = 'callback_block' if action.startswith('@') else 'registered_action' if e['routes'] else 'public_method_registration_unresolved'
        callbacks, callback_gaps = self.active_callbacks(owner, action) if kind != 'callback_block' else ([], [])
        auth, auth_gaps = self.auth_review(e, callbacks) if kind != 'callback_block' else (
            {'classification': 'unknown', 'reason': 'callback block was miscounted as an action', 'evidence': []}, [])
        sites, gaps, bodies = self.trace(e['roots'], context_owner=owner)
        by_site = {(s['file'], s['line'], s['method'], s['receiver']): s for s in sites}
        original = []
        for m in e['matches']:
            key = m['file'], m['line'], m['method'], m['receiver']
            found = by_site.get(key)
            if found:
                ids = set(m['api_ids'])
                supported_ids = [i for i in found['supported_api_ids'] if i in ids]
                rejected_ids = [i for i in found['rejected_api_ids'] if i in ids]
                unresolved_ids = sorted(ids - set(supported_ids) - set(rejected_ids))
                original.append(found | {'supported_api_ids': supported_ids, 'rejected_api_ids': rejected_ids,
                    'unresolved_api_ids': unresolved_ids,
                    'status': 'supported' if supported_ids else 'unresolved' if unresolved_ids else 'rejected',
                    'baseline_api_ids': m['api_ids'], 'baseline_confidence': m['confidence']})
            else:
                original.append({'file': m['file'], 'line': m['line'], 'method': m['method'], 'receiver': m['receiver'],
                    'status': 'unresolved', 'supported_api_ids': [], 'rejected_api_ids': [], 'unresolved_api_ids': m['api_ids'],
                    'baseline_api_ids': m['api_ids'], 'baseline_confidence': m['confidence'],
                    'reason': 'original operator/call was not rediscovered by the expanded parser; retained as a gap'})
                gaps.append({'kind': 'baseline_site_not_rediscovered', 'file': m['file'], 'line': m['line'], 'method': m['method']})
        supported = [s for s in sites if s['supported_api_ids']]
        unknown = [s for s in original if s['unresolved_api_ids']]
        api_status = 'supported' if supported else 'unresolved' if unknown else 'original_matches_rejected'
        all_gaps = callback_gaps + auth_gaps + gaps
        for s in original:
            unidentified = [i for i in s['unresolved_api_ids'] if self.api[i]['namespace'] is None]
            if unidentified:
                all_gaps.append({'kind': 'inventory_namespace_unknown', 'file': s['file'], 'line': s['line'],
                                 'api_ids': unidentified, 'reason': 'input has no native receiver namespace; C-source inspection excluded'})
        if kind == 'callback_block':
            all_gaps.append({'kind': 'callback_miscounted_as_action', 'source': e['source']})
        elif kind != 'registered_action':
            all_gaps.append({'kind': 'HTTP_registration_unresolved', 'source': e['source']})
        if supported:
            all_gaps.append({'kind': 'branch_and_call_order_unverified', 'reason': 'a statically found site may be conditional or preceded by a halting callback'})
        for gap in all_gaps:
            self.gaps.append(gap | {'entrypoint_id': e['id']})
        return {'entrypoint_id': e['id'], 'gitlab_commit_sha': self.m.sha, 'class_or_field': owner, 'action': action,
            'source': e['source'], 'routes': e['routes'], 'entrypoint_status': kind,
            'baseline_auth': 'unauthenticated', 'reviewed_auth': auth,
            'baseline_qualified': bool(e['qualified_matched_api_ids']), 'api_status': api_status,
            'examined_bodies': len(bodies), 'original_match_reviews': original,
            'qualified_sites': supported, 'supported_api_ids': sorted({i for s in supported for i in s['supported_api_ids']}),
            'newly_qualified': bool(supported) and not bool(e['qualified_matched_api_ids']),
            'callback_review': callbacks, 'gap_count': len(all_gaps)}

    def run(self):
        self.output.mkdir(parents=True, exist_ok=True)
        records = []
        for i, e in enumerate(self.entries, 1):
            records.append(self.review_entry(e))
            if i % 25 == 0:
                print(f'Reviewed {i}/191 candidates; enriched {len(self.enriched)} bodies', flush=True)
        summary = {'gitlab_commit_sha': self.m.sha, 'api_inventory_sha256': hashlib.sha256(self.inventory.read_bytes()).hexdigest(),
            'baseline_summary_sha256': hashlib.sha256((self.baseline / 'summary.json').read_bytes()).hexdigest(),
            'baseline_entrypoints_sha256': hashlib.sha256((self.baseline / 'entrypoints.jsonl.gz').read_bytes()).hexdigest(),
            'baseline_candidates': 191, 'baseline_qualified_candidates': 4,
            'entrypoint_status_counts': dict(collections.Counter(r['entrypoint_status'] for r in records)),
            'api_status_counts': dict(collections.Counter(r['api_status'] for r in records)),
            'reviewed_auth_counts': dict(collections.Counter(r['reviewed_auth']['classification'] for r in records)),
            'qualified_candidates': sum(bool(r['qualified_sites']) for r in records),
            'newly_qualified_candidates': sum(r['newly_qualified'] for r in records),
            'registered_qualified_candidates': sum(bool(r['qualified_sites']) and r['entrypoint_status'] == 'registered_action' for r in records),
            'registered_unauthenticated_qualified_candidates': sum(bool(r['qualified_sites']) and r['entrypoint_status'] == 'registered_action'
                and r['reviewed_auth']['classification'] == 'unauthenticated' for r in records),
            'registered_unknown_auth_qualified_candidates': sum(bool(r['qualified_sites']) and r['entrypoint_status'] == 'registered_action'
                and r['reviewed_auth']['classification'] == 'unknown' for r in records),
            'original_site_review_counts': dict(collections.Counter(s['status'] for r in records for s in r['original_match_reviews'])),
            'gap_counts': dict(collections.Counter(g['kind'] for g in self.gaps)),
            'helper_depth_cap': DEPTH, 'body_cap_per_trace': BODY_CAP, 'auth_helper_depth_cap': AUTH_DEPTH,
            'return_inference_depth_cap': RETURN_DEPTH, 'helper_candidate_cap_per_call': CALL_CANDIDATE_CAP,
            'source_files_opened_for_targeted_review': len(self.touched), 'enriched_bodies': len(self.enriched),
            'execution': 'static Ruby parsing only; no application/gem execution; no C-extension source inspection'}
        (self.output / 'summary.json').write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n')
        write_jsonl(self.output / 'reviews.jsonl.gz', records)
        write_jsonl(self.output / 'gaps.jsonl.gz', self.gaps)
        write_jsonl(self.output / 'source_files.jsonl', [{'file': f, 'sha256': hashlib.sha256((self.source / f).read_bytes()).hexdigest()} for f in sorted(self.touched)])
        with open(self.output / 'reviews.csv', 'w', newline='') as out:
            w = csv.writer(out, lineterminator='\n')
            w.writerow(['entrypoint_id', 'class_or_field', 'action', 'entrypoint_status', 'reviewed_auth', 'api_status', 'baseline_qualified',
                        'newly_qualified', 'qualified_site_count', 'supported_api_ids', 'original_supported', 'original_rejected', 'original_unresolved', 'gaps'])
            for r in records:
                c = collections.Counter(s['status'] for s in r['original_match_reviews'])
                w.writerow([r['entrypoint_id'], r['class_or_field'], r['action'], r['entrypoint_status'], r['reviewed_auth']['classification'],
                    r['api_status'], r['baseline_qualified'], r['newly_qualified'], len(r['qualified_sites']), ';'.join(r['supported_api_ids']),
                    c['supported'], c['rejected'], c['unresolved'], r['gap_count']])
        print(json.dumps(summary, indent=2), flush=True)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'inventory', 'baseline', 'output'):
        p.add_argument('--' + name, type=Path, required=True)
    p.add_argument('--cache', type=Path)
    a = p.parse_args()
    Review(a.source.resolve(), a.inventory.resolve(), a.baseline.resolve(), a.output.resolve(), a.cache).run()


if __name__ == '__main__':
    main()

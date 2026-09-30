#!/usr/bin/env python3
"""Parse Ruby source without loading GitLab or its dependencies."""
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

DEPTH = 2
METHOD_CAP = 64
CANDIDATE_CAP = 8
HTTP = {'get', 'post', 'put', 'patch', 'delete', 'head', 'options', 'match', 'route'}
DYNAMIC = {'send', 'public_send', '__send__', 'method_missing', 'define_method',
           'define_singleton_method', 'class_eval', 'module_eval', 'instance_eval', 'eval',
           'const_get', 'constantize', 'safe_constantize'}
FILTERS = {'before_action', 'prepend_before_action', 'append_before_action',
           'skip_before_action', 'before_filter', 'skip_before_filter'}
AUTH_REQUIRED = {'authenticate_user!', 'authenticate_admin!', 'authenticate!',
                 'require_admin!', 'require_authenticated_user!', 'authenticate_runner!'}
AUTH_OPTIONAL = {'authenticate_sessionless_user!', 'authenticate_with_http_token',
                 'authenticate_with_http_basic'}
EXCLUDED = {'spec', 'test', 'qa', 'vendor', 'doc', 'db', 'node_modules',
            'tooling', 'scripts', 'bin', 'fixtures', 'tmp', '.git', '.ai'}
CONSTANT = re.compile(r'^(?:::)?[A-Z]\w*(?:::[A-Z]\w*)*$')


def git(root, *args):
    return subprocess.check_output(['git', '-C', str(root), *args]).decode().strip()


def txt(node):
    return node.text.decode('utf-8', 'replace') if node else ''


def fld(node, name):
    return node.child_by_field_name(name) if node else None


def walk(node, stop=()):
    if node is None:
        return
    yield node
    for c in node.named_children:
        if c.type not in stop:
            yield from walk(c, stop)


def literal(node):
    if node is None:
        return None
    if node.type in ('simple_symbol', 'hash_key_symbol', 'bare_symbol'):
        return txt(node).lstrip(':')
    if node.type == 'string' and not any(n.type == 'interpolation' for n in walk(node)):
        return ''.join(txt(c) for c in node.named_children if c.type == 'string_content')
    if node.type in ('constant', 'scope_resolution'):
        return txt(node).lstrip(':')
    return None


def args(node):
    a = fld(node, 'arguments')
    return list(a.named_children) if a else []


def options(node):
    result = {}
    for a in args(node):
        for p in walk(a):
            if p.type == 'pair':
                key = literal(fld(p, 'key'))
                if key:
                    result[key] = fld(p, 'value')
    return result


def positional(node):
    return [a for a in args(node) if a.type not in ('pair', 'hash')]


def symbols(node):
    return [literal(n) for n in walk(node) if n.type in ('simple_symbol', 'bare_symbol', 'string')]


def method_name(node):
    return txt(fld(node, 'method'))


def block_body(node):
    return fld(fld(node, 'block'), 'body')


def location(file, node):
    return {'file': file, 'line': node.start_point.row + 1,
            'end_line': node.end_point.row + 1}


def conditional(node, boundary=None):
    p = node.parent
    while p is not None and p != boundary:
        if p.type in ('if', 'unless', 'if_modifier', 'unless_modifier', 'case', 'when',
                      'conditional', 'while', 'until', 'rescue', 'elsif'):
            return True
        p = p.parent
    return False


def rack_context(node):
    p = node.parent
    while p:
        if p.type == 'call' and txt(fld(p, 'receiver')).lstrip(':') == 'Rack::Builder':
            return True
        p = p.parent
    return False


def route_auth_context(node, file):
    result = []
    p = node.parent
    while p:
        if p.type == 'call' and method_name(p) in {'authenticate', 'authenticated', 'constraints'}:
            result.append({**location(file, p), 'name': method_name(p),
                           'expression': txt(p).split('\n')[0][:300], 'conditional': conditional(p)})
        p = p.parent
    return result


class Mapper:
    def __init__(self, source, inventory, output):
        self.source, self.inventory, self.output = source, inventory, output
        self.sha = git(source, 'rev-parse', 'HEAD')
        self.apis = json.loads(inventory.read_text())
        assert isinstance(self.apis, list) and all('id' in a and 'method' in a for a in self.apis)
        self.api_by_name = collections.defaultdict(list)
        for a in self.apis:
            self.api_by_name[a['method']].append(a)
        self.parser = Parser(Language(tree_sitter_ruby.language()))
        self.classes = collections.defaultdict(lambda: {'parents': [], 'mixins': [], 'macros': [], 'files': []})
        self.units, self.method_index, self.aliases = {}, collections.defaultdict(list), {}
        self.entries, self.routes, self.registrations = [], [], []
        self.gaps = collections.defaultdict(list)
        self.files = []
        self.declared_fields = []
        self.mounted_mutations = []
        self.global_helpers = []

    def qualify(self, name, owner):
        if name.startswith('::'):
            return name[2:]
        if not owner or '::' in name:
            return name
        return owner + '::' + name

    def resolve_constant(self, name, owner):
        name = name.lstrip(':')
        candidates = [name]
        parts = owner.split('::')
        for i in range(len(parts), 0, -1):
            candidates.insert(0, '::'.join(parts[:i] + [name]))
        for c in candidates:
            if c in self.classes or c in self.aliases:
                return c
        return name

    def facts(self, body, file, owner):
        calls, types = [], {}
        if body is None:
            return calls
        for n in walk(body, ('method', 'singleton_method', 'class', 'module')):
            if n.type in ('assignment', 'operator_assignment'):
                left, right = fld(n, 'left'), fld(n, 'right')
                if left and right:
                    rt = self.infer(right, types)
                    if rt:
                        types[txt(left)] = rt
                    else:
                        types.pop(txt(left), None)
            if n.type == 'call':
                name = method_name(n)
                receiver = fld(n, 'receiver')
                typ = self.infer(receiver, types)
                call = {**location(file, n), 'name': name, 'receiver': txt(receiver),
                        'receiver_type': typ[0] if typ else None,
                        'receiver_kind': typ[1] if typ else None,
                        'conditional': conditional(n, body),
                        'expression': txt(n).split('\n')[0][:240]}
                if fld(n, 'method'):
                    call['line'] = fld(n, 'method').start_point.row + 1
                if name in DYNAMIC or any(c.type == 'interpolation' for c in walk(fld(n, 'method'))):
                    call['dynamic'] = True
                calls.append(call)
            elif n.type == 'super':
                calls.append({**location(file, n), 'name': 'super', 'receiver': '',
                              'receiver_type': None, 'receiver_kind': None,
                              'conditional': conditional(n, body), 'expression': txt(n)[:240]})
            elif n.type == 'element_reference':
                typ = self.infer(fld(n, 'object'), types)
                # Only qualified operator receivers are considered API candidates.
                if typ:
                    calls.append({**location(file, n), 'name': '[]', 'receiver': txt(fld(n, 'object')),
                                  'receiver_type': typ[0], 'receiver_kind': typ[1],
                                  'conditional': conditional(n, body), 'expression': txt(n)[:240]})
            elif n.type == 'identifier':
                # Ruby's grammar leaves argument-free implicit calls as identifiers.
                p = n.parent
                if txt(n) in types or (p and p.type in ('call', 'assignment', 'operator_assignment',
                        'method_parameters', 'optional_parameter', 'keyword_parameter', 'pair',
                        'block_parameters', 'element_reference', 'scope_resolution')):
                    continue
                calls.append({**location(file, n), 'name': txt(n), 'receiver': '',
                              'receiver_type': None, 'receiver_kind': None,
                              'conditional': conditional(n, body), 'bare_identifier': True,
                              'expression': txt(n)})
        return calls

    def infer(self, node, types):
        if node is None:
            return None
        s = txt(node)
        if CONSTANT.fullmatch(s):
            return s.lstrip(':'), 'singleton'
        if s in types:
            return types[s]
        if node.type == 'call' and method_name(node) == 'new':
            rec = txt(fld(node, 'receiver'))
            if CONSTANT.fullmatch(rec):
                return rec.lstrip(':'), 'instance'
        return None

    def unit(self, node, body, file, owner, name, kind='instance', visibility='public'):
        uid = f'{file}:{node.start_point.row + 1}:{node.start_point.column + 1}:{name}'
        if uid not in self.units:
            self.units[uid] = {**location(file, node), 'id': uid, 'owner': owner, 'name': name,
                               'kind': kind, 'visibility': visibility,
                               'calls': self.facts(body, file, owner),
                               'body': location(file, body) if body else None}
        return uid

    def entry(self, typ, owner, action, file, node, roots=(), route=None, **extra):
        eid = f'{typ}:{owner}:{action}:{file}:{node.start_point.row + 1}:{node.start_point.column + 1}'
        e = {'id': eid, 'type': typ, 'class_or_field': owner, 'action': action,
             'source': location(file, node), 'routes': [route] if route else [],
             'roots': list(roots), **extra}
        self.entries.append(e)
        return e

    def parse(self):
        tracked = git(self.source, 'ls-files', '-z').split('\0')
        for file in sorted(f for f in tracked if f.endswith(('.rb', '.ru'))):
            parts = set(Path(file).parts)
            excluded = sorted(parts & EXCLUDED)
            if excluded:
                self.gaps['skipped_files'].append({'file': file, 'reason': 'excluded directory: ' + ', '.join(excluded)})
                continue
            data = (self.source / file).read_bytes()
            tree = self.parser.parse(data)
            errors = [location(file, n) | {'kind': n.type} for n in walk(tree.root_node)
                      if n.type == 'ERROR' or n.is_missing]
            if errors:
                self.gaps['parse_errors'].extend(errors)
            self.files.append({'file': file, 'sha256': hashlib.sha256(data).hexdigest(),
                               'bytes': len(data), 'parse_errors': len(errors)})
            self.visit(tree.root_node, file, '', 'public', [], [], None)
        print(f'Parsed {len(self.files)} files; indexed {len(self.units)} bodies', flush=True)

    def visit(self, node, file, owner, visibility, path, mods, resource):
        if node is None:
            return
        if node.type in ('class', 'module'):
            name = txt(fld(node, 'name'))
            own = self.qualify(name, owner)
            c = self.classes[own]
            c['files'].append(file)
            sup = fld(node, 'superclass')
            if sup:
                c['parents'].append(txt(sup).lstrip('< ').strip())
            body = fld(node, 'body')
            if body:
                self.visit(body, file, own, 'public', path, mods, resource)
            return
        if node.type in ('method', 'singleton_method'):
            name = txt(fld(node, 'name'))
            kind = 'singleton' if node.type == 'singleton_method' else 'instance'
            p = node.parent
            while p is not None and p.type not in {'class', 'module'}:
                if p.type == 'singleton_class' or (p.type == 'call' and method_name(p) == 'class_methods'):
                    kind = 'singleton'
                p = p.parent
            uid = self.unit(node, fld(node, 'body'), file, owner, name, kind, visibility)
            self.method_index[(owner, name, kind)].append(uid)
            if visibility == 'module_function':
                self.units[uid]['visibility'] = 'private'
                self.method_index[(owner, name, 'singleton')].append(uid)
            if file.startswith(('config/routes', 'ee/config/routes')):
                self.visit(fld(node, 'body'), file, owner, visibility, path, mods, resource)
            elif b'Rack::Builder' in node.text or b'Rack::Handler::' in node.text:
                for n in walk(fld(node, 'body'), ('method', 'singleton_method')):
                    if n.type == 'call' and (txt(fld(n, 'receiver')).lstrip(':') == 'Rack::Builder' or
                            (method_name(n) == 'mount' and 'Rack::Handler::' in txt(n))):
                        self.visit(n, file, owner, visibility, path, mods, resource)
            return
        if node.type == 'assignment':
            left, right = txt(fld(node, 'left')), txt(fld(node, 'right'))
            if CONSTANT.fullmatch(left) and CONSTANT.fullmatch(right):
                self.aliases[self.qualify(left, owner)] = right.lstrip(':')
        if node.type == 'alias':
            self.classes[owner].setdefault('method_aliases', {})[txt(fld(node, 'name')).lstrip(':')] = txt(fld(node, 'alias')).lstrip(':')
        if node.type in ('body_statement', 'program', 'block_body'):
            vis = visibility
            for c in node.named_children:
                if c.type == 'identifier' and txt(c) == 'module_function':
                    vis = 'module_function'
                elif c.type == 'call' and method_name(c) == 'module_function' and not args(c):
                    vis = 'module_function'
                if c.type == 'identifier' and txt(c) in ('private', 'protected', 'public'):
                    vis = txt(c)
                elif c.type == 'call' and method_name(c) in ('private', 'protected', 'public') and not args(c):
                    vis = method_name(c)
                self.visit(c, file, owner, vis, path, mods, resource)
            return
        if node.type == 'call':
            name, opts, pos = method_name(node), options(node), positional(node)
            body = block_body(node)
            c = self.classes[owner]
            if name == 'extend' and any(txt(a) == 'self' for a in pos):
                c['extend_self'] = True
            if name == 'module_function' and pos:
                c.setdefault('module_functions', []).extend(literal(a) for a in pos if literal(a))
            if name in FILTERS or name in {'authorize', 'authorization_scopes', 'skip_authorization', 'authenticate'}:
                c['macros'].append({**location(file, node), 'name': name,
                    'symbols': [literal(a) for a in pos if literal(a)],
                    'only': symbols(opts.get('only')), 'except': symbols(opts.get('except')),
                    'only_specified': 'only' in opts,
                    'conditional': ('if' in opts or 'unless' in opts or conditional(node)),
                    'expression': txt(node).split('\n')[0][:300]})
                if body:
                    uid = self.unit(node, body, file, owner, f'@{name}')
                    c['macros'][-1]['unit'] = uid
            if name in {'include', 'prepend', 'extend', 'helpers'} and pos:
                c['mixins'].extend(txt(a).lstrip(':') for a in pos if CONSTANT.fullmatch(txt(a)))
                if owner == 'API::API' and name == 'helpers':
                    self.global_helpers.extend(c['mixins'])
            if name in {'alias_method', 'alias'} and len(pos) >= 2:
                c.setdefault('method_aliases', {})[literal(pos[0])] = literal(pos[1])
            if name == 'before' and body and ('/api/' in '/' + file):
                uid = self.unit(node, body, file, owner, '@before')
                c.setdefault('befores', []).append({'unit': uid, 'scopes': self.scope_ids(node), **location(file, node)})
            if '/graphql/' in '/' + file and name == 'field' and pos:
                field = literal(pos[0])
                if field:
                    self.declared_fields.append({'owner': owner, 'field': field,
                        'resolver': txt(opts.get('resolver')), 'mutation': txt(opts.get('mutation')),
                        'method': literal(opts.get('resolver_method')) or literal(opts.get('method')) or field,
                        'authorize': txt(opts.get('authorize')), 'source': location(file, node),
                        'node_id': f'{file}:{node.start_point.row + 1}:{node.start_point.column + 1}'})
                else:
                    self.gaps['unresolved_registrations'].append(location(file, node) | {'reason': 'dynamic GraphQL field name'})
            if '/graphql/' in '/' + file and name in {'mount_mutation', 'mount_aliased_mutation'} and pos:
                mutation = txt(pos[1] if name == 'mount_aliased_mutation' and len(pos) > 1 else pos[0])
                self.mounted_mutations.append({'owner': owner, 'mutation': mutation,
                    'alias': literal(pos[0]) if name == 'mount_aliased_mutation' else None,
                    'source': location(file, node), 'node_id': f'{file}:{node.start_point.row + 1}:{node.start_point.column + 1}'})
            if name == 'graphql_name' and pos:
                c['graphql_name'] = literal(pos[0])
            is_routes = file.startswith(('config/routes', 'ee/config/routes'))
            is_api = '/api/' in '/' + file and '/graphql/' not in '/' + file
            if name in HTTP and (is_routes or (is_api and body)):
                if is_api and body:
                    scopes = self.scope_ids(node)
                    uid = self.unit(node, body, file, owner, f'@{name}')
                    verb = literal(pos[0]) if name == 'route' and pos else name.upper()
                    route_pos = pos[1:] if name == 'route' else pos
                    suffix = literal(route_pos[0]) if route_pos else ''
                    route = {'verb': str(verb).upper(), 'path': '/' + '/'.join(path + ([suffix] if suffix else [])),
                             'path_status': 'local DSL template; mount prefix not expanded',
                             'source': location(file, node)}
                    self.entry('grape_endpoint', owner, name.upper(), file, node, [uid], route,
                               scopes=scopes, discovery='endpoint block')
                else:
                    self.rails_route(node, file, owner, path, mods, resource)
                return
            if name in {'mount', 'run', 'map', 'use', 'devise_for', 'use_doorkeeper',
                        'use_doorkeeper_openid_connect', 'use_doorkeeper_device_authorization_grant'}:
                if is_routes or file.endswith('.ru') or rack_context(node) or (is_api and name == 'mount') or (
                        name == 'mount' and 'Rack::Handler::' in txt(node)):
                    handler_body = body
                    if name == 'run' and pos and pos[0].type == 'lambda':
                        handler_body = pos[0]
                    uid = self.unit(node, handler_body, file, owner, '@' + name) if handler_body else None
                    target = txt(pos[0]) if pos else ''
                    at = literal(opts.get('at'))
                    for p in args(node):
                        if p.type == 'pair' and txt(fld(p, 'key')).startswith(('::', 'API', 'Sidekiq', 'Peek')):
                            target, at = txt(fld(p, 'key')), literal(fld(p, 'value'))
                    e = self.entry('http_registration', owner or '<top-level>', name, file, node,
                                   [uid] if uid else [],
                                   {'verb': None, 'path': at, 'path_status': 'registration', 'source': location(file, node)},
                                   target=target, discovery='registration DSL', declaration=txt(node).split('\n')[0][:400])
                    if name == 'mount' and 'Rack::Handler::' in txt(node) and pos:
                        e['helper_target'] = txt(pos[-1])
                    self.registrations.append(e)
                    e['routes'][0]['auth_context'] = route_auth_context(node, file)
            new_path, new_mods, new_res = path[:], mods[:], resource
            if name in {'namespace', 'scope', 'resource', 'resources', 'group'} and body:
                v = literal(pos[0]) if pos else None
                if name == 'namespace':
                    if v:
                        new_path.append(literal(opts.get('path')) or v)
                        new_mods.append(literal(opts.get('module')) or v)
                elif name == 'scope':
                    if literal(opts.get('path')) or v:
                        new_path.append(literal(opts.get('path')) or v)
                    if literal(opts.get('module')):
                        new_mods.append(literal(opts.get('module')))
                elif name in {'resource', 'resources'}:
                    if v:
                        new_path.append(literal(opts.get('path')) or v)
                    if is_routes and v:
                        controller = literal(opts.get('controller')) or v
                        if name == 'resource' and not opts.get('controller') and not controller.endswith('s'):
                            controller += 's'
                        res_mods = mods + ([literal(opts.get('module'))] if literal(opts.get('module')) else [])
                        new_res = {'controller': controller.lstrip('/') if controller.startswith('/') else '/'.join(res_mods + [controller]),
                                   'plural': name == 'resources', 'path': new_path}
                        self.resource_routes(node, file, new_res, opts)
                        if literal(opts.get('module')):
                            new_mods.append(literal(opts.get('module')))
                elif v:
                    new_path.append(v)
            elif name in {'resource', 'resources'} and is_routes and pos:
                v = literal(pos[0])
                if v:
                    controller = literal(opts.get('controller')) or v
                    if name == 'resource' and not opts.get('controller') and not controller.endswith('s'):
                        controller += 's'
                    res_mods = mods + ([literal(opts.get('module'))] if literal(opts.get('module')) else [])
                    self.resource_routes(node, file, {'controller': controller.lstrip('/') if controller.startswith('/') else '/'.join(res_mods + [controller]),
                                         'plural': name == 'resources', 'path': path + [literal(opts.get('path')) or v]}, opts)
            if name in {'member', 'collection'} and resource:
                new_res = resource | {'on': name}
            if body:
                self.visit(body, file, owner, visibility, new_path, new_mods, new_res)
            # Inspect arguments for nested registrations; do not count the surrounding DSL twice.
            for a in args(node):
                self.visit(a, file, owner, name if name in {'private', 'protected', 'public'} else visibility, path, mods, resource)
            return
        for c in node.named_children:
            self.visit(c, file, owner, visibility, path, mods, resource)

    def scope_ids(self, node):
        result = []
        p = node.parent
        while p:
            if p.type == 'call' and method_name(p) in {'namespace', 'resource', 'resources', 'group', 'version'}:
                result.append((p.start_point.row + 1, p.start_point.column + 1))
            p = p.parent
        return result

    def resource_routes(self, node, file, resource, opts):
        actions = {'index': ('GET', ''), 'show': ('GET', ':id'), 'new': ('GET', 'new'),
                   'create': ('POST', ''), 'edit': ('GET', ':id/edit'),
                   'update': ('PATCH/PUT', ':id'), 'destroy': ('DELETE', ':id')}
        only, exc = symbols(opts.get('only')), symbols(opts.get('except'))
        for action, (verb, suffix) in actions.items():
            if ('only' in opts and action not in only) or action in exc or (not resource['plural'] and action == 'index'):
                continue
            if not resource['plural']:
                suffix = suffix.replace(':id/', '').replace(':id', '')
            self.routes.append({'controller': resource['controller'], 'action': action, 'verb': verb,
                'path': '/' + '/'.join(resource['path'] + ([suffix] if suffix else [])),
                'path_status': 'static REST expansion; draw/scopes/concerns may add prefixes',
                'source': location(file, node), 'auth_context': route_auth_context(node, file)})

    def rails_route(self, node, file, owner, path, mods, resource):
        opts, pos = options(node), positional(node)
        target, route_path = literal(opts.get('to')), literal(pos[0]) if pos else None
        for a in args(node):
            if a.type == 'pair' and fld(a, 'key').type == 'string':
                route_path, target = literal(fld(a, 'key')), literal(fld(a, 'value'))
        controller, action = None, None
        if target and '#' in target:
            controller, action = target.split('#', 1)
            if mods and not controller.startswith('/'):
                controller = '/'.join(mods + [controller])
        elif resource and route_path:
            controller = resource['controller']
            action = literal(opts.get('action')) or route_path
        elif literal(opts.get('controller')):
            controller, action = literal(opts['controller']), literal(opts.get('action'))
        route = {'controller': controller, 'action': action, 'verb': method_name(node).upper(),
                 'path': '/' + '/'.join(path + ([route_path] if route_path else [])),
                 'path_status': 'local DSL template; draw/scopes/concerns may add prefixes',
                 'source': location(file, node), 'auth_context': route_auth_context(node, file)}
        if controller and action:
            self.routes.append(route)
        else:
            body = block_body(node)
            to = opts.get('to')
            if body is None and to is not None and (to.type == 'lambda' or method_name(to) in {'proc', 'lambda'}):
                body = to
            uid = self.unit(node, body, file, owner, '@route') if body else None
            e = self.entry('rails_route', owner or '<routes>', target or route_path or '<dynamic>', file, node,
                          [uid] if uid else [], route, discovery='unresolved/inline route',
                          declaration=txt(node).split('\n')[0][:400])
            self.gaps['unresolved_registrations'].append({'entrypoint_id': e['id'], **location(file, node),
                                                       'reason': 'controller/action or inline Rack target not resolved'})

    def ancestry(self, owner, seen=None):
        seen = set() if seen is None else seen
        if owner in seen:
            return []
        seen.add(owner)
        result = [owner]
        c = self.classes.get(owner, {})
        for mix in c.get('mixins', []) + c.get('parents', []):
            result.extend(self.ancestry(self.resolve_constant(mix, owner.rsplit('::', 1)[0] if '::' in owner else ''), seen))
        return result

    def lookup(self, owner, name, kind='instance'):
        for cls in self.ancestry(owner):
            alias = self.classes.get(cls, {}).get('method_aliases', {}).get(name, name)
            hits = self.method_index.get((cls, alias, kind), [])
            c = self.classes.get(cls, {})
            if not hits and kind == 'singleton' and (c.get('extend_self') or alias in c.get('module_functions', [])):
                hits = self.method_index.get((cls, alias, 'instance'), [])
            if hits:
                return hits
        return []

    def finish_entries(self):
        actions = {}
        for uid, u in list(self.units.items()):
            if '/controllers/' in '/' + u['file'] and u['kind'] == 'instance' and u['visibility'] == 'public':
                if not u['owner'].endswith('Controller') or u['owner'] in {'ApplicationController', 'BaseActionController'}:
                    continue
                e = {'id': 'rails_action:' + uid, 'type': 'rails_action', 'class_or_field': u['owner'],
                     'action': u['name'], 'source': {k: u[k] for k in ('file', 'line', 'end_line')},
                     'roots': [uid], 'routes': [], 'discovery': 'public controller method candidate'}
                self.entries.append(e)
                actions[(u['owner'], u['name'])] = e
        for route in self.routes:
            owner = '::'.join(''.join(x[:1].upper() + x[1:] for x in part.split('_'))
                              for part in route['controller'].lstrip('/').split('/')) + 'Controller'
            key = (owner, route['action'])
            if key not in actions:
                roots = self.lookup(owner, route['action'])
                e = {'id': f'rails_action:{owner}:{route["action"]}:{route["source"]["file"]}:{route["source"]["line"]}',
                     'type': 'rails_action', 'class_or_field': owner, 'action': route['action'],
                     'source': route['source'], 'roots': roots, 'routes': [], 'discovery': 'static route declaration'}
                self.entries.append(e)
                actions[key] = e
            actions[key]['routes'].append(route)
        for f in self.declared_fields:
            owner, field = f['owner'], f['field']
            resolver = f['mutation'] or f['resolver']
            cls = self.resolve_constant(resolver.split('.')[0], owner) if resolver else owner
            method = 'resolve' if resolver else f['method']
            roots = self.lookup(cls, method)
            if owner.endswith('QueryType'):
                typ = 'graphql_query'
            elif owner.endswith('MutationType'):
                typ = 'graphql_mutation'
            elif owner.endswith('SubscriptionType'):
                typ = 'graphql_subscription'
            else:
                typ = 'graphql_field'
            e = {'id': f'{typ}:{owner}.{field}:{f["node_id"]}', 'type': typ,
                 'class_or_field': owner + '.' + field, 'action': method, 'source': f['source'],
                 'roots': roots, 'routes': [{'verb': 'GET/POST', 'path': '/api/graphql',
                                           'path_status': 'shared GraphQL transport'}],
                 'resolver_class': cls, 'authorize_declaration': f['authorize'],
                 'discovery': 'field declaration', 'field_owner': owner,
                 'resolver_expression': resolver}
            self.entries.append(e)
            if resolver and '.' in resolver:
                self.gaps['resolver_factories'].append({'entrypoint_id': e['id'], 'source': f['source'],
                    'expression': resolver, 'reason': 'resolver factory not executed; base class resolver body used as heuristic'})
        for f in self.mounted_mutations:
            cls = self.resolve_constant(f['mutation'], f['owner'])
            graphql_name = f['alias'] or self.classes.get(cls, {}).get('graphql_name')
            field = graphql_name or cls
            roots = self.lookup(cls, 'resolve')
            self.entries.append({'id': f'graphql_mutation:{f["owner"]}.{field}:{f["node_id"]}',
                'type': 'graphql_mutation', 'class_or_field': f['owner'] + '.' + field,
                'action': 'resolve', 'source': f['source'], 'roots': roots,
                'routes': [{'verb': 'POST', 'path': '/api/graphql', 'path_status': 'shared GraphQL transport'}],
                'resolver_class': cls, 'resolver_expression': f['mutation'], 'field_owner': f['owner'],
                'graphql_name': graphql_name, 'discovery': 'mount_mutation registration; class name retained when graphql_name is generated'})
        # Standalone resolver/mutation implementations preserve orphan/dynamic registration coverage.
        for uid, u in list(self.units.items()):
            if '/graphql/' in '/' + u['file'] and u['name'] == 'resolve' and u['kind'] == 'instance':
                e = {'id': 'graphql_resolver:' + uid, 'type': 'graphql_resolver',
                     'class_or_field': u['owner'], 'action': 'resolve',
                     'source': {k: u[k] for k in ('file', 'line', 'end_line')},
                     'roots': [uid], 'routes': [], 'resolver_class': u['owner'],
                     'discovery': 'resolver body candidate; schema reachability not established'}
                self.entries.append(e)
        for e in self.registrations:
            target = e.get('target', '').split('.new')[0].lstrip(':')
            if CONSTANT.fullmatch(target):
                target = self.resolve_constant(target, e['class_or_field'])
                e['roots'].extend(self.lookup(target, 'call', 'singleton') or self.lookup(target, 'call'))
            if e.get('helper_target'):
                e['roots'].extend(self.lookup(e['class_or_field'], e['helper_target']))
        for e in self.entries:
            if not e['roots']:
                self.gaps['missing_bodies'].append({'entrypoint_id': e['id'], 'source': e['source'],
                    'reason': 'inherited/generated/external/default object-field body not resolved'})

    def applicable(self, macro, action):
        return (not macro.get('only_specified') or action in macro['only']) and action not in macro['except']

    def auth(self, e):
        evidence, mandatory, uncertain, skipped = [], {}, False, False
        route_guards = [r.get('auth_context', []) for r in e['routes']]
        for contexts in route_guards:
            evidence.extend(contexts)
        if route_guards and all(any(g['name'] in {'authenticate', 'authenticated'} and not g['conditional']
                                    for g in guards) for guards in route_guards):
            return 'authenticated', evidence, 'unconditional authentication route scope'
        owner = e.get('resolver_class', e.get('field_owner', e['class_or_field']))
        chain = self.ancestry(owner)
        if e['type'] == 'rails_action':
            for cls in reversed(chain):
                for m in self.classes.get(cls, {}).get('macros', []):
                    if m['name'] not in FILTERS or not self.applicable(m, e['action']):
                        continue
                    names = m['symbols'][:]
                    if m.get('unit'):
                        names += [c['name'] for c in self.units[m['unit']]['calls']]
                    for name in names:
                        if not name.startswith(('authenticate', 'require_admin', 'require_authenticated', 'authorize')):
                            continue
                        evidence.append(m | {'owner': cls, 'auth_method': name})
                        if 'skip_' in m['name']:
                            if m['conditional']:
                                uncertain = True
                            else:
                                mandatory.pop(name, None)
                                skipped |= name in AUTH_REQUIRED
                        elif name in AUTH_REQUIRED:
                            mandatory[name] = not m['conditional']
                            uncertain |= m['conditional']
                        elif name not in AUTH_OPTIONAL:
                            uncertain = True
            if any(mandatory.values()):
                return 'authenticated', evidence, 'unconditional authentication filter'
            if skipped and not uncertain:
                return 'unauthenticated', evidence, 'mandatory authentication filter explicitly skipped'
        elif e['type'] == 'grape_endpoint':
            units = [(uid, 'body') for uid in e['roots']]
            for cls in chain:
                for b in self.classes.get(cls, {}).get('befores', []):
                    if all(s in e.get('scopes', []) for s in b['scopes']):
                        units.append((b['unit'], 'before'))
            for uid, origin in units:
                for c in self.units[uid]['calls']:
                    name = c['name']
                    if name.startswith(('authenticate', 'require_admin', 'require_authenticated', 'authorize')):
                        evidence.append({**c, 'origin': origin})
                        if (name in AUTH_REQUIRED and not c['conditional']) or (
                            name == 'authenticate_non_get!' and e['action'] not in {'GET', 'HEAD', 'OPTIONS', 'ROUTE'} and not c['conditional']):
                            mandatory[name] = True
                        elif name not in AUTH_OPTIONAL:
                            uncertain = True
            if mandatory:
                return 'authenticated', evidence, 'unconditional endpoint/before authentication call'
        elif e['type'].startswith('graphql'):
            for cls in chain:
                for m in self.classes.get(cls, {}).get('macros', []):
                    if m['name'] in {'authorize', 'authorization_scopes', 'skip_authorization', 'authenticate'}:
                        evidence.append(m | {'owner': cls})
            if e.get('authorize_declaration'):
                evidence.append({'declaration': e['authorize_declaration'], 'source': e['source']})
            gate = self.lookup(owner, 'authorized?', 'singleton')
            gate_owner = self.units[gate[0]]['owner'] if gate else None
            if 'Mutations::BaseMutation' in chain and gate_owner in {None, 'Mutations::BaseMutation'}:
                evidence.extend(self.graphql_mutation_auth_evidence())
                return 'authenticated', evidence, 'BaseMutation execute_graphql_mutation gate; GlobalPolicy prevents anonymous'
            return 'unknown', evidence, 'field permissions/token scopes do not alone establish a login requirement'
        # Treat explicit body guards as evidence, without following arbitrary auth helpers.
        for uid in e['roots']:
            for c in self.units[uid]['calls']:
                if c['name'] in AUTH_REQUIRED:
                    evidence.append(c | {'origin': 'body'})
                    if not c['conditional']:
                        return 'authenticated', evidence, 'unconditional direct body authentication call'
        return 'unknown', evidence, 'no conclusive unconditional authentication/explicit public declaration in bounded evidence'

    def graphql_mutation_auth_evidence(self):
        result = []
        for uid in self.method_index.get(('Mutations::BaseMutation', 'authorized?', 'singleton'), []):
            u = self.units[uid]
            result.append({k: u[k] for k in ('file', 'line', 'end_line', 'owner', 'name')})
        p = self.source / 'app/policies/global_policy.rb'
        if p.exists():
            for i, line in enumerate(p.read_text().splitlines(), 1):
                if 'prevent :execute_graphql_mutation' in line:
                    result.append({'file': 'app/policies/global_policy.rb', 'line': i,
                                   'declaration': line.strip()})
                    break
        return result

    def expand_alias(self, typ, owner):
        seen = set()
        while typ and typ not in seen:
            seen.add(typ)
            full = self.resolve_constant(typ, owner)
            target = self.aliases.get(full, self.aliases.get(typ))
            if not target:
                break
            typ = target
        return typ

    def api_matches(self, call, owner):
        if call.get('dynamic') or call.get('bare_identifier'):
            return None
        candidates = self.api_by_name.get(call['name'], [])
        typ = self.expand_alias(call['receiver_type'], owner)
        kind = call['receiver_kind']
        exact = [a for a in candidates if typ and a['namespace'] == typ and (not a['kinds'] or kind in a['kinds'])]
        reason = 'qualified constant/simple local constructor receiver'
        if typ and call['name'] == 'new' and kind == 'singleton':
            constructors = [a for a in self.api_by_name.get('initialize', [])
                            if a['namespace'] == typ and 'instance' in a['kinds']]
            if constructors:
                exact.extend(constructors)
                reason = 'literal class construction: new invokes initialize (heuristic; factory overrides unproven)'
        if typ == 'CGI':
            exact += [a for a in candidates if a['namespace'] == 'CGI::EscapeExt']
            if exact:
                reason = 'CGI public EscapeExt module mixin alias'
        if exact:
            return [a['id'] for a in exact], True, reason
        if not candidates:
            return None
        # Qualified non-gem receivers with a colliding method are still name-only candidates.
        return [a['id'] for a in candidates], False, 'method spelling only; receiver/native owner/version unproven'

    def edges(self, u, call):
        if call.get('dynamic'):
            return [], 'dynamic dispatch boundary'
        name, rec = call['name'], call['receiver']
        if name == 'super':
            return [], 'super dispatch not resolved'
        if rec in ('', 'self'):
            hits = self.lookup(u['owner'], name, u['kind'])
            if not hits and u['owner'].startswith(('API::', 'EE::API::')):
                for mix in self.global_helpers:
                    hits.extend(self.lookup(self.resolve_constant(mix, u['owner']), name))
            return sorted(set(hits)), 'same owner/inheritance/explicit mixin'
        typ = self.expand_alias(call['receiver_type'], u['owner'])
        if typ:
            cls = self.resolve_constant(typ, u['owner'])
            return self.lookup(cls, name, call['receiver_kind']), 'qualified GitLab method/simple constructed receiver'
        return [], 'receiver type not resolved'

    def prepare_units(self):
        for u in self.units.values():
            matches, edges, gaps = [], [], []
            if u['name'] == 'method_missing':
                self.gaps['dynamic_dispatch_definitions'].append({'unit_id': u['id'],
                    'file': u['file'], 'line': u['line'], 'owner': u['owner'], 'name': u['name']})
            for c in u['calls']:
                matched = self.api_matches(c, u['owner'])
                if matched:
                    ids, supported, reason = matched
                    matches.append({'api_ids': ids, 'qualified': supported, 'reason': reason,
                                    'file': c['file'], 'line': c['line'], 'expression': c['expression'],
                                    'method': c['name'], 'receiver': c['receiver']})
                targets, resolution = self.edges(u, c)
                if len(targets) > 1:
                    gaps.append({'kind': 'helper_name_collision', 'file': c['file'], 'line': c['line'],
                                 'method': c['name'], 'candidates': targets})
                if len(targets) > CANDIDATE_CAP:
                    gaps.append({'kind': 'helper_candidate_cutoff', 'file': c['file'], 'line': c['line'],
                                 'method': c['name'], 'candidates': targets, 'cap': CANDIDATE_CAP})
                    continue
                for target in targets:
                    if target != u['id']:
                        edges.append({'target': target, 'file': c['file'], 'line': c['line'],
                                      'method': c['name'], 'resolution': resolution})
                if c.get('dynamic') or c['name'] == 'super':
                    gaps.append({'kind': 'dynamic_dispatch' if c.get('dynamic') else 'super_dispatch',
                                 **{k: c[k] for k in ('file', 'line', 'name', 'expression')}})
                    if c.get('dynamic'):
                        self.gaps['indexed_dynamic_dispatch_sites'].append({'unit_id': u['id'],
                            **{k: c[k] for k in ('file', 'line', 'name', 'expression')}})
                elif not targets and c['receiver'] and not c.get('receiver_type'):
                    gaps.append({'kind': 'unresolved_receiver', **{k: c[k] for k in ('file', 'line', 'name', 'receiver')}})
            u['matches'], u['edges'], u['gaps'] = matches, edges, gaps
        print('Prepared bounded helper edges and API candidates', flush=True)

    def map_entry(self, e):
        queue = collections.deque((uid, 0, []) for uid in e['roots'])
        visited, matches, seen_matches, entry_gaps = set(), [], set(), []
        deepest_examined = 0
        while queue:
            uid, depth, hops = queue.popleft()
            if uid in visited:
                continue
            if len(visited) >= METHOD_CAP:
                entry_gaps.append({'kind': 'helper_method_cutoff', 'cap': METHOD_CAP,
                                   'remaining_methods': sorted(set([uid] + [q[0] for q in queue]))})
                break
            visited.add(uid)
            deepest_examined = max(deepest_examined, depth)
            u = self.units[uid]
            for m in u['matches']:
                key = (m['file'], m['line'], m['method'], tuple(m['api_ids']))
                if key in seen_matches:
                    continue
                seen_matches.add(key)
                matches.append(m | {'hop_depth': depth, 'helper_path': hops,
                    'confidence': ('direct' if depth == 0 else 'helper') if m['qualified'] else 'name-only'})
            for g in u['gaps']:
                entry_gaps.append(g | {'unit_id': uid, 'hop_depth': depth})
            if depth >= DEPTH:
                for edge in u['edges']:
                    if edge['target'] not in visited:
                        entry_gaps.append(edge | {'kind': 'helper_depth_cutoff', 'hop_depth': depth, 'cap': DEPTH})
                continue
            for edge in u['edges']:
                queue.append((edge['target'], depth + 1, hops + [edge | {'from': uid}]))
        classification, evidence, rationale = self.auth(e)
        e['auth'] = {'classification': classification, 'evidence': evidence, 'rationale': rationale}
        e['gitlab_commit_sha'] = self.sha
        e['matches'] = matches
        e['examined_body_count'] = len(visited)
        e['max_hop_depth_used'] = deepest_examined
        e['max_match_hop_depth'] = max([m['hop_depth'] for m in matches] + [0])
        e['matched_api_ids'] = sorted({a for m in matches for a in m['api_ids']})
        e['qualified_matched_api_ids'] = sorted({a for m in matches if m['qualified'] for a in m['api_ids']})
        if classification == 'unknown':
            self.gaps['unknown_auth'].append({'entrypoint_id': e['id'], 'source': e['source'],
                                             'reason': rationale, 'evidence': evidence})
        for gap in entry_gaps:
            self.gaps[gap['kind']].append(gap | {'entrypoint_id': e['id']})
        return e

    def write_jsonl(self, filename, rows, compressed=False):
        path = self.output / filename
        opener = gzip.open if compressed else open
        with opener(path, 'wt', encoding='utf-8') as out:
            for row in rows:
                out.write(json.dumps(row, sort_keys=True, separators=(',', ':')) + '\n')

    def write(self):
        self.output.mkdir(parents=True, exist_ok=True)
        totals = collections.Counter()
        types = collections.defaultdict(collections.Counter)
        used, qualified_used = set(), set()
        self.entries.sort(key=lambda e: e['id'])
        for i, e in enumerate(self.entries):
            self.map_entry(e)
            auth, hit, qhit = e['auth']['classification'], bool(e['matches']), bool(e['qualified_matched_api_ids'])
            totals['entrypoints_examined'] += 1
            totals[f'{auth}_entrypoints'] += 1
            totals[f'{auth}_with_match'] += hit
            totals[f'{auth}_with_qualified_match'] += qhit
            totals['unmatched_entrypoints'] += not hit
            totals['entrypoints_without_qualified_matches'] += not qhit
            totals['match_sites'] += len(e['matches'])
            for m in e['matches']:
                totals[f'{m["confidence"]}_match_sites'] += 1
            types[e['type']]['entrypoints_examined'] += 1
            types[e['type']][auth] += 1
            types[e['type']]['with_match'] += hit
            types[e['type']]['with_qualified_match'] += qhit
            used.update(e['matched_api_ids'])
            qualified_used.update(e['qualified_matched_api_ids'])
            if i and i % 3000 == 0:
                print(f'Mapped {i}/{len(self.entries)} entries', flush=True)
        for name in self.api_by_name:
            apis = self.api_by_name[name]
            owners = sorted({str(a['namespace']) for a in apis})
            if len(owners) > 1:
                self.gaps['name_collisions'].append({'method': name, 'namespaces': owners,
                    'api_ids': [a['id'] for a in apis],
                    'gitlab_method_definitions': [{k: u[k] for k in ('id', 'owner', 'file', 'line')}
                        for u in self.units.values() if u['name'] == name]})
        all_ids = {a['id'] for a in self.apis}
        manifest = {'gitlab_commit_sha': self.sha, 'gitlab_remote': git(self.source, 'remote', 'get-url', 'origin'),
            'default_branch': git(self.source, 'symbolic-ref', '--short', 'refs/remotes/origin/HEAD'),
            'clone_directory': str(self.source), 'api_inventory_path': str(self.inventory),
            'api_inventory_repository_path': self.inventory.name,
            'api_inventory_sha256': hashlib.sha256(self.inventory.read_bytes()).hexdigest(),
            'api_count': len(self.apis), 'helper_depth_cap': DEPTH, 'helper_method_cap_per_entrypoint': METHOD_CAP,
            'helper_candidates_cap_per_call': CANDIDATE_CAP, 'counts': dict(totals),
            'by_entrypoint_type': {k: dict(v) for k, v in types.items()},
            'apis_with_zero_entrypoint_matches': len(all_ids - used),
            'apis_with_zero_qualified_entrypoint_matches': len(all_ids - qualified_used),
            'parsed_files': len(self.files), 'method_or_block_bodies': len(self.units),
            'coverage_record_counts': {k: len(v) for k, v in self.gaps.items()},
            'execution': 'static parsing only; no application/gem loading; no C-extension source read',
            'profile': 'combined CE and EE declarations; conditional/static candidates, not a deployed route table'}
        (self.output / 'summary.json').write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
        self.write_jsonl('entrypoints.jsonl.gz', self.entries, True)
        self.write_jsonl('api_catalog.jsonl', self.apis)
        self.write_jsonl('zero_match_apis.jsonl', [a for a in self.apis if a['id'] not in used])
        self.write_jsonl('zero_qualified_match_apis.jsonl', [a for a in self.apis if a['id'] not in qualified_used])
        self.write_jsonl('files_examined.jsonl', self.files)
        self.write_jsonl('bodies.jsonl.gz', [{k: v for k, v in u.items() if k not in ('calls', 'matches', 'edges', 'gaps')}
                                          for u in self.units.values()], True)
        for kind, records in self.gaps.items():
            self.write_jsonl(f'coverage_{kind}.jsonl.gz', records, True)
        with open(self.output / 'entrypoints.csv', 'w', newline='') as out:
            writer = csv.writer(out, lineterminator='\n')
            writer.writerow(['gitlab_commit_sha', 'entrypoint_id', 'type', 'class_or_field', 'action',
                'auth', 'file', 'line', 'body_count', 'max_match_hop_depth', 'match_site_count',
                'qualified_match_site_count', 'matched_api_count', 'qualified_matched_api_count', 'routes_json', 'discovery'])
            for e in self.entries:
                writer.writerow([self.sha, e['id'], e['type'], e['class_or_field'], e['action'],
                    e['auth']['classification'], e['source']['file'], e['source']['line'],
                    e['examined_body_count'], e['max_match_hop_depth'], len(e['matches']),
                    sum(m['qualified'] for m in e['matches']), len(e['matched_api_ids']),
                    len(e['qualified_matched_api_ids']), json.dumps(e['routes'], separators=(',', ':')), e['discovery']])
        api_catalog = {a['id']: a for a in self.apis}
        with gzip.open(self.output / 'matches.csv.gz', 'wt', newline='') as out:
            writer = csv.writer(out, lineterminator='\n')
            writer.writerow(['gitlab_commit_sha', 'entrypoint_id', 'auth', 'api_id', 'gem', 'version',
                             'namespace', 'method', 'file', 'line', 'hop_depth', 'confidence', 'reason', 'helper_path_json'])
            for e in self.entries:
                for m in e['matches']:
                    for aid in m['api_ids']:
                        api = api_catalog[aid]
                        writer.writerow([self.sha, e['id'], e['auth']['classification'], aid, api['gem'], api.get('version'),
                            api['namespace'], api['method'], m['file'], m['line'], m['hop_depth'], m['confidence'], m['reason'],
                            json.dumps(m['helper_path'], separators=(',', ':'))])
        self.write_readme(manifest)
        print(json.dumps(manifest['counts'], indent=2), flush=True)

    def write_readme(self, s):
        c = s['counts']
        lines = ['# Front-end inventory and map of listed gem APIs', '',
            f'GitLab canonical default branch: `{s["default_branch"]}` at `{self.sha}`.', '',
            f'Input: `../{self.inventory.name}`; SHA-256 `{s["api_inventory_sha256"]}`. The original schema and file are unchanged.', '',
            'This is a heuristic spelling/receiver map. A match does not establish runtime dispatch, native loading, authorization success, input control, a memory effect on that invocation, or a vulnerability.', '',
            '## Counts', '', '| Classification | Examined | With any match | With qualified match |',
            '|---|---:|---:|---:|']
        for a in ['unauthenticated', 'authenticated', 'unknown']:
            lines.append(f'| {a} | {c.get(a+"_entrypoints",0)} | {c.get(a+"_with_match",0)} | {c.get(a+"_with_qualified_match",0)} |')
        lines += ['', f'Entrypoints examined: **{c["entrypoints_examined"]}**. Unmatched: **{c["unmatched_entrypoints"]}**. Without qualified matches: **{c["entrypoints_without_qualified_matches"]}**.', '',
            f'Inventory API identities: **{s["api_count"]}**. Zero entrypoint matches: **{s["apis_with_zero_entrypoint_matches"]}**. Zero qualified entrypoint matches: **{s["apis_with_zero_qualified_entrypoint_matches"]}**.', '',
            '| Entrypoint type | Examined | With any match | With qualified match |', '|---|---:|---:|---:|']
        for typ, v in sorted(s['by_entrypoint_type'].items()):
            lines.append(f'| {typ} | {v["entrypoints_examined"]} | {v["with_match"]} | {v["with_qualified_match"]} |')
        lines += ['', '## Tables and records', '',
            '- `entrypoints.csv`: all examined entrypoint candidates and route templates.',
            '- `matches.csv.gz`: flattened entrypoint/API rows with gem identity, source site, confidence and helper path.',
            '- `entrypoints.jsonl.gz`: complete records, auth evidence, API IDs, file/line matches, hop depths and helper paths; join `api_ids` to `api_catalog.jsonl`.',
            '- `api_catalog.jsonl`: unchanged input objects, one API identity per row. Versions remain distinct and are not verified against this GitLab lockfile.',
            '- `zero_match_apis.jsonl` and `zero_qualified_match_apis.jsonl`: complete input objects with no matching entrypoint in each confidence population.',
            '- `bodies.jsonl.gz`: extracted method/block source spans. `files_examined.jsonl` records source hashes and parser errors.',
            '- `summary.json`: source revision, input hash, bounds, aggregate counts and coverage counts.', '',
            '## Method and confidence', '',
            'Tree-sitter parses tracked Ruby/Rack source. It never loads the application or gems. C-extension files are not opened. Controllers include public methods as candidates and statically named route actions (including inherited or missing bodies). Grape endpoints are HTTP DSL blocks. GraphQL includes declared query/mutation/subscription fields, object fields and resolver implementations. Registrations include mounts, Rack map/run/use and authentication-engine DSLs. CE and EE are combined; candidate counts are not independent deployed URLs. Controller helpers/overrides can appear among public-method candidates; orphan resolver bodies and mutation output fields are retained with their discovery labels.', '',
            f'Helper traversal follows explicit same-owner/inherited/mixin calls, constant-qualified calls, and variables assigned a literal `Constant.new`. It stops at **{DEPTH} helper hops**, **{METHOD_CAP} bodies per entrypoint**, or more than **{CANDIDATE_CAP} helper candidates per call**. No global method-name helper search is used. Repeated bodies are visited once. `super`, reflective sends and metaprogramming are gaps. Calls after a dynamic site remain searchable, but the dynamic target is never followed.', '',
            '`direct` means a qualified API receiver at hop zero. `helper` means a qualified receiver in an explicitly resolved helper. `name-only` means only the method spelling matches; all corresponding inventory IDs are candidates. Literal constant aliases and local constructor assignments are accepted; literal class construction also considers that class\'s listed instance initialize API. Factory overrides remain unproven. `CGI` to `CGI::EscapeExt` is the sole built-in public-module alias. Generic operator/subscript matches require an inferred receiver; other operators, setters and bare-identifier gem matches are skipped. Native internal wrapper expansion (for example Psych private parsing or BCrypt internals) is not attempted.', '',
            'Hop zero is the selected action/endpoint/resolver body. Callbacks are inspected for authentication but are not added as API-matching roots. No branch/path feasibility, argument flow, callback execution graph, model association type inference or external gem wrapper traversal is computed. Helper matches retain one shortest encountered path per site.', '',
            '## Authentication rules', '',
            '`authenticated` requires a recognized unconditional mandatory auth filter or body/Grape-before call. Rails inherited filters, `only`/`except`, explicit skips and conditional declarations are inspected. `authenticate_non_get!` applies only to statically identified non-read verbs. Optional sessionless/token discovery is not treated as a login requirement. `unauthenticated` requires an explicit mandatory-filter skip with no unresolved replacement auth evidence; it means anonymous access is a static candidate, not a guarantee that permissions or data availability allow it. Other cases remain `unknown`.', '',
            'GraphQL mutation implementations inheriting `Mutations::BaseMutation` are classified from the `execute_graphql_mutation` gate and the GlobalPolicy anonymous prevention, with source evidence; singleton authorized? overrides keep the result unknown. Other fields keep `authorize` and token-scope evidence but remain unknown: resource permissions or API scopes alone do not prove a login requirement. Parent object/schema reachability and EE policy overrides are not solved. No claim of authorization bypass is made.', '',
            '## Coverage appendix', '',
            '| Coverage category | Records |', '|---|---:|---:|']
        for k, v in sorted(s['coverage_record_counts'].items()):
            lines.append(f'| {k} | {v} |')
        lines += ['',
            'Every category above has a `coverage_<category>.jsonl.gz` appendix with locations or entrypoint IDs. `skipped_files` enumerates excluded tracked Ruby/Rack files. Non-Ruby files are outside the parser scope, including C/C++, JavaScript/TypeScript front-end code and Go Workhorse. Parse errors are recorded while unaffected syntax nodes are retained. Unknown-auth records list every undecided entrypoint and collected evidence. Dispatch/cutoff records are per entrypoint/body; repeated source sites may therefore occur. Name collisions group same-spelling APIs from different namespaces; versions also remain separate. Unresolved receivers list other calls that cannot be followed.', '',
            'Routes are local static DSL templates. Draw inclusion prefixes, concerns, mounted Grape prefixes/versions, plural inflection, constraints, environment switches, organization scopes and DSL-generated routes may be incomplete. Default GraphQL object-property resolution, field/type inheritance, dynamic resolver factories, EE prepend composition, callbacks, external engines, generated Ruby and runtime autoload/monkey patches can add or replace behavior. A missing body or zero match is not evidence of absence. Unsupported operators and dynamically computed receivers/names can hide inventory calls. Name-only matches have high false-positive rates; do not treat the any-match totals as established API reachability.', '',
            '## Reproduce', '',
            '```sh', 'python -m pip install -r frontend_gem_api_map/requirements.txt',
            'git clone --depth 1 --single-branch https://gitlab.com/gitlab-org/gitlab.git /workspace/gitlab-frontend-source',
            f'git -C /workspace/gitlab-frontend-source checkout {self.sha}',
            'python frontend_gem_api_map/map_frontend.py --source /workspace/gitlab-frontend-source --inventory gem_api_groups_known_memory_effects.min.json --output frontend_gem_api_map',
            'python frontend_gem_api_map/validate_map.py --source /workspace/gitlab-frontend-source --output frontend_gem_api_map --inventory gem_api_groups_known_memory_effects.min.json',
            '```', '',
            'If the pinned commit has left the shallow default-branch tip, fetch that SHA before checkout. Parser dependency versions are pinned. The inventory and GitLab revision govern the results; earlier archives in the analysis repository are not reused by this mapper.', '']
        (self.output / 'README.md').write_text('\n'.join(lines))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source', type=Path, required=True)
    p.add_argument('--inventory', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    m = Mapper(a.source.resolve(), a.inventory.resolve(), a.output.resolve())
    m.parse()
    m.finish_entries()
    m.prepare_units()
    m.write()


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""Inventory inert C/C++ syntax; never preprocess, compile, load or run sources.

This is a formal-parameter occurrence inventory, not a value/taint analysis.
"""
import argparse, ast, collections, csv, gzip, hashlib, json, pathlib, re, subprocess
from catalog import (PARSERS, ALLOC, RESIZE, COPY, arguments, callee, compact,
                     decl_name, format_index, text, unparen, walk)
from entry_catalog import (REGISTRATIONS, expression_from_string, function_parameters,
                           number, select_source_files)
from fetch_sources import write_csv

COPY_SLOTS = {name: 2 for name in COPY if name not in {'strcpy', 'strcat'}}
COPY_SLOTS.update(mempcpy=2, bcopy=2, wmemcpy=2, wmemmove=2, wcsncpy=2, wcsncat=2,
                  MEMCPY=3, MEMMOVE=3, RB_MEMCPY=3, RB_MEMMOVE=3)
COPY_NAMES = COPY | set(COPY_SLOTS) | {'wcscpy', 'wcscat'}
ALLOC_NAMES = ALLOC | RESIZE
FREE = {'free', 'xfree', 'ruby_xfree', 'ruby_sized_xfree', 'ALLOCV_END', 'RB_ALLOCV_END'}
# Known external C-library boundaries. They are never traversed.
LIBC = set('abort abs acos asin atan atan2 atof atoi atol atoll bsearch ceil clock close '
           'cos cosh dup dup2 exit exp fabs fclose fcntl fdopen feof ferror fflush fgetc '
           'fgetpos fgets floor fopen fork fputc fputs fread freopen fseek fsetpos ftell '
           'fwrite getc getchar getenv getpid gettimeofday isalnum isalpha isascii isblank '
           'iscntrl isdigit isgraph islower isprint ispunct isspace isupper isxdigit labs '
           'llabs log log10 lseek memchr memcmp memset open perror pow putc putchar puts '
           'qsort raise read readlink remove rename rewind round select setbuf setvbuf '
           'sin sinh sleep sqrt stat strchr strcmp strcoll strcspn strerror strftime '
           'strlen strncasecmp strncmp strnlen strpbrk strrchr strspn strstr strtod strtok '
           'strtol strtoll strtoul strtoull strxfrm system tan tanh time tmpfile tmpnam '
           'tolower toupper trunc ungetc unlink usleep vsnprintf wait waitpid write'.split())

FIELDS = ['gem', 'version', 'ruby_method_name', 'c_function', 'argument_index', 'slot',
          'site_file', 'site_line', 'hop_count', 'argument_label', 'parameter_name',
          'site_function', 'callee_or_store', 'slot_argument_index', 'slot_expression',
          'ruby_receiver', 'registration_file', 'registration_line', 'entry_id', 'path',
          'argument_labels', 'slot_labels', 'visible_parameters']
HOP_FIELDS = ['gem', 'version', 'ruby_method_name', 'c_function', 'entry_id', 'file',
              'line', 'hop_count', 'target', 'reason', 'path', 'argument_indices']

def plain(node):
    node = unparen(node)
    while node and node.type == 'cast_expression':
        node = unparen(node.child_by_field_name('value'))
    return node

def declared_name(node, data):
    while node:
        if node.type == 'identifier':
            return text(node, data)
        child = node.child_by_field_name('declarator')
        if child is None and node.type == 'parenthesized_declarator' and node.named_children:
            child = node.named_children[0]
        node = child
    return ''

def direct_registration_name(value):
    parsed = expression_from_string(value)
    if not parsed:
        return None
    _, data, node = parsed
    node = plain(node)
    if node and node.type == 'pointer_expression' and text(node.child_by_field_name('operator'), data) == '&':
        node = plain(node.child_by_field_name('argument'))
    if node and node.type in {'identifier', 'qualified_identifier'}:
        return text(node, data).split('::')[-1]
    return None

def store_parts(node, data):
    if node.type not in {'assignment_expression', 'update_expression'}:
        return None
    left = plain(node.child_by_field_name('left') if node.type == 'assignment_expression'
                 else node.child_by_field_name('argument'))
    if left and left.type == 'subscript_expression':
        index = left.child_by_field_name('index')
        indices = left.child_by_field_name('indices')
        index = index or (indices.named_children[0] if indices and indices.named_children else None)
        return left, index
    if left and left.type == 'pointer_expression' and text(left.child_by_field_name('operator'), data) == '*':
        operand = plain(left.child_by_field_name('argument'))
        if operand and operand.type == 'binary_expression' and text(operand.child_by_field_name('operator'), data) == '+':
            return left, operand.child_by_field_name('right')
    return None

def slots(name, aa):
    result = []
    def add(kind, index, expression=None):
        if expression is not None or 0 <= index < len(aa):
            result.append((kind, index, expression if expression is not None else aa[index]))
    if name in COPY_SLOTS:
        add('length', COPY_SLOTS[name])
    fi = format_index(name)
    if fi is not None and fi >= 0:
        add('format', fi)
        if name in {'snprintf', 'vsnprintf', 'swprintf', 'vswprintf'}:
            add('length', 1)
    if name in ALLOC_NAMES:
        if name in {'ALLOC', 'ZALLOC', 'RB_ALLOC', 'RB_ZALLOC'}:
            result.append(('size', 0, None))  # Implicit sizeof(type), no macro expansion.
        elif name in {'calloc', 'xcalloc', 'ruby_xcalloc', 'xmalloc2', 'ruby_xmalloc2'}:
            add('size', 0); add('size', 1)
        elif name in {'xrealloc2', 'ruby_xrealloc2', 'ruby_xrealloc2_sized'}:
            add('size', 1); add('size', 2)
        elif name in {'REALLOC_N', 'RB_REALLOC_N', 'ALLOCV_N', 'RB_ALLOCV_N'}:
            add('size', 2)
        elif name in {'ALLOC_N', 'ZALLOC_N', 'RB_ALLOC_N', 'RB_ZALLOC_N', 'ALLOCA_N',
                      'RB_ALLOCA_N', 'ALLOCV', 'RB_ALLOCV', 'realloc', 'xrealloc', 'ruby_xrealloc'}:
            add('size', 1)
        else:
            add('size', 0)
    return result

class Inventory:
    def __init__(self, functions, macros, entries):
        self.functions, self.macros, self.entries = functions, macros, entries
        self.names = collections.defaultdict(list)
        for fid, fn in functions.items():
            self.names[(fn['gem'], fn['name'])].append(fid)
        self.parsed, self.templates = {}, {}
        self.rows, self.hops, self.root_records = [], {}, []
        self.contexts = 0

    def resolve(self, name, caller):
        candidates = [fid for fid in self.names.get((caller['gem'], name), [])
                      if set(self.functions[fid]['extension_groups']) & set(caller['extension_groups'])]
        local = [fid for fid in candidates if self.functions[fid]['file'] == caller['file']]
        if len(local) == 1:
            return local[0], ''
        visible = [fid for fid in candidates if not self.functions[fid]['static'] or self.functions[fid]['file'].endswith('.h')]
        if len(visible) == 1:
            return visible[0], ''
        return None, 'ambiguous in-extension definition' if candidates else 'outside extension source'

    def parsed_fn(self, fid):
        if fid not in self.parsed:
            fn = self.functions[fid]
            data = fn['source']
            tree = PARSERS[fn['parser']].parse(data)
            root = next((n for n in walk(tree.root_node) if n.type == 'function_definition'), None)
            self.parsed[fid] = (tree, data, root)
        return self.parsed[fid]

    def issue(self, entry, fn, node, target, reason, path, origins=()):
        line = fn['line'] + (node.start_point.row if node else 0)
        key = (entry['entry_id'], fn['file'], line, target, reason)
        row = dict(gem=entry['gem'], version=entry['version'], ruby_method_name=entry['ruby_method_name'],
                   c_function=entry['c_function'], entry_id=entry['entry_id'], file=fn['file'],
                   line=line, hop_count=max(0, len(path)-1), target=target, reason=reason,
                   path=' -> '.join(self.functions[f]['name'] if f in self.functions else f for f in path),
                   argument_indices=sorted({o[0] for o in origins if isinstance(o[0], int)}))
        if key not in self.hops or row['hop_count'] < self.hops[key]['hop_count']:
            self.hops[key] = row

    def refs(self, node, env, packs, data):
        """Only syntactically present mapped formals / positional extracts."""
        node = plain(node)
        if not node or node.type in {'type_descriptor', 'primitive_type'}:
            return set()
        if node.type == 'identifier':
            return set(env.get(text(node, data), ()))
        if node.type == 'field_expression':
            return self.refs(node.child_by_field_name('argument'), env, packs, data)
        if node.type == 'subscript_expression':
            base = node.child_by_field_name('argument')
            index = node.child_by_field_name('index')
            indices = node.child_by_field_name('indices')
            index = index or (indices.named_children[0] if indices and indices.named_children else None)
            base_name = text(plain(base), data)
            if base_name in packs:
                offset = number(index, data)
                return {(offset, base_name + '[' + str(offset) + ']')} if offset is not None and offset >= 0 else set()
        if node.type == 'call_expression' and callee(node, data) == 'rb_ary_entry':
            aa = arguments(node)
            if len(aa) >= 2 and text(plain(aa[0]), data) in packs:
                offset = number(aa[1], data)
                return {(offset, text(aa[0], data) + '[' + str(offset) + ']')} if offset is not None and offset >= 0 else set()
        children = arguments(node) if node.type == 'call_expression' else node.named_children
        return set().union(*(self.refs(child, env, packs, data) for child in children)) if children else set()

    def pack_refs(self, node, packs, data):
        node = plain(node)
        return {text(node, data)} & packs if node and node.type == 'identifier' else set()

    def transfer_refs(self, node, env, packs, data):
        node = plain(node)
        if not node:
            return set()
        # Occurrence at the outer call is visible syntax; a callee receiving a
        # nested call's return has no mapped formal without that return's model.
        # In particular, never carry an origin through an unexpanded macro.
        if node.type == 'call_expression' and callee(node, data) == 'rb_ary_entry':
            aa = arguments(node)
            if aa and self.pack_refs(aa[0], packs, data):
                return self.refs(node, env, packs, data)
        if any(n.type == 'call_expression' for n in walk(node)):
            return set()
        return self.refs(node, env, packs, data)

    def label(self, node, env, packs, locals_, data):
        if node is None:
            return dict(label='other', expression='<no explicit operand>')
        expression = compact(text(node, data))
        node = plain(node)
        refs = self.refs(node, env, packs, data)
        result = dict(label='other', expression=expression)
        if node and node.type == 'sizeof_expression':
            result['label'] = 'sizeof'
            if refs:
                result['parameters'] = [dict(name=n, index=i) for i, n in sorted(refs)]
        elif refs:
            result.update(label='param', parameters=[dict(name=n, index=i) for i, n in sorted(refs)])
        elif node and node.type in {'number_literal', 'char_literal', 'string_literal', 'concatenated_string',
                                   'true', 'false', 'null', 'nullptr'}:
            result['label'] = 'literal'
        elif node:
            identifiers = {text(n, data) for n in walk(node) if n.type == 'identifier'}
            if identifiers & locals_:
                result['label'] = 'local'
        return result

    def template(self, fid):
        if fid not in self.templates:
            _, data, root = self.parsed_fn(fid)
            fn = self.functions[fid]
            locals_, calls, stores = set(fn['parameters']), [], []
            for node in walk(root, exclude_functions=True) if root else []:
                if node.type == 'declaration':
                    for child in node.named_children:
                        if child.type == 'init_declarator':
                            locals_.add(declared_name(child.child_by_field_name('declarator'), data))
                        elif 'declarator' in child.type or child.type == 'identifier':
                            locals_.add(declared_name(child, data))
                if node.type == 'call_expression':
                    calls.append(node)
                if store_parts(node, data):
                    stores.append(node)
            self.templates[fid] = (data, root, locals_, calls, stores)
        return self.templates[fid]

    def extract(self, entry, fn, calls, env, packs, data, path):
        # rb_scan_args is an argument-position convention, not an executed macro.
        # Do not apply branch-dependent/repeated assignments as value propagation.
        for call in calls:
            name, aa = callee(call, data), arguments(call)
            shift = 1 if name == 'rb_scan_args_kw' else 0
            if name not in {'rb_scan_args', 'rb_scan_args_kw'} or len(aa) < 3 + shift:
                continue
            if not self.pack_refs(aa[1 + shift], packs, data):
                continue
            fmt_node = plain(aa[2 + shift])
            fmt = text(fmt_node, data).strip('"') if fmt_node and fmt_node.type == 'string_literal' else ''
            match = re.fullmatch(r'(\d)(\d)?([*:&]*)', fmt)
            if not match:
                self.issue(entry, fn, call, name, 'unresolved Ruby argument extraction', path)
                continue
            fixed = int(match[1]) + int(match[2] or '0')
            for index, out in enumerate(aa[3 + shift:3 + shift + fixed]):
                out = plain(out)
                target = plain(out.child_by_field_name('argument')) if out and out.type == 'pointer_expression' else None
                if target and target.type == 'identifier':
                    name_out = text(target, data)
                    env[name_out] = {(index, name_out)}
            if match[3]:
                self.issue(entry, fn, call, name, 'rest/keyword/block positions unresolved', path)

        # Positional argv/argument-array extraction into a named local is also
        # a Ruby parameter binding. General local aliases are deliberately absent.
        _, _, root = self.parsed_fn(fn['id'])
        for node in walk(root, exclude_functions=True):
            if node.type == 'init_declarator':
                target = decl_name(node.child_by_field_name('declarator'), data)
                value = plain(node.child_by_field_name('value'))
            elif node.type == 'assignment_expression' and text(node.child_by_field_name('operator'), data) == '=':
                left = plain(node.child_by_field_name('left'))
                target = text(left, data) if left and left.type == 'identifier' else ''
                value = plain(node.child_by_field_name('right'))
            else:
                continue
            positional = value and (value.type == 'subscript_expression' and
                text(plain(value.child_by_field_name('argument')), data) in packs or
                value.type == 'call_expression' and callee(value, data) == 'rb_ary_entry' and
                arguments(value) and text(plain(arguments(value)[0]), data) in packs)
            if target and positional:
                refs = self.refs(value, {}, packs, data)
                if refs:
                    env[target] = {(i, target) for i, _ in refs}
                else:
                    self.issue(entry, fn, node, compact(text(value, data)),
                               'dynamic Ruby argument position unresolved', path)

    def site(self, entry, fn, node, name, aa, selected_slots, env, packs, locals_, data, path):
        labels = []
        for i, a in enumerate(aa):
            label_env = env
            if name in {'rb_scan_args', 'rb_scan_args_kw'} and i >= 3 + (name == 'rb_scan_args_kw'):
                # These address operands bind outputs, rather than use the
                # positional parameters extracted by this call as inputs.
                label_env = {k: v for k, v in env.items() if k in fn['parameters']}
            labels.append(dict(argument_index=i, **self.label(a, label_env, packs, locals_, data)))
        present = {(p['index'], p['name']) for label in labels for p in label.get('parameters', [])}
        if not present:
            return
        slot_labels = []
        for kind, position, expression in selected_slots:
            label = self.label(expression, env, packs, locals_, data)
            if name in {'ALLOC', 'ZALLOC', 'RB_ALLOC', 'RB_ZALLOC'} and expression is None:
                label = dict(label='sizeof', expression='sizeof(' + (text(aa[0], data) if aa else '?') + ')')
            slot_labels.append(dict(slot=kind, argument_index=position, **label))
        for kind, position, expression in selected_slots:
            label = next(s for s in slot_labels if s['slot'] == kind and s['argument_index'] == position)
            rendered = label['label']
            if rendered == 'param':
                rendered += '(' + ';'.join(p['name'] + ',' + str(p['index']) for p in label['parameters']) + ')'
            for index, parameter_name in sorted(present):
                self.rows.append(dict(gem=entry['gem'], version=entry['version'],
                    ruby_method_name=entry['ruby_method_name'], c_function=entry['c_function'],
                    argument_index=index, slot=kind, site_file=fn['file'],
                    site_line=fn['line'] + node.start_point.row, hop_count=len(path)-1,
                    argument_label=rendered, parameter_name=parameter_name, site_function=fn['name'],
                    callee_or_store=name, slot_argument_index=position, slot_expression=label['expression'],
                    ruby_receiver=entry['ruby_receiver'], registration_file=entry['registration_file'],
                    registration_line=int(entry['registration_line']), entry_id=entry['entry_id'],
                    path=' -> '.join(self.functions[f]['name'] for f in path),
                    argument_labels=labels, slot_labels=slot_labels,
                    visible_parameters=[dict(index=i, name=n) for i, n in sorted(present)]))

    def run_root(self, entry):
        caller = dict(gem=entry['gem'], file=entry['registration_file'],
                      line=int(entry['registration_line']), extension_groups=ast.literal_eval(entry['extension_groups']))
        name = direct_registration_name(entry['function_expression'])
        fid, reason = self.resolve(name, caller) if name else (None, 'unexpanded registration macro or function pointer')
        root_record = dict(entry, inventory_status='resolved' if fid else 'unresolved',
                           parameter_names=self.functions[fid]['parameters'] if fid else [])
        self.root_records.append(root_record)
        if not fid:
            self.issue(entry, caller, None, entry['function_expression'], reason, (entry['c_function'],))
            return
        fn = self.functions[fid]
        arity = int(entry['arity']) if entry['arity'] else None
        env, packs = {}, set()
        if arity is not None and arity >= 0 and len(fn['parameters']) >= arity + 1:
            env = {p: {(i, p)} for i, p in enumerate(fn['parameters'][1:arity+1]) if p}
        elif arity == -1 and len(fn['parameters']) >= 3:
            packs.add(fn['parameters'][1])
        elif arity == -2 and len(fn['parameters']) >= 2:
            packs.add(fn['parameters'][1])
        elif entry['registration'] != 'rb_define_alloc_func':
            root_record['inventory_status'] = 'unresolved_signature'
            self.issue(entry, fn, None, name, 'unresolved root parameter signature', (fid,))
        queue, visited = collections.deque([(fid, env, packs, (fid,))]), set()
        while queue:
            current, bindings, packs, path = queue.popleft()
            context = (current, tuple(sorted((k, tuple(sorted(v))) for k, v in bindings.items())), tuple(sorted(packs)))
            if context in visited:
                continue
            visited.add(context)
            self.contexts += 1
            fn = self.functions[current]
            data, root, locals_, calls, stores = self.template(current)
            if root is None or root.has_error or fn['recovered']:
                self.issue(entry, fn, None, fn['name'], 'function body contains parser recovery', path)
                continue
            bindings = dict(bindings)
            self.extract(entry, fn, calls, bindings, packs, data, path)
            for node in stores:
                left, index = store_parts(node, data)
                rhs = node.child_by_field_name('right')
                aa = [left] + ([rhs] if rhs else [])
                self.site(entry, fn, node, 'indexed-store', aa, [('index', -1, index)],
                          bindings, packs, locals_, data, path)
            for call in calls:
                name, aa = callee(call, data), arguments(call)
                incoming = set().union(*(self.refs(a, bindings, packs, data) for a in aa)) if aa else set()
                selected = slots(name, aa)
                if selected:
                    self.site(entry, fn, call, name, aa, selected, bindings, packs, locals_, data, path)
                if name in FREE:
                    continue
                is_macro = (fn['gem'], name) in self.macros or (bool(re.fullmatch(r'[A-Z_][A-Z_0-9]*', name or ''))
                    and (fn['gem'], name) not in self.names)
                if is_macro:
                    self.issue(entry, fn, call, name, 'unexpanded macro', path, incoming)
                    continue
                if selected or name in COPY_NAMES:
                    continue
                if format_index(name) == -1:
                    self.issue(entry, fn, call, name, 'unknown format-call signature', path, incoming)
                    continue
                if name in {'rb_scan_args', 'rb_scan_args_kw', 'rb_ary_entry'}:
                    continue
                if not name or name in locals_:
                    target = compact(text(call.child_by_field_name('function'), data))
                    self.issue(entry, fn, call, target, 'function-pointer or member dispatch', path, incoming)
                    continue
                target, why = self.resolve(name, fn)
                if target:
                    if target in path:
                        self.issue(entry, fn, call, name, 'recursive helper hop', path, incoming)
                        continue
                    target_fn = self.functions[target]
                    next_bindings, next_packs = {}, set()
                    for p, actual in zip(target_fn['parameters'], aa):
                        values = self.transfer_refs(actual, bindings, packs, data)
                        if values:
                            next_bindings[p] = values
                        if self.pack_refs(actual, packs, data):
                            next_packs.add(p)
                    queue.append((target, next_bindings, next_packs, path + (target,)))
                elif name not in LIBC:
                    self.issue(entry, fn, call, name, why, path, incoming)

def index_sources(out):
    sources = list(select_source_files(out))
    entries = list(csv.DictReader((out / 'entry-points.csv').open()))
    build_roots = collections.defaultdict(set)
    for entry in entries:
        build_roots[entry['gem']].update(ast.literal_eval(entry['extension_groups']))
    functions, macros = {}, set()
    for i, record in enumerate(sources, 1):
        data = pathlib.Path(record['absolute_path']).read_bytes()
        if hashlib.sha256(data).hexdigest() != record['sha256']:
            raise ValueError('Catalog source digest mismatch: ' + record['file'])
        tree = PARSERS[record['parser']].parse(data)
        matches = [r for r in build_roots[record['gem']] if record['file'].startswith(r + '/')]
        groups = [max(matches, key=len)] if matches else sorted(build_roots[record['gem']]) or ['ext']
        for node in walk(tree.root_node):
            if node.type in {'preproc_def', 'preproc_function_def'}:
                macros.add((record['gem'], text(node.child_by_field_name('name'), data)))
            if node.type != 'function_definition':
                continue
            name = decl_name(node.child_by_field_name('declarator'), data)
            if not name:
                continue
            fid = f"{record['gem']}:{record['file']}:{node.start_point.row+1}:{name}"
            params = function_parameters(node, data)
            # K&R formal lists have identifier children rather than declarations.
            declarator = node.child_by_field_name('declarator')
            while declarator and declarator.type != 'function_declarator':
                declarator = declarator.child_by_field_name('declarator')
            param_node = declarator.child_by_field_name('parameters') if declarator else None
            if not params and param_node:
                params = [text(n, data) for n in param_node.named_children if n.type == 'identifier']
            functions[fid] = dict(id=fid, gem=record['gem'], version=record['version'],
                file=record['file'], name=name, line=node.start_point.row+1,
                parameters=params, static=bool(re.search(r'\bstatic\b', text(node, data).split('{', 1)[0])),
                parser=record['parser'], source=text(node, data).encode(), recovered=node.has_error,
                extension_groups=groups)
        if i % 500 == 0:
            print(f'Indexed {i}/{len(sources)} native files', flush=True)
    return functions, macros, entries

def dedup_key(row):
    return row['gem'], row['ruby_method_name'], row['argument_index'], row['site_line']

def preference(row):
    own = any(p['index'] == row['argument_index'] for s in row['slot_labels']
              if s['slot'] == row['slot'] and s['argument_index'] == row['slot_argument_index']
              for p in s.get('parameters', []))
    return (row['hop_count'], not own, row['site_file'], row['site_function'],
            row['slot_argument_index'], row['slot'], row['entry_id'])

def jsonlines(path, records):
    with path.open('w') as handle:
        for row in records:
            handle.write(json.dumps(row, sort_keys=True) + '\n')

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', type=pathlib.Path, default=pathlib.Path(__file__).resolve().parents[1])
    args = ap.parse_args()
    functions, macros, entries = index_sources(args.out)
    inventory = Inventory(functions, macros, entries)
    for i, entry in enumerate(entries, 1):
        inventory.run_root(entry)
        if i % 100 == 0:
            print(f'Traced {i}/{len(entries)} roots; {len(inventory.rows)} candidate rows, '
                  f'{len(inventory.hops)} unresolved hops', flush=True)
    grouped = collections.defaultdict(list)
    for row in inventory.rows:
        grouped[dedup_key(row)].append(row)
    rows, collisions = [], []
    for key in sorted(grouped):
        alternatives = sorted(grouped[key], key=preference)
        kept = alternatives[0]
        rows.append(kept)
        # Exact repeated paths/registrations are harmless; preserve different sites/slots.
        distinct = {(r['site_file'], r['site_line'], r['slot'], r['slot_argument_index'],
                     r['slot_expression'], r['ruby_receiver'], r['c_function']) for r in alternatives}
        if len(distinct) > 1:
            collisions.append(dict(key=list(key), representative=kept, alternatives=alternatives[1:]))
    csv_rows = [{k: json.dumps(v, sort_keys=True) if isinstance(v, (dict, list)) else v
                 for k, v in row.items()} for row in rows]
    write_csv(args.out / 'entry-argument-sites.csv', csv_rows, FIELDS)
    jsonlines(args.out / 'entry-argument-sites.jsonl', rows)
    # The supplementary ledger preserves all slots when the requested four-field
    # deduplication key collapses several slots, receivers, or source-file lines.
    jsonlines(args.out / 'argument-inventory-dedup-collisions.jsonl', collisions)
    hops = sorted(inventory.hops.values(), key=lambda r: (r['gem'], r['entry_id'], r['file'], r['line'], r['target'], r['reason']))
    with gzip.open(args.out / 'unresolved-hops.csv.gz', 'wt', newline='') as handle:
        writer = csv.DictWriter(handle, HOP_FIELDS, lineterminator='\n')
        writer.writeheader()
        writer.writerows(dict(r, argument_indices=json.dumps(r['argument_indices'])) for r in hops)
    jsonlines(args.out / 'argument-inventory-roots.jsonl', inventory.root_records)
    previous = json.loads((args.out / 'summary.json').read_text())
    starting_sha = previous.get('starting_repository_sha') or subprocess.check_output(
        ['git', 'rev-parse', 'HEAD'], cwd=args.out, text=True).strip()
    summary = dict(starting_repository_sha=starting_sha,
        objective='Static formal-parameter occurrence and argument-slot inventory',
        roots=len(entries), resolved_roots=sum(r['inventory_status']=='resolved' for r in inventory.root_records),
        unresolved_roots=sum(r['inventory_status']!='resolved' for r in inventory.root_records),
        rows=len(rows), unresolved_hops=len(hops),
        roots_with_rows=len({r['entry_id'] for r in inventory.rows}),
        roots_by_registration=dict(collections.Counter(r['registration'] for r in entries)),
        rows_by_slot=dict(collections.Counter(r['slot'] for r in rows)),
        rows_by_argument_label=dict(collections.Counter(r['argument_label'].split('(')[0] for r in rows)),
        unresolved_hops_by_reason=dict(collections.Counter(r['reason'] for r in hops)),
        extension_gems=len({r['gem'] for r in csv.DictReader((args.out/'files-scanned.csv').open())}),
        source_files=sum(1 for _ in csv.DictReader((args.out/'files-scanned.csv').open())),
        function_definitions=len(functions), helper_contexts_visited=inventory.contexts,
        candidate_argument_slot_rows=len(inventory.rows), dedup_keys_with_distinct_alternatives=len(collisions),
        deduplication_key=['gem','ruby_method_name','argument_index','site_line'],
        target_code_executed=False, lock_sha256=hashlib.sha256((args.out/'Gemfile.lock').read_bytes()).hexdigest())
    original = json.loads((args.out / 'prior-entry-provenance-summary.json').read_text())
    for key in ['gitlab_url', 'gitlab_sha', 'default_branch', 'locked_package_entries',
                'locked_gem_names', 'parser_versions', 'skipped_files', 'files_with_parser_diagnostics']:
        summary[key] = original[key]
    summary.update(entry_points=summary['roots'], kept_rows=summary['rows'],
                   resolved_entry_points=summary['resolved_roots'])
    (args.out / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    (args.out / 'summary.txt').write_text(
        'Static extension call-argument inventory\n'
        f"Starting work SHA: {summary['starting_repository_sha']}\n"
        f"Roots: {summary['roots']} ({summary['resolved_roots']} resolved; {summary['unresolved_roots']} unresolved)\n"
        f"Rows: {summary['rows']}\nUnresolved hops: {summary['unresolved_hops']}\n"
        f"Source files: {summary['source_files']}; extension gems: {summary['extension_gems']}\n"
        f"Dedup keys with distinct alternatives: {len(collisions)}\n"
        'See notes.txt for index conventions, slot signatures and coverage limits.\n'
        'Only archive readers and static analysis tooling ran; target code was not executed.\n')
    print(json.dumps(summary, indent=2), flush=True)

if __name__ == '__main__':
    main()

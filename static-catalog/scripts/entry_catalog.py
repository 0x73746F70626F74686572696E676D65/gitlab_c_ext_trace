#!/usr/bin/env python3
"""Conservative, static Ruby-entry argument provenance within extension sources."""
import argparse, collections, csv, hashlib, json, pathlib, re
from dataclasses import dataclass
from catalog import (PARSERS, ALLOC, RESIZE, COPY, RUBY_FORMAT, arguments, callee,
                     compact, decl_name, format_index, literal, norm, text, unparen,
                     walk, allocator_bounds, analyze, native_scope, lexical_mask)
from fetch_sources import write_csv

REGISTRATIONS = {'rb_define_method', 'rb_define_singleton_method', 'rb_define_module_function',
                 'rb_define_private_method', 'rb_define_protected_method', 'rb_define_alloc_func'}
LENGTHS = {'strlen', 'strnlen', 'RSTRING_LEN', 'RARRAY_LEN', 'RARRAY_LENINT',
           'rb_str_strlen', 'rb_str_length', 'rb_str_bytesize', 'rb_ary_length'}

@dataclass(frozen=True)
class Origin:
    index: int
    path: tuple = ()
    pack: bool = False

def function_parameters(fn, data):
    declarator = fn.child_by_field_name('declarator')
    while declarator and declarator.type != 'function_declarator':
        declarator = declarator.child_by_field_name('declarator')
    parameters = declarator.child_by_field_name('parameters') if declarator else None
    return [decl_name(p.child_by_field_name('declarator'), data)
            for p in parameters.named_children if p.type in {'parameter_declaration', 'optional_parameter_declaration'}] if parameters else []

def store_parts(node, data):
    if node.type != 'assignment_expression' or text(node.child_by_field_name('operator'), data) != '=':
        return None
    left = unparen(node.child_by_field_name('left'))
    if left and left.type == 'subscript_expression':
        index = left.child_by_field_name('index')
        indexes = left.child_by_field_name('indices')
        index = index or (indexes.named_children[0] if indexes and indexes.named_children else None)
        return 'p[i] =', left.child_by_field_name('argument'), index
    if left and left.type == 'pointer_expression' and text(left.child_by_field_name('operator'), data) == '*':
        operand = unparen(left.child_by_field_name('argument'))
        if operand and operand.type == 'binary_expression' and text(operand.child_by_field_name('operator'), data) == '+':
            return '*(p + i) =', operand.child_by_field_name('left'), operand.child_by_field_name('right')
    return None

def sink(name):
    return name in COPY | ALLOC | RESIZE or format_index(name) is not None

def number(node, data):
    node = unparen(node)
    if not node:
        return None
    try:
        raw = re.sub(r'[uUlL]+$', '', text(node, data))
        return int(raw, 0)
    except ValueError:
        return None

def expression_from_string(value, language='c'):
    data = ('void __catalog_expr(void) { return ' + value + '; }').encode()
    tree = PARSERS[language].parse(data)
    fn = next((n for n in walk(tree.root_node) if n.type == 'function_definition'), None)
    ret = next((n for n in walk(fn) if n.type == 'return_statement'), None) if fn else None
    if tree.root_node.has_error or not ret or not ret.named_children:
        return None
    return tree, data, ret.named_children[0]

def select_source_files(out):
    records = list(csv.DictReader((out / 'files-scanned.csv').open()))
    manifest = json.loads((out / 'fetch-manifest.json').read_text())
    by_variant = {(r['gem'], r['locked_version']): r for r in manifest if r['status'] == 'fetched'}
    for record in records:
        variant = record['source_variants'].split(';')[0]
        source = by_variant[(record['gem'], variant)]
        record['absolute_path'] = str(pathlib.Path(source['source_directory']) / record['file'])
        yield record

def index_sources(out):
    functions, entries, macros, sites, issues = {}, [], collections.defaultdict(list), [], []
    files = list(select_source_files(out))
    build_roots = collections.defaultdict(set)
    for source in json.loads((out/'fetch-manifest.json').read_text()):
        if source['status']=='fetched':
            inventory=json.loads((pathlib.Path(source['source_directory'])/'_inventory.json').read_text())
            for member in inventory:
                if pathlib.PurePosixPath(member['path']).name=='extconf.rb':
                    directory=str(pathlib.PurePosixPath(member['path']).parent)
                    if native_scope(source['gem'],directory+'/__catalog__.c'):
                        build_roots[source['gem']].add(directory)
    def groups(gem,path):
        matches=[root for root in build_roots[gem] if path.startswith(root+'/')]
        return [max(matches,key=len)] if matches else sorted(build_roots[gem]) or ['ext']
    for i, record in enumerate(files, 1):
        data = pathlib.Path(record['absolute_path']).read_bytes()
        if hashlib.sha256(data).hexdigest() != record['sha256']:
            raise ValueError('source digest mismatch: ' + record['file'])
        tree = PARSERS[record['parser']].parse(data)
        nodes = list(walk(tree.root_node))
        ranges = []
        for node in nodes:
            if node.type in {'preproc_function_def', 'preproc_def'}:
                name = text(node.child_by_field_name('name'), data)
                replacement = text(node.child_by_field_name('value'), data).strip()
                parameters = node.child_by_field_name('parameters')
                names = [text(n, data) for n in parameters.named_children] if parameters else None
                macros[(record['gem'], name)].append(dict(file=record['file'], parameters=names, replacement=replacement))
            if node.type != 'function_definition':
                continue
            name = decl_name(node.child_by_field_name('declarator'), data)
            if not name:
                continue
            fid = f'{record["gem"]}:{record["file"]}:{node.start_point.row + 1}:{name}'
            functions[fid] = dict(id=fid, gem=record['gem'], version=record['version'], file=record['file'],
                name=name, line=node.start_point.row + 1, byte=node.start_byte,
                parameters=function_parameters(node, data), static=bool(re.search(r'\bstatic\b', text(node, data).split('{',1)[0])),
                parser=record['parser'], source=text(node, data).encode(), recovered=node.has_error,
                extension_groups=groups(record['gem'],record['file']),
                source_sha256=record['sha256'], source_variants=record['source_variants'])
            ranges.append((node.start_byte, node.end_byte, fid))
        for node in nodes:
            name, args = (callee(node, data), arguments(node)) if node.type == 'call_expression' else ('', [])
            if name in REGISTRATIONS:
                alloc = name == 'rb_define_alloc_func'
                if len(args) < (2 if alloc else 4):
                    issues.append(dict(gem=record['gem'], file=record['file'], line=node.start_point.row+1, reason='incomplete Ruby registration'))
                    continue
                ruby_name = '<allocator>' if alloc else text(args[1], data)
                if not alloc and literal(args[1]):
                    try:
                        ruby_name = json.loads(text(args[1], data))
                    except ValueError:
                        ruby_name = text(args[1], data)
                function_expr = text(args[1 if alloc else 2], data)
                arity = 0 if alloc else number(args[3], data)
                entries.append(dict(gem=record['gem'], version=record['version'], ruby_method_name=ruby_name,
                    ruby_receiver=compact(text(args[0], data)), registration=name,
                    function_expression=function_expr, arity=arity, registration_file=record['file'],
                    extension_groups=groups(record['gem'],record['file']),
                    registration_line=node.start_point.row+1, source_variants=record['source_variants']))
            store = store_parts(node, data)
            if sink(name) or store:
                fid = next((fid for a,b,fid in ranges if a <= node.start_byte < b), None)
                if not fid:
                    issues.append(dict(gem=record['gem'], file=record['file'], line=node.start_point.row+1,
                                       reason='site without a parsed enclosing function'))
                    continue
                sites.append(dict(gem=record['gem'], version=record['version'], file=record['file'],
                    line=node.start_point.row+1, byte=node.start_byte, function_id=fid,
                    function=functions[fid]['name'], callee_or_store=store[0] if store else name,
                    argument_snippet=compact(text(node, data))[:240]))
        if i % 500 == 0:
            print(f'Indexed {i}/{len(files)} files: {len(entries)} registrations, {len(sites)} sites', flush=True)
    return functions, entries, macros, sites, issues

class Tracer:
    def __init__(self, functions, macros):
        self.functions, self.macros = functions, macros
        self.names = collections.defaultdict(list)
        for fid, fn in functions.items():
            self.names[(fn['gem'], fn['name'])].append(fid)
        self.parsed, self.local_sites = {}, {}
        self.kept, self.unresolved, self.drops = {}, {}, {}
        self.root, self.active = None, set()

    def resolve(self, name, caller):
        candidates = [fid for fid in self.names.get((caller['gem'], name), [])
                      if set(self.functions[fid].get('extension_groups',['ext'])) & set(caller.get('extension_groups',['ext']))]
        local = [fid for fid in candidates if self.functions[fid]['file'] == caller['file']]
        if len(local) == 1:
            return local[0]
        visible = [fid for fid in candidates if not self.functions[fid]['static'] or self.functions[fid]['file'].endswith('.h')]
        return visible[0] if len(visible) == 1 else None

    def issue(self, fn, node, target, values, reason):
        for origin in values:
            key = (self.root['entry_id'], origin.index, fn['file'], fn['line']+node.start_point.row, target, reason)
            self.unresolved[key] = dict(entry_id=self.root['entry_id'], gem=fn['gem'],
                ruby_method_name=self.root['ruby_method_name'], c_function=self.root['c_function'],
                argument_index=origin.index if not origin.pack else '<argument-vector>',
                file=fn['file'], line=fn['line']+node.start_point.row, target=target, reason=reason,
                path=' -> '.join(origin.path + (fn['name'],)))

    def drop(self, fn, node, values, reason):
        for origin in values:
            self.drops[(self.root['entry_id'], origin.index, fn['file'], fn['line']+node.start_point.row, reason)] = reason

    def macro(self, name, argv, fn):
        definitions = self.macros.get((fn['gem'], name), [])
        local = [m for m in definitions if m['file'] == fn['file']]
        definitions = local or definitions
        alternatives = {(tuple(m['parameters']) if m['parameters'] is not None else None, m['replacement']) for m in definitions}
        if len(alternatives) != 1:
            return None
        params, replacement = next(iter(alternatives))
        if re.search(r'##|(?<![\w])#|\b(?:do|return|goto|if)\b|[;{}]', replacement):
            return None
        if params is None:
            return replacement if not argv else None
        if len(params) != len(argv):
            return None
        substitutions = dict(zip(params, argv))
        return re.sub(r'\b[A-Za-z_]\w*\b', lambda m: '('+substitutions[m[0]]+')' if m[0] in substitutions else m[0], replacement)

    def expression(self, node, env, fn, data, macro_stack=()):
        node = unparen(node)
        if not node:
            return set()
        typ = node.type
        if typ in {'number_literal', 'char_literal', 'string_literal', 'concatenated_string', 'sizeof_expression', 'type_descriptor', 'primitive_type'}:
            return set()
        if typ == 'identifier':
            name = text(node, data)
            if name in env:
                return set(env[name])
            replacement = self.macro(name, [], fn) if name not in macro_stack else None
            parsed = expression_from_string(replacement, fn['parser']) if replacement else None
            return self.expression(parsed[2], env, fn, parsed[1], macro_stack+(name,)) if parsed else set()
        if typ == 'cast_expression':
            return self.expression(node.child_by_field_name('value'), env, fn, data, macro_stack)
        if typ == 'assignment_expression':
            value = self.expression(node.child_by_field_name('right'), env, fn, data, macro_stack)
            left = unparen(node.child_by_field_name('left'))
            if text(node.child_by_field_name('operator'), data) != '=':
                value |= self.expression(left, env, fn, data, macro_stack)
            store = store_parts(node, data)
            if store:
                self.site(fn, node, data, env, store)
            if left and left.type == 'identifier':
                env[text(left,data)] = value
            elif left and left.type=='pointer_expression' and text(left.child_by_field_name('argument'),data) in fn['parameters']:
                pass  # Explicit scalar output-parameter assignments are summarized by statement().
            elif value:
                self.issue(fn, node, compact(text(left,data)), value, 'field/indirect assignment requires alias resolution')
            return value
        if typ == 'subscript_expression':
            base = node.child_by_field_name('argument')
            index = node.child_by_field_name('index')
            indexes = node.child_by_field_name('indices')
            index = index or (indexes.named_children[0] if indexes and indexes.named_children else None)
            values = self.expression(base, env, fn, data, macro_stack)
            integer = number(index, data)
            result = {Origin(o.index+integer,o.path) for o in values if o.pack and integer is not None and integer >= 0}
            unresolved = {o for o in values if not o.pack or integer is None}
            if unresolved:
                self.issue(fn, node, compact(text(node,data)), unresolved, 'indirect read or dynamic Ruby argument index')
            return result
        if typ == 'field_expression':
            base = self.expression(node.child_by_field_name('argument'), env, fn, data, macro_stack)
            if base:
                field = text(node.child_by_field_name('field'), data)
                if re.search(r'(?:len|length|size|count|capacity)',field,re.I):
                    self.drop(fn,node,base,'argument rewritten to an object length/size field')
                else:
                    self.issue(fn,node,compact(text(node,data)),base,'field read requires object/alias resolution')
            return set()
        if typ == 'pointer_expression':
            value = self.expression(node.child_by_field_name('argument'),env,fn,data,macro_stack)
            if text(node.child_by_field_name('operator'),data) == '&':
                return value
            if value:
                self.issue(fn,node,compact(text(node,data)),value,'indirect read requires alias resolution')
            return set()
        if typ == 'conditional_expression':
            self.expression(node.child_by_field_name('condition'),env,fn,data,macro_stack)
            return self.expression(node.child_by_field_name('consequence'),env,fn,data,macro_stack) | self.expression(node.child_by_field_name('alternative'),env,fn,data,macro_stack)
        if typ == 'call_expression':
            name = callee(node,data)
            aa = arguments(node)
            # Addressed output parameters are handled by Ruby argument extraction below.
            values = [self.expression(a,env,fn,data,macro_stack) for a in aa]
            incoming = set().union(*values) if values else set()
            incoming |= self.expression(node.child_by_field_name('function'),env,fn,data,macro_stack)
            if name in {'rb_scan_args','rb_scan_args_kw'}:
                self.site(fn,node,data,env,None,values)
                shift = 1 if name.endswith('_kw') else 0
                if len(aa) >= 3+shift and literal(aa[2+shift]):
                    fmt = text(aa[2+shift],data).strip('"')
                    match = re.match(r'^(\d)(\d)?',fmt)
                    if match:
                        fixed = int(match[1])+int(match[2] or '0')
                        pack = {o for o in values[1+shift] if o.pack}
                        for i,out in enumerate(aa[3+shift:3+shift+fixed]):
                            target = unparen(out.child_by_field_name('argument')) if out.type == 'pointer_expression' else None
                            if target and target.type == 'identifier':
                                env[text(target,data)] = {Origin(o.index+i,o.path) for o in pack}
                        if len(aa)>3+shift+fixed and pack:
                            self.issue(fn,node,name,pack,'rest/keyword/block argument extraction is not mapped to positional indices')
                        return set()
                if incoming:
                    self.issue(fn,node,name,incoming,'Ruby argument extraction has a nonliteral or unsupported signature')
                return set()
            if name == 'rb_ary_entry' and len(aa) >= 2:
                offset = number(aa[1],data)
                packs = {o for o in values[0] if o.pack}
                if packs and offset is not None and offset >= 0:
                    return {Origin(o.index+offset,o.path) for o in packs}
            if name in LENGTHS:
                self.drop(fn,node,incoming,'argument rewritten to a local object length')
                return set()
            if sink(name):
                self.site(fn,node,data,env,None,values)
                return set()
            if not incoming:
                return set()
            if name and name not in macro_stack:
                replacement = self.macro(name,[text(a,data) for a in aa],fn)
                parsed = expression_from_string(replacement,fn['parser']) if replacement else None
                if parsed and not any(n.type=='call_expression' for n in walk(parsed[2])):
                    return self.expression(parsed[2],env,fn,parsed[1],macro_stack+(name,))
            target = self.resolve(name,fn) if name and name not in env and (fn['gem'],name) not in self.macros else None
            if target:
                transferred = [{Origin(o.index,o.path if o.path and o.path[-1]==fn['name'] else o.path+(fn['name'],),o.pack) for o in v} for v in values]
                returns, output_parameters = self.trace(target,transferred)
                for index,result in output_parameters.items():
                    if index >= len(aa):
                        continue
                    argument = aa[index]
                    pointee = unparen(argument.child_by_field_name('argument')) if argument.type == 'pointer_expression' else None
                    if pointee and pointee.type == 'identifier':
                        env[text(pointee,data)] = result
                return returns
            reason = 'unexpanded macro' if (fn['gem'],name) in self.macros or re.match(r'^[A-Z_][A-Z_0-9]*$',name) else 'external call has no in-extension definition'
            if not name or name in env:
                reason = 'function-pointer or member dispatch'
            self.issue(fn,node,name or compact(text(node.child_by_field_name('function'),data)),incoming,reason)
            return set()
        result = set()
        for child in node.named_children:
            result |= self.expression(child,env,fn,data,macro_stack)
        return result

    def site(self, fn, node, data, env, store=None, values=None):
        offset = node.start_byte
        info = self.local_sites[fn['id']].get(offset)
        if not info:
            return  # A macro-generated sink cannot be located as an original source call.
        name, aa = callee(node,data), arguments(node)
        if store:
            slots = [('index',store[2],'index'),('pointer',store[1],'destination')]
        else:
            slots = []
            if name in COPY:
                slots += [('pointer',a,'destination' if i==0 else 'source') for i,a in enumerate(aa[:2])]
                if len(aa)>=3:
                    slots.append(('count',aa[2],'length'))
            fi = format_index(name)
            if fi is not None:
                if fi >= 0 and len(aa)>fi:
                    slots.append(('format',aa[fi],'format'))
                if name in {'snprintf','vsnprintf','swprintf','vswprintf'} and len(aa)>1:
                    slots.append(('count',aa[1],'destination bound'))
                if name in {'sprintf','vsprintf','snprintf','vsnprintf','swprintf','vswprintf'} and aa:
                    slots.append(('pointer',aa[0],'destination'))
            if name in ALLOC | RESIZE:
                if info['arithmetic_copy_pair']:
                    slots += [('size',a,'allocator bound') for a in allocator_bounds(name,aa)]
                if name in RESIZE and aa:
                    slots.append(('pointer',aa[0],'resized pointer'))
        for slot, expression, position in slots:
            if not expression or expression.type == 'sizeof_expression' or literal(expression) or number(expression,data) is not None:
                continue
            if slot == 'index' and 'E' not in info['labels']:
                continue
            # Only this slot's value is tracked; a literal format does not bind a separate pointer/count slot.
            origins = self.expression(expression,env,fn,data) if values is None or expression not in aa else values[aa.index(expression)]
            for origin in origins:
                if origin.pack:
                    self.issue(fn,node,name or store[0],{origin},'argument vector does not identify one Ruby-passed argument')
                    continue
                path = origin.path if origin.path and origin.path[-1]==fn['name'] else origin.path+(fn['name'],)
                helpers = sum(p!=self.root['c_function'] for p in path)
                key = (self.root['entry_id'],origin.index,fn['file'],fn['line']+node.start_point.row,name or store[0],slot,position)
                self.kept[key] = dict(gem=fn['gem'],version=fn['version'],ruby_method_name=self.root['ruby_method_name'],
                    ruby_receiver=self.root['ruby_receiver'],c_function=self.root['c_function'],arity=self.root['arity'],
                    argument_index=origin.index,site_file=fn['file'],site_line=fn['line']+node.start_point.row,
                    callee_or_store=name or store[0],slot=slot,argument_slot=position,
                    note='direct' if helpers==0 else 'via one helper' if helpers==1 else f'via {helpers} helpers',
                    path=' -> '.join(path),argument_snippet=compact(text(expression,data))[:180],
                    registration_file=self.root['registration_file'],registration_line=self.root['registration_line'],
                    entry_id=self.root['entry_id'],site_function=fn['name'])

    def statement(self, node, env, fn, data, returns, outputs):
        if not node:
            return
        typ = node.type
        if typ == 'compound_statement':
            for child in node.named_children:
                if self.statement(child,env,fn,data,returns,outputs):
                    return True
        elif typ == 'declaration':
            for child in node.named_children:
                if child.type == 'init_declarator':
                    target = decl_name(child.child_by_field_name('declarator'),data)
                    env[target] = self.expression(child.child_by_field_name('value'),env,fn,data)
        elif typ == 'if_statement':
            self.expression(node.child_by_field_name('condition'),env,fn,data)
            branches, terminated = [], []
            for field in ('consequence','alternative'):
                local = {k:set(v) for k,v in env.items()}
                ended = self.statement(node.child_by_field_name(field),local,fn,data,returns,outputs)
                branches.append(local)
                terminated.append(bool(ended))
            if all(terminated):
                return True
            continuing = [b for b,t in zip(branches,terminated) if not t]
            for key in set().union(*(set(b) for b in continuing)):
                env[key] = set().union(*(b.get(key,set()) for b in continuing))
        elif typ in {'for_statement','while_statement','do_statement'}:
            self.statement(node.child_by_field_name('initializer'),env,fn,data,returns,outputs)
            self.expression(node.child_by_field_name('condition'),env,fn,data)
            before = {k:set(v) for k,v in env.items()}
            self.statement(node.child_by_field_name('body'),env,fn,data,returns,outputs)
            self.expression(node.child_by_field_name('update'),env,fn,data)
            for k,v in before.items():
                env[k] = env.get(k,set())|v
        elif typ == 'return_statement':
            if node.named_children:
                returns.update(self.expression(node.named_children[0],env,fn,data))
            return True
        elif typ in {'goto_statement','break_statement','continue_statement'}:
            if typ=='goto_statement':
                self.issue(fn,node,'goto',set().union(*env.values()) if env else set(),'goto control flow is not resolved')
            return True
        elif typ in {'switch_statement','preproc_if','preproc_ifdef','preproc_else','preproc_elif'}:
            self.issue(fn,node,typ,set().union(*env.values()) if env else set(),'conditional compilation or switch control flow is not resolved')
            return False
        elif typ in {'function_definition','lambda_expression','preproc_def','preproc_function_def'}:
            return
        else:
            # Explicit *out = value summaries support simple helper output parameters.
            for candidate in walk(node,exclude_functions=True):
                if candidate.type == 'assignment_expression':
                    left = unparen(candidate.child_by_field_name('left'))
                    pointee = unparen(left.child_by_field_name('argument')) if left and left.type=='pointer_expression' else None
                    if pointee and text(pointee,data) in fn['parameters']:
                        index = fn['parameters'].index(text(pointee,data))
                        outputs[index] |= self.expression(candidate.child_by_field_name('right'),env,fn,data)
            self.expression(node,env,fn,data)

    def trace(self, fid, inputs):
        fn = self.functions[fid]
        context = (fid,tuple(tuple(sorted((o.index,o.pack) for o in v)) for v in inputs))
        if context in self.active:
            values = set().union(*inputs) if inputs else set()
            if values:
                parsed = self.parsed[fid]
                self.issue(fn,parsed[2],fn['name'],values,'recursive argument flow not resolved')
            return set(),{}
        self.active.add(context)
        if fid not in self.parsed:
            data = fn['source']
            tree = PARSERS[fn['parser']].parse(data)
            root = next((n for n in walk(tree.root_node) if n.type=='function_definition'),None)
            self.parsed[fid] = (tree,data,root)
            analyzed = analyze(data,fn['parser'])[0]
            self.local_sites[fid] = {s['byte']:s for s in analyzed}
        tree,data,root = self.parsed[fid]
        env = {p:set(inputs[i]) if i<len(inputs) else set() for i,p in enumerate(fn['parameters'])}
        returns, outputs = set(),collections.defaultdict(set)
        if root:
            if fn['recovered'] or root.has_error:
                self.issue(fn,root,fn['name'],set().union(*inputs) if inputs else set(),'function body contains parser recovery')
            else:
                self.statement(root.child_by_field_name('body'),env,fn,data,returns,outputs)
        self.active.remove(context)
        def returned(values):
            return {Origin(o.index,o.path if o.path and o.path[-1]==fn['name'] else o.path+(fn['name'],),o.pack) for o in values}
        return returned(returns),{k:returned(v) for k,v in outputs.items()}

def registration_function(expression, fn, tracer, seen=()):
    parsed = expression_from_string(expression,fn['parser'])
    if not parsed:
        return None
    tree,data,node = parsed
    node = unparen(node)
    while node and node.type=='cast_expression':
        node = unparen(node.child_by_field_name('value'))
    if node and node.type in {'identifier','qualified_identifier'}:
        return text(node,data).split('::')[-1]
    if node and node.type=='pointer_expression' and text(node.child_by_field_name('operator'),data)=='&':
        return registration_function(text(node.child_by_field_name('argument'),data),fn,tracer,seen)
    if node and node.type=='call_expression':
        name = callee(node,data)
        if name not in seen:
            replacement = tracer.macro(name,[text(a,data) for a in arguments(node)],fn)
            if replacement:
                return registration_function(replacement,fn,tracer,seen+(name,))
    return None

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out',type=pathlib.Path,required=True)
    args = ap.parse_args()
    functions,entries,macros,sites,issues = index_sources(args.out)
    tracer = Tracer(functions,macros)
    for i,entry in enumerate(entries):
        entry['entry_id'] = f'{entry["gem"]}:{entry["registration_file"]}:{entry["registration_line"]}:{entry["ruby_method_name"]}'
        caller = dict(gem=entry['gem'],file=entry['registration_file'],parser='c',extension_groups=entry['extension_groups'])
        cname = registration_function(entry['function_expression'],caller,tracer)
        entry['c_function'] = cname or entry['function_expression']
        fid = tracer.resolve(cname,caller) if cname else None
        entry['status'] = 'resolved' if fid else 'unresolved_function_binding'
        if not fid:
            issues.append(dict(gem=entry['gem'],file=entry['registration_file'],line=entry['registration_line'],reason='registration function is an unexpanded macro, missing, or ambiguous'))
            continue
        fn = functions[fid]
        entry['definition_file'],entry['definition_line'] = fn['file'],fn['line']
        arity = entry['arity']
        inputs = [set() for p in fn['parameters']]
        if arity is None or arity < -2 or arity>=0 and len(inputs)<arity+1:
            entry['status']='unresolved_arity_or_callback_signature'
            continue
        if arity>0:
            for index in range(arity):
                inputs[index+1]={Origin(index)}
        elif arity==-1 and len(inputs)>=3:
            inputs[1]={Origin(0,pack=True)}
        elif arity==-2 and len(inputs)>=2:
            inputs[1]={Origin(0,pack=True)}
        if any(inputs):
            tracer.root=entry
            tracer.trace(fid,inputs)
        if i%250==0:
            print(f'Traced {i+1}/{len(entries)} registrations; kept {len(tracer.kept)}, unresolved {len(tracer.unresolved)}',flush=True)
    rows = sorted(tracer.kept.values(),key=lambda r:(r['gem'],r['ruby_method_name'],r['c_function'],r['argument_index'],r['site_file'],r['site_line'],r['slot'],r['argument_slot']))
    write_csv(args.out/'entry-argument-sites.csv',rows,['gem','version','ruby_method_name','ruby_receiver','c_function','arity','argument_index','site_file','site_line','callee_or_store','slot','argument_slot','note','path','argument_snippet','registration_file','registration_line','entry_id','site_function'])
    with (args.out/'entry-argument-sites.jsonl').open('w') as f:
        for row in rows:
            f.write(json.dumps(row)+'\n')
    write_csv(args.out/'entry-points.csv',entries,['gem','version','ruby_method_name','ruby_receiver','c_function','arity','registration','registration_file','registration_line','definition_file','definition_line','status','function_expression','source_variants','entry_id','extension_groups'])
    write_csv(args.out/'sites.csv',sites,['gem','version','file','line','function','callee_or_store','argument_snippet','function_id','byte'])
    write_csv(args.out/'unresolved-hops.csv',sorted(tracer.unresolved.values(),key=lambda r:(r['gem'],r['entry_id'],str(r['argument_index']),r['file'],r['line'],r['target'])),['entry_id','gem','ruby_method_name','c_function','argument_index','file','line','target','reason','path'])
    write_csv(args.out/'index-issues.csv',issues,['gem','file','line','reason'])
    inventory = json.loads((args.out/'inventory-summary.json').read_text())
    summary = {k:inventory[k] for k in ['gitlab_url','gitlab_sha','default_branch','lock_sha256','locked_package_entries','locked_gem_names','fetched_locked_entries','gems_not_fetched','extension_gem_count','gems_with_extensions','files_scanned','unique_gem_file_paths','parser_versions','parser_diagnostics','files_with_parser_diagnostics','lexical_candidates_unparsed','lexical_gaps_by_reason','skipped_files']}
    summary.update(objective='Ruby-callable extension functions with unchanged argument provenance to unbound local slots',
        extensions_scanned=inventory['extension_gem_count'],entry_points=len(entries),
        resolved_entry_points=sum(e['status']=='resolved' for e in entries),
        entry_points_with_ruby_arguments=sum(e['status']=='resolved' and (e['arity']>0 or e['arity'] in {-1,-2}) for e in entries),
        sites=len(sites),kept_rows=len(rows),kept_pairs=len({(r['entry_id'],r['site_file'],r['site_line'],r['callee_or_store']) for r in rows}),
        kept_rows_by_slot=dict(collections.Counter(r['slot'] for r in rows)),unresolved_hops=len(tracer.unresolved),
        unresolved_hops_by_reason=dict(collections.Counter(r['reason'] for r in tracer.unresolved.values())),
        dropped_argument_transfers=len(tracer.drops),drop_transfer_reasons=dict(collections.Counter(tracer.drops.values())),
        index_issues=len(issues),function_definitions=len(functions))
    summary['extension_build_roots']=len({(f['gem'],g) for f in functions.values() for g in f['extension_groups']})
    (args.out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
    print(json.dumps({k:v for k,v in summary.items() if k!='gems_with_extensions'},indent=2),flush=True)

if __name__=='__main__':
    main()

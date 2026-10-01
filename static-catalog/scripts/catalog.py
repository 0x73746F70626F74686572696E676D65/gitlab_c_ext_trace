#!/usr/bin/env python3
"""Function-local syntax catalog. No build, preprocessing, or application execution."""
import argparse, collections, csv, hashlib, importlib.metadata, json, pathlib, re
from tree_sitter import Language, Parser
import tree_sitter_c, tree_sitter_cpp
from fetch_sources import NATIVE, write_csv

COPY = {'memcpy', 'memmove', 'strcpy', 'strncpy', 'strcat', 'strncat'}
ALLOC = {'malloc', 'calloc', 'alloca', 'xmalloc', 'xcalloc', 'ruby_xmalloc', 'ruby_xcalloc',
         'xmalloc2', 'ruby_xmalloc2', 'ALLOCA_N', 'RB_ALLOCA_N',
         'ALLOC', 'ALLOC_N', 'ZALLOC', 'ZALLOC_N', 'RB_ALLOC', 'RB_ALLOC_N',
         'RB_ZALLOC', 'RB_ZALLOC_N', 'ALLOCV', 'ALLOCV_N', 'RB_ALLOCV', 'RB_ALLOCV_N'}
RESIZE = {'realloc', 'xrealloc', 'ruby_xrealloc', 'xrealloc2', 'ruby_xrealloc2',
          'ruby_xrealloc2_sized', 'REALLOC_N', 'RB_REALLOC_N'}
RELEASE = {'free', 'xfree', 'ruby_xfree', 'ruby_sized_xfree', 'ALLOCV_END', 'RB_ALLOCV_END'}
HELPERS = {'strlen', 'strnlen', 'memcmp', 'rb_memhash', 'st_hash', 'st_hash_start',
           'st_hash_end', 'st_hash_uint', 'st_hash_uint32'}
RUBY_FORMAT = {'rb_sprintf': 0, 'rb_vsprintf': 0, 'rb_enc_sprintf': 1, 'rb_str_catf': 1, 'rb_str_vcatf': 1,
               'rb_enc_raise': 2, 'rb_str_format': 2,
               'rb_raise': 1, 'rb_warn': 0, 'rb_warning': 0, 'rb_fatal': 0, 'rb_bug': 0,
               'rb_scan_args': 2, 'rb_scan_args_kw': 3}
ASSOCIATED = {
    'grpc': [('src/', 'src/ruby/ext/grpc/extconf.rb: build gRPC core'),
             ('include/', 'src/ruby/ext/grpc/extconf.rb: gRPC headers'),
             ('third_party/', 'gRPC bundled build dependencies')],
    'rugged': [('vendor/libgit2/', 'ext/rugged/extconf.rb: LIBGIT2_DIR')],
    'prism': [('src/', 'ext/prism/extconf.rb: add_libprism_source'),
              ('include/', 'ext/prism/extconf.rb: find_header')],
    'rbs': [('src/', 'ext/rbs_extension/extconf.rb: VPATH/srcs'),
            ('include/', 'ext/rbs_extension/extconf.rb: INCFLAGS')],
    'nokogiri': [('gumbo-parser/src/', 'ext/nokogiri/extconf.rb: gumbo source recipe')],
}
PARSERS = {'c': Parser(Language(tree_sitter_c.language())),
           'cpp': Parser(Language(tree_sitter_cpp.language()))}

def walk(node, exclude_functions=False):
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        if exclude_functions and current != node and current.type in {'function_definition', 'lambda_expression'}:
            continue
        stack.extend(reversed(current.named_children))

def text(node, data):
    return data[node.start_byte:node.end_byte].decode('utf-8', errors='replace') if node else ''

def compact(value):
    return re.sub(r'\s+', ' ', value).strip()

def norm(value):
    return re.sub(r'\s+', '', value)

def unparen(node):
    while node and node.type == 'parenthesized_expression' and node.named_children:
        node = node.named_children[0]
    return node

def decl_name(node, data):
    while node:
        if node.type in {'identifier', 'field_identifier', 'qualified_identifier', 'operator_name', 'destructor_name'}:
            return text(node, data)
        node = node.child_by_field_name('declarator')
    return ''

def callee(call, data):
    fn = call.child_by_field_name('function')
    if fn and fn.type in {'identifier', 'qualified_identifier'}:
        return text(fn, data).split('::')[-1]
    return ''

def arguments(call):
    args = call.child_by_field_name('arguments')
    return args.named_children if args else []

def format_index(name):
    if name in RUBY_FORMAT:
        return RUBY_FORMAT[name]
    if not re.fullmatch(r'\w*(?:printf|scanf)(?:_s)?', name):
        return None
    name = name.removesuffix('_s')
    # Recognized standard signatures; other suffix matches remain sites with unknown signature.
    if name in {'printf', 'vprintf', 'scanf', 'vscanf', 'wprintf', 'vwprintf', 'wscanf', 'vwscanf'}:
        return 0
    if name in {'fprintf', 'vfprintf', 'fscanf', 'vfscanf', 'sprintf', 'vsprintf', 'sscanf',
                'vsscanf', 'fwprintf', 'vfwprintf', 'fwscanf', 'vfwscanf', 'swscanf', 'vswscanf',
                'asprintf', 'vasprintf', 'dprintf', 'vdprintf'}:
        return 1
    if name in {'snprintf', 'vsnprintf', 'swprintf', 'vswprintf'}:
        return 2
    return -1

def selected(name):
    return name in COPY | ALLOC | RESIZE | RELEASE | HELPERS | {'memset'} or format_index(name) is not None

def literal(node):
    node = unparen(node)
    return bool(node and (node.type == 'string_literal' or
                node.type == 'concatenated_string' and all(literal(n) for n in node.named_children)))

def constant(node, data, constants):
    node = unparen(node)
    if not node:
        return False
    if node.type in {'number_literal', 'char_literal', 'sizeof_expression'}:
        return True
    if node.type == 'identifier':
        return text(node, data) in constants
    if node.type in {'binary_expression', 'unary_expression', 'cast_expression'}:
        children = [x for x in node.named_children if x.type not in {'type_descriptor', 'primitive_type'}]
        return bool(children) and all(constant(x, data, constants) for x in children)
    return False

def assignment_target(call, data):
    current = call
    while current.parent and current.parent.type in {'parenthesized_expression', 'cast_expression'}:
        current = current.parent
    parent = current.parent
    if parent and parent.type == 'init_declarator' and parent.child_by_field_name('value') == current:
        return decl_name(parent.child_by_field_name('declarator'), data)
    if parent and parent.type == 'assignment_expression' and parent.child_by_field_name('right') == current:
        return compact(text(parent.child_by_field_name('left'), data))
    return ''

def alloc_size(name, args):
    if name in {'ALLOC', 'ZALLOC', 'RB_ALLOC', 'RB_ZALLOC'}:
        return None
    index = 1 if name in {'ALLOC_N', 'ZALLOC_N', 'RB_ALLOC_N', 'RB_ZALLOC_N', 'ALLOCA_N', 'RB_ALLOCA_N',
                         'ALLOCV', 'RB_ALLOCV', 'realloc', 'xrealloc', 'ruby_xrealloc',
                         'xrealloc2', 'ruby_xrealloc2', 'ruby_xrealloc2_sized'} else (
            2 if name in {'REALLOC_N', 'RB_REALLOC_N', 'ALLOCV_N', 'RB_ALLOCV_N'} else 0)
    return args[index] if len(args) > index else None

def allocator_bounds(name, args):
    if name in {'calloc', 'xcalloc', 'ruby_xcalloc', 'xmalloc2', 'ruby_xmalloc2'}:
        return args[:2]
    if name in {'xrealloc2', 'ruby_xrealloc2', 'ruby_xrealloc2_sized'}:
        return args[1:3]
    bound = alloc_size(name, args)
    return [bound] if bound else []

def integer_rank(typ):
    match = re.search(r'\b(?:u?int(8|16|32|64)_t)\b', typ)
    if match:
        return {'8': 1, '16': 2, '32': 3, '64': 5}[match[1]]
    if re.search(r'\b(?:size_t|ssize_t)\b', typ):
        return 5
    if 'long long' in typ:
        return 5
    for word, rank in [('char', 1), ('short', 2), ('long', 4), ('int', 3)]:
        if re.search(r'\b' + word + r'\b', typ):
            return rank
    return None

def lexical_mask(data):
    # Preserve offsets while excluding comments and literals from candidate reconciliation.
    pattern = rb'//[^\n]*|/\*[\s\S]*?\*/|"(?:\\[\s\S]|[^"\\])*"|\'(?:\\[\s\S]|[^\'\\])*\''
    return re.sub(pattern, lambda m: re.sub(rb'[^\n]', b' ', m[0]), data)

def lexical_gaps(data, nodes):
    recognized, macro_spans = set(), []
    for n in nodes:
        if n.type == 'preproc_arg':
            macro_spans.append((n.start_byte, n.end_byte))
        if n.type in {'call_expression', 'function_declarator'}:
            head = n.child_by_field_name('function' if n.type == 'call_expression' else 'declarator')
            if head:
                for match in re.finditer(rb'\b([A-Za-z_]\w*)\s*$', data[head.start_byte:head.end_byte]):
                    recognized.add(head.start_byte + match.start(1))
    gaps = []
    for match in re.finditer(rb'\b([A-Za-z_]\w*)\s*\(', lexical_mask(data)):
        name = match[1].decode('ascii')
        if not selected(name) or match.start(1) in recognized:
            continue
        start = match.start(1)
        is_macro = any(a <= start < b for a, b in macro_spans)
        gaps.append(dict(line=data.count(b'\n', 0, start) + 1, callee=name,
                         reason='unexpanded macro replacement tokens' if is_macro else 'lexical candidate without parsed call/declarator',
                         snippet=compact(data[start:start + 100].decode('utf-8', errors='replace'))))
    return gaps

def enclosing_block(node):
    current = node.parent
    while current:
        if current.type == 'compound_statement':
            return current
        current = current.parent
    return None

def offset_within_block(node, block):
    return bool(block and block.start_byte < node.start_byte < block.end_byte)

def previous_statement(node):
    current = node
    while current.parent and current.parent.type not in {'compound_statement', 'translation_unit'}:
        current = current.parent
    return current.prev_named_sibling

def bounds_compared(store, index, data):
    # Only this physical line or the immediately preceding condition is eligible.
    line = store.start_point.row
    lines = data.decode('utf-8', errors='replace').splitlines()
    line_text = lines[line] if line < len(lines) else ''
    token = re.escape(compact(index))
    if not token:
        return False
    # Require a length-looking expression on the other side, rather than any comparison.
    length = r'(?:[\w.>\-]*(?:len|length|size|count|capacity|cap|end|limit|max|nitems|nelem|nbytes|num)[\w.>\-]*|n|\d+|sizeof\s*\([^)]*\))'
    comparison = rf'(?:\b{token}\s*(?:<|<=|>|>=|!=)\s*{length}\b|{length}\s*(?:<|<=|>|>=|!=)\s*\b{token}\b)'
    if re.search(comparison, line_text, re.I):
        return True
    current = store.parent
    while current and current.type != 'function_definition':
        if current.type in {'if_statement', 'for_statement', 'while_statement'}:
            condition = current.child_by_field_name('condition')
            if condition and condition.end_point.row == line - 1:
                return bool(re.search(comparison, compact(text(condition, data)), re.I))
        current = current.parent
    previous = previous_statement(store)
    if previous and previous.type == 'if_statement':
        condition = previous.child_by_field_name('condition')
        if condition and condition.end_point.row == line - 1:
            return bool(re.search(comparison, compact(text(condition, data)), re.I))
    return False

def analyze(data, language):
    tree = PARSERS[language].parse(data)
    nodes = list(walk(tree.root_node))
    diagnostics = [dict(line=n.start_point.row + 1, end_line=n.end_point.row + 1,
                        kind='ERROR' if n.type == 'ERROR' else 'MISSING',
                        snippet=compact(text(n, data))[:100].rstrip())
                   for n in nodes if n.type == 'ERROR' or n.is_missing]
    functions = [n for n in nodes if n.type == 'function_definition']
    candidates, seen_nodes = [], set()
    for fn in functions:
        body = fn.child_by_field_name('body')
        if not body:
            continue
        fn_nodes = list(walk(body, exclude_functions=True))
        name = decl_name(fn.child_by_field_name('declarator'), data) or '<unresolved-function>'
        parameter_nodes = [n for n in walk(fn.child_by_field_name('declarator')) if n.type == 'parameter_declaration']
        parameters = {decl_name(n.child_by_field_name('declarator'), data) for n in parameter_nodes}
        constants, capacities, allocations, origins, writes, local_ranks = set(), {}, [], [], [], {}
        for declaration in parameter_nodes + [n for n in fn_nodes if n.type == 'declaration']:
            rank = integer_rank(text(declaration.child_by_field_name('type'), data))
            for child in declaration.named_children:
                if child.type == 'init_declarator':
                    child = child.child_by_field_name('declarator')
                variable = decl_name(child, data)
                if variable and rank:
                    local_ranks[variable] = rank
        calls = [n for n in fn_nodes if n.type == 'call_expression']
        for node in fn_nodes:
            if node.type == 'declaration' and re.search(r'\b(?:const|constexpr)\b', text(node, data)):
                for child in node.named_children:
                    if child.type == 'init_declarator' and constant(child.child_by_field_name('value'), data, constants):
                        constants.add(decl_name(child.child_by_field_name('declarator'), data))
            if node.type == 'array_declarator':
                size = node.child_by_field_name('size')
                if size and constant(size, data, constants):
                    variable = decl_name(node.child_by_field_name('declarator'), data)
                    declaration = node.parent
                    while declaration and declaration.type not in {'declaration', 'parameter_declaration', 'field_declaration'}:
                        declaration = declaration.parent
                    # Array parameters decay to pointers and supply no local capacity.
                    if declaration and declaration.type == 'declaration':
                        capacities[variable] = (compact(text(size, data)), bool(re.search(r'\b(?:char|uint8_t|int8_t)\b', text(declaration, data))), node.start_byte)
            if node.type == 'assignment_expression':
                writes.append((node, compact(text(node.child_by_field_name('left'), data)),
                               compact(text(node.child_by_field_name('right'), data))))
            if node.type == 'call_expression':
                cname, args = callee(node, data), arguments(node)
                target = assignment_target(node, data)
                if cname in ALLOC | RESIZE:
                    if cname in {'REALLOC_N', 'RB_REALLOC_N'} and args:
                        target = compact(text(args[0], data))
                    size = alloc_size(cname, args)
                    allocations.append((node, target, size, cname))
                    if target and size and constant(size, data, constants) and cname not in {'calloc', 'xcalloc', 'ruby_xcalloc', 'xmalloc2', 'ruby_xmalloc2'}:
                        capacities[target] = (compact(text(size, data)), cname in {'malloc', 'xmalloc', 'ruby_xmalloc', 'alloca'}, node.start_byte)
                elif target:
                    origins.append((node, target, cname))

        pairs = collections.defaultdict(list)
        for alloc, target, size, cname in allocations:
            if not target or not size:
                continue
            counts = set()
            for expr in [n for bound in allocator_bounds(cname, arguments(alloc)) for n in walk(bound)]:
                if expr.type == 'binary_expression':
                    operator = text(expr.child_by_field_name('operator'), data)
                    if operator in {'+', '*'}:
                        for side in ('left', 'right'):
                            operand = expr.child_by_field_name(side)
                            if operand and not constant(operand, data, constants):
                                counts.add(norm(text(operand, data)))
                if expr.type == 'cast_expression':
                    typ = text(expr.child_by_field_name('type'), data)
                    operand = unparen(expr.child_by_field_name('value'))
                    source_rank = local_ranks.get(text(operand, data))
                    target_rank = integer_rank(typ)
                    if operand and source_rank and target_rank and source_rank > target_rank:
                        counts.add(norm(text(operand, data)))
            for copy in calls:
                cn, aa = callee(copy, data), arguments(copy)
                if copy.start_byte <= alloc.end_byte or cn not in COPY or len(aa) < 3:
                    continue
                if norm(text(unparen(aa[0]), data)) == norm(target) and norm(text(unparen(aa[2]), data)) in counts:
                    if any(alloc.end_byte < w.start_byte < copy.start_byte and norm(left) == norm(target)
                           for w, left, right in writes):
                        continue
                    reason = f'{cname} at line {alloc.start_point.row + 1}: size {compact(text(size, data))}; {cn} at line {copy.start_point.row + 1}: count {compact(text(aa[2], data))}'
                    pairs[alloc.start_byte].append(reason)
                    pairs[copy.start_byte].append(reason)

        for node in fn_nodes:
            cname, args, store_index = '', [], None
            if node.type == 'call_expression':
                cname = callee(node, data)
                if not selected(cname):
                    continue
                args = arguments(node)
                snippet = ', '.join(compact(text(a, data)) for a in args)
            elif node.type == 'assignment_expression' and text(node.child_by_field_name('operator'), data) == '=':
                left = unparen(node.child_by_field_name('left'))
                if left and left.type == 'subscript_expression':
                    index = left.child_by_field_name('index')
                    if index is None:
                        indexes = left.child_by_field_name('indices')
                        index = indexes.named_children[0] if indexes and indexes.named_children else None
                    store_index, cname = compact(text(index, data)), 'p[i] ='
                elif left and left.type == 'pointer_expression' and text(left.child_by_field_name('operator'), data) == '*':
                    operand = unparen(left.child_by_field_name('argument'))
                    if operand and operand.type == 'binary_expression' and text(operand.child_by_field_name('operator'), data) == '+':
                        store_index = compact(text(operand.child_by_field_name('right'), data))
                        cname = '*(p + i) ='
                if store_index is None:
                    continue
                snippet = compact(text(node, data))
            else:
                continue
            seen_nodes.add((node.start_byte, node.type))
            labels, evidence = [], []
            f_reason = ''
            fi = format_index(cname)
            if cname in HELPERS:
                f_reason = 'helper explicitly included by F'
            elif fi is not None and fi >= 0 and len(args) > fi and literal(args[fi]):
                f_reason = 'literal format argument'
            elif cname in COPY | {'memset'} and len(args) > 2:
                bound = args[2]
                if any(n.type == 'sizeof_expression' for n in walk(bound)):
                    f_reason = 'sizeof in length argument'
                else:
                    dest = compact(text(unparen(args[0]), data))
                    capacity = capacities.get(dest)
                    if capacity and capacity[1] and capacity[2] < node.start_byte and constant(bound, data, constants) and norm(text(bound, data)) == norm(capacity[0]):
                        f_reason = 'constant length matches local byte destination capacity'
            elif cname in ALLOC | RESIZE:
                bounds = allocator_bounds(cname, args)
                if any(n.type == 'sizeof_expression' for bound in bounds for n in walk(bound)):
                    f_reason = 'sizeof in allocator bound'
                elif cname in {'ALLOC', 'ZALLOC', 'RB_ALLOC', 'RB_ZALLOC'}:
                    f_reason = 'typed single-object Ruby allocator'
            if cname in RELEASE and args:
                pointer = compact(text(unparen(args[0]), data))
                block = enclosing_block(node)
                previous = [(a, target, size, cn) for a, target, size, cn in allocations
                            if cn in ALLOC and norm(target) == norm(pointer) and a.end_byte < node.start_byte
                            and enclosing_block(a) == block]
                if previous:
                    a = max(previous, key=lambda x: x[0].start_byte)[0]
                    changed = any(a.end_byte < w.start_byte < node.start_byte and norm(left) == norm(pointer)
                                  for w, left, right in writes)
                    escaped = any(a.end_byte < w.start_byte < node.start_byte and
                                  ('->' in left or '.' in left) and norm(right) == norm(pointer)
                                  for w, left, right in writes)
                    if not changed and not escaped and re.fullmatch(r'\w+', pointer):
                        f_reason = 'free of pointer allocated in this lexical block without field assignment'
            if f_reason:
                labels, evidence = ['F'], [f_reason]
            else:
                if cname in COPY | {'memset'} and len(args) > 2:
                    dest = compact(text(unparen(args[0]), data))
                    capacity = capacities.get(dest)
                    if capacity and capacity[2] < node.start_byte and norm(capacity[0]) != norm(text(args[2], data)):
                        labels.append('A')
                        evidence.append(f'local destination {dest} capacity {capacity[0]}; length {compact(text(args[2], data))}')
                if node.start_byte in pairs:
                    labels.append('B')
                    evidence.extend(pairs[node.start_byte])
                if fi is not None and fi >= 0 and len(args) > fi and not literal(args[fi]):
                    labels.append('C')
                    evidence.append(f'format argument {fi + 1} is not a string literal')
                if cname in RELEASE | RESIZE and args:
                    ptr = unparen(args[0])
                    pointer = compact(text(ptr, data))
                    if ptr and (ptr.type == 'field_expression' or pointer in parameters):
                        labels.append('D')
                        evidence.append('pointer is a field or enclosing-function parameter')
                    elif ptr and ptr.type == 'call_expression' and callee(ptr, data) not in ALLOC | RESIZE:
                        labels.append('D')
                        evidence.append('pointer is returned by a nonallocator call')
                    else:
                        prior = [(a, target, cn) for a, target, cn in origins
                                 if norm(target) == norm(pointer) and a.end_byte < node.start_byte]
                        if prior:
                            a, target, cn = max(prior, key=lambda x: x[0].start_byte)
                            later_write = any(a.end_byte < w.start_byte < node.start_byte and norm(left) == norm(pointer)
                                              for w, left, right in writes)
                            later_alloc = any(a.end_byte < a2.start_byte < node.start_byte and norm(t2) == norm(pointer)
                                              for a2, t2, s2, c2 in allocations)
                            if not later_write and not later_alloc:
                                labels.append('D')
                                evidence.append(f'pointer assigned from nonallocator {cn or "indirect call"} at line {a.start_point.row + 1}')
                if store_index is not None and not bounds_compared(node, store_index, data):
                    labels.append('E')
                    evidence.append('no index/length comparison on store line or immediately preceding condition')
            candidates.append(dict(line=node.start_point.row + 1, byte=node.start_byte,
                                   function=name, callee_or_store=cname,
                                   argument_snippet=snippet[:300], labels=sorted(set(labels)),
                                   evidence=evidence, arithmetic_copy_pair=node.start_byte in pairs,
                                   parser_recovered=fn.has_error or node.has_error))
    outside = collections.Counter()
    for node in nodes:
        if (node.start_byte, node.type) in seen_nodes:
            continue
        if node.type == 'call_expression' and selected(callee(node, data)):
            outside['selected_calls_without_function'] += 1
    return candidates, diagnostics, dict(outside), lexical_gaps(data, nodes)

def native_scope(gem, path):
    parts = pathlib.PurePosixPath(path).parts
    if parts and parts[0] in {'test', 'tests', 'spec', 'examples', 'doc', 'docs', 'benchmark', 'benchmarks'}:
        return None
    if parts and parts[0] == 'ext' or path.startswith('src/ruby/ext/'):
        return 'extension tree'
    for prefix, reason in ASSOCIATED.get(gem, []):
        if path.startswith(prefix):
            if any(part in {'test', 'tests', 'testing', 'examples', 'benchmark', 'benchmarks', 'fuzz', 'fuzzer', 'fuzzers'} for part in parts):
                return None
            if re.search(r'(?:_test|_benchmark|_fuzzer)\.(?:c|cc|cpp|h)$', path):
                return None
            return reason
    return None

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', type=pathlib.Path, required=True)
    args = ap.parse_args()
    manifest = json.loads((args.out / 'fetch-manifest.json').read_text())
    variants, skipped, gems = collections.defaultdict(list), [], []
    for source in manifest:
        if source['status'] != 'fetched':
            continue
        directory = pathlib.Path(source['source_directory'])
        inventory = json.loads((directory / '_inventory.json').read_text())
        count, native_count = 0, 0
        for entry in inventory:
            path = entry['path']
            if pathlib.PurePosixPath(path).suffix not in NATIVE:
                if re.search(r'\.(?:tar\.(?:gz|bz2|xz)|tgz|zip)$', path):
                    skipped.append(dict(gem=source['gem'], version=source['locked_version'], file=path,
                                        reason='nested archive not expanded'))
                continue
            native_count += 1
            scope = native_scope(source['gem'], path)
            if not scope or entry['kind'] != 'file':
                skipped.append(dict(gem=source['gem'], version=source['locked_version'], file=path,
                                    reason='outside extension/associated source scope' if not scope else 'nonregular archive member'))
                continue
            data = (directory / path).read_bytes()
            digest = hashlib.sha256(data).hexdigest()
            variants[(source['gem'], source['version'], path, digest)].append(
                dict(locked_version=source['locked_version'], scope=scope, absolute_path=str(directory / path)))
            count += 1
        gems.append(dict(gem=source['gem'], version=source['version'], locked_version=source['locked_version'],
                         c_extension_files=count, native_files_in_package=native_count,
                         status='scanned' if count else 'no_in_scope_C_extension_files'))
    file_records, parse_records, gap_records, row_sites, f_tally, unknown_tally = [], [], [], collections.defaultdict(list), collections.Counter(), collections.Counter()
    sites_seen, raw_sites, outside_counts, parse_cache = 0, 0, collections.Counter(), {}
    label_counts = collections.Counter()
    for i, ((gem, version, path, digest), sources) in enumerate(sorted(variants.items()), 1):
        language = 'cpp' if pathlib.PurePosixPath(path).suffix in {'.cc', '.cpp'} else 'c'
        data = pathlib.Path(sources[0]['absolute_path']).read_bytes()
        key = (digest, language)
        if key not in parse_cache:
            parsed = analyze(data, language)
            # Some shipped .h files contain C++ syntax; keep the parse with fewer errors.
            if pathlib.PurePosixPath(path).suffix == '.h' and parsed[1]:
                alternate = analyze(data, 'cpp')
                if len(alternate[1]) < len(parsed[1]):
                    parsed, language = alternate, 'cpp'
            parse_cache[key] = (parsed, language)
        (sites, diagnostics, outside, gaps), language = parse_cache[key]
        outside_counts.update(outside)
        sites_seen += len(sites)
        raw_sites += len(sites) * len(sources)
        file_records.append(dict(gem=gem, version=version, file=path, sha256=digest, bytes=len(data),
                                 source_variants=';'.join(s['locked_version'] for s in sources),
                                 scope=sources[0]['scope'], parser=language, sites_seen=len(sites),
                                 parser_errors=len(diagnostics), lexical_candidates_unparsed=len(gaps), **outside))
        for d in diagnostics:
            parse_records.append(dict(gem=gem, version=version, file=path, sha256=digest, **d))
        for gap in gaps:
            gap_records.append(dict(gem=gem, version=version, file=path, sha256=digest, **gap))
        for site in sites:
            label_counts.update(site['labels'])
            if site['labels'] == ['F']:
                f_tally[(gem, site['callee_or_store'], site['evidence'][0])] += 1
            elif site['labels']:
                row_sites[(gem, path, site['line'])].append(dict(version=version, source_sha256=digest,
                    source_variants=[s['locked_version'] for s in sources], **site))
            else:
                unknown_tally[(gem, site['callee_or_store'])] += 1
        if i % 250 == 0:
            print(f'Parsed {i}/{len(variants)} distinct extension source files; {sites_seen} sites', flush=True)
    rows = []
    # A temporary local syntax index supplies predicates to the entry-argument tracer.
    with (args.out / '_local-syntax-index.jsonl').open('w') as f:
        for (gem, path, line), sites in sorted(row_sites.items()):
            labels = sorted({l for s in sites for l in s['labels']})
            row = dict(gem=gem, version=';'.join(sorted({s['version'] for s in sites})), file=path,
                       line=line, function=' | '.join(sorted({s['function'] for s in sites})),
                       callee_or_store=' | '.join(sorted({s['callee_or_store'] for s in sites})),
                       labels=';'.join(labels), argument_snippet=' | '.join(sorted({s['argument_snippet'] for s in sites})),
                       evidence=' | '.join(sorted({e for s in sites for e in s['evidence']})),
                       source_variants=';'.join(sorted({v for s in sites for v in s['source_variants']})),
                       source_sha256=';'.join(sorted({s['source_sha256'] for s in sites})), site_count=len(sites))
            rows.append(row)
            f.write(json.dumps(dict(gem=gem, file=path, line=line, labels=labels, sites=sites)) + '\n')
    write_csv(args.out / 'files-scanned.csv', file_records, ['gem', 'version', 'file', 'sha256', 'bytes',
              'source_variants', 'scope', 'parser', 'sites_seen', 'parser_errors', 'lexical_candidates_unparsed', 'selected_calls_without_function'])
    write_csv(args.out / 'parser-diagnostics.csv', parse_records,
              ['gem', 'version', 'file', 'sha256', 'line', 'end_line', 'kind', 'snippet'])
    write_csv(args.out / 'lexical-candidates-unparsed.csv', gap_records,
              ['gem', 'version', 'file', 'sha256', 'line', 'callee', 'reason', 'snippet'])
    write_csv(args.out / 'files-skipped.csv', skipped, ['gem', 'version', 'file', 'reason'])
    write_csv(args.out / 'gem-extension-inventory.csv', gems,
              ['gem', 'version', 'locked_version', 'c_extension_files', 'native_files_in_package', 'status'])
    locked = [r for r in manifest if not r.get('supplementary')]
    summary = json.loads((args.out / 'provenance.json').read_text())
    summary.update(locked_package_entries=len(locked), locked_gem_names=len({r['gem'] for r in locked}),
                   fetched_locked_entries=sum(r['status'] == 'fetched' for r in locked),
                   gems_not_fetched=[{k:r.get(k) for k in ('gem','locked_version','error')} for r in locked if r['status'] != 'fetched'],
                   supplementary_fetch_failures=[r['gem'] for r in manifest if r.get('supplementary') and r['status'] != 'fetched'],
                   gems_with_extensions=sorted({g['gem'] for g in gems if g['c_extension_files']}),
                   extension_gem_count=len({g['gem'] for g in gems if g['c_extension_files']}),
                   files_scanned=len(file_records), unique_gem_file_paths=len({(r['gem'],r['file']) for r in file_records}),
                   file_variant_instances=sum(len(v) for v in variants.values()),
                   sites_seen=sites_seen, site_variant_instances=raw_sites,
                   site_counts_by_label=dict(sorted(label_counts.items())),
                   working_set_rows=len(rows), working_set_sites=sum(len(v) for v in row_sites.values()),
                   working_set_rows_by_label={l:sum(l in r['labels'].split(';') for r in rows) for l in 'ABCDE'},
                   sites_labeled_F_only=sum(f_tally.values()), unclassified_sites=sum(unknown_tally.values()),
                   parser_diagnostics=len(parse_records), files_with_parser_diagnostics=sum(bool(r['parser_errors']) for r in file_records),
                   skipped_files=len(skipped), unresolved_context_counts=dict(outside_counts),
                   lexical_candidates_unparsed=len(gap_records),
                   lexical_gaps_by_reason=dict(collections.Counter(r['reason'] for r in gap_records)),
                   working_set_sites_in_recovered_functions=sum(s['parser_recovered'] for sites in row_sites.values() for s in sites),
                   parser_versions={p:importlib.metadata.version(p) for p in ('tree-sitter','tree-sitter-c','tree-sitter-cpp')})
    assert summary['working_set_sites'] + summary['sites_labeled_F_only'] + summary['unclassified_sites'] == sites_seen
    for obsolete in ['site_counts_by_label','working_set_rows','working_set_sites','working_set_rows_by_label',
                     'sites_labeled_F_only','unclassified_sites','working_set_sites_in_recovered_functions']:
        summary.pop(obsolete,None)
    (args.out / 'inventory-summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    (args.out / '_local-syntax-index.jsonl').unlink()
    print(json.dumps({k:v for k,v in summary.items() if k not in {'gems_with_extensions','parser_versions'}}, indent=2), flush=True)

if __name__ == '__main__':
    main()

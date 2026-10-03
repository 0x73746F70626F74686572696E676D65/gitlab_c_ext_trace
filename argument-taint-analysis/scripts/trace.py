#!/usr/bin/env python3
"""Deterministic inert interprocedural C argument-taint analysis.

All functions are summarized over symbolic formal arguments. A worklist solves
return, output-memory and sink summaries to a fixed point, including recursion.
There is no call-depth or per-root function budget. Unknown returns are never
invented. Branches are joined, so witnesses establish static may-data-flow.
"""
import argparse, bisect, collections, csv, hashlib, heapq, inspect, json, os, re, sys
from dataclasses import dataclass, field
from pathlib import Path
import tree_sitter, tree_sitter_c, tree_sitter_cpp
from index_cache import compact_offsets,load_index
from includes import include_graph,visible_headers

PARSERS = {'c': tree_sitter.Parser(tree_sitter.Language(tree_sitter_c.language())),
           'cpp': tree_sitter.Parser(tree_sitter.Language(tree_sitter_cpp.language()))}
REG = {'rb_define_method', 'rb_define_singleton_method', 'rb_define_module_function',
       'rb_define_private_method', 'rb_define_protected_method', 'rb_define_global_function'}
TOKEN = re.compile(r'//[^\n]*|/\*[\s\S]*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[A-Za-z_]\w*|\d+(?:\.\d+)?\w*|##|\.\.\.|->|::|<<=?|>>=?|[!=<>+*/%&|^-]=|&&|\|\||\+\+|--|[^\s]', re.M)
IDENT = re.compile(r'^[A-Za-z_]\w*$')
LITERALS = {'number_literal','char_literal','string_literal','concatenated_string','null','nullptr','true','false'}
CONSTANTS = {'NULL','Qnil','Qtrue','Qfalse','Qundef','true','false','nullptr'}
def package_key(p):
    return p['gem']+'@'+p['locked_version']+(':'+p['source_variant'] if p.get('source_variant') else '')
ACCESS = set(('RSTRING_PTR RSTRING_LEN RSTRING_END RSTRING_EMBED_LEN RARRAY_PTR RARRAY_CONST_PTR '
    'RARRAY_LEN RARRAY_LENINT RARRAY_AREF RBASIC RDATA RTYPEDDATA_DATA DATA_PTR '
    'StringValuePtr StringValueCStr rb_string_value_ptr rb_string_value_cstr '
    'rb_str_strlen rb_str_length rb_str_bytesize rb_ary_length rb_ary_entry rb_ary_aref '
    'rb_hash_aref rb_hash_lookup rb_hash_lookup2 rb_hash_size rb_sym2str rb_id2str '
    'rb_obj_as_string rb_str_to_str rb_check_string_type rb_check_array_type rb_check_hash_type '
    'rb_str_to_inum rb_str2inum rb_cstr_to_inum rb_num2long rb_num2ulong rb_num2ll rb_num2ull '
    'rb_num2int rb_num2uint rb_num2dbl rb_num2chr rb_fix2long rb_fix2int '
    'strlen strnlen wcslen wcsnlen memcmp strcmp strncmp strchr strrchr memchr '
    'ntohl ntohs htonl htons le16toh le32toh le64toh htobe16 htobe32 htobe64 '
    'bswap_16 bswap_32 bswap_64 __builtin_bswap16 __builtin_bswap32 __builtin_bswap64 '
    'likely unlikely LIKELY UNLIKELY RB_LIKELY RB_UNLIKELY RB_UNLIKELY_EXCEPTION '
    'abs labs llabs min max MIN MAX fmin fmax tolower toupper atoi atol atoll strtol strtoul '
    'strtoll strtoull strtod rb_to_int rb_to_float rb_float_value rb_Integer').split())
ACCESS |= {p+t for p in ('NUM2','FIX2') for t in ('INT','UINT','LONG','ULONG','LL','ULL','DBL','CHR','SHORT','USHORT','SIZET','SSIZET')}
ACCESS |= {'INT2FIX','UINT2FIX','LONG2FIX','ULONG2FIX','LL2FIX','ULL2FIX','SIZET2FIX','SSIZET2FIX','FIXNUM_P','RB_FIXNUM_P'}
ACCESS |= set('RTEST RB_TEST NIL_P RB_NIL_P TYPE BUILTIN_TYPE RB_TYPE_P RB_BUILTIN_TYPE_P SPECIAL_CONST_P RB_SPECIAL_CONST_P SYMBOL_P STATIC_SYM_P DYNAMIC_SYM_P RB_FLOAT_TYPE_P RB_INTEGER_TYPE_P RB_BIGNUM_TYPE_P RFLOAT_VALUE RBIGNUM_DIGITS RBIGNUM_LEN RHASH_SIZE RHASH_TBL'.split())
BOX = set('INT2NUM UINT2NUM LONG2NUM ULONG2NUM LL2NUM ULL2NUM DBL2NUM SIZET2NUM SSIZET2NUM OFFT2NUM PIDT2NUM TIMET2NUM rb_float_new rb_float_new_in_heap rb_ll2inum rb_ull2inum rb_int2inum rb_uint2inum rb_long2num rb_ulong2num'.split())
INTERN = {'rb_intern','rb_intern_const','rb_intern2','rb_intern3','rb_intern_str','rb_str_intern'}
COERCE = set('StringValue StringValuePtr StringValueCStr SafeStringValue ExportStringValue rb_obj_as_string rb_check_string_type rb_Array rb_String rb_Float rb_Integer rb_ary_to_ary rb_to_symbol rb_dbl2big'.split())
WRAP = {'Data_Wrap_Struct','TypedData_Wrap_Struct'}
CLASS_MEMORY = set('rb_define_class_under rb_define_module_under rb_define_module rb_singleton_class rb_define_class rb_define_class_id rb_define_class_id_under'.split())
CPP_COPY = set('copy copy_n copy_backward move move_backward uninitialized_copy uninitialized_move uninitialized_copy_n'.split())
CPP_FILL = set('fill fill_n uninitialized_fill uninitialized_fill_n'.split())
ALLOC = {'malloc':[0], 'calloc':[0,1], 'realloc':[0,1], 'reallocarray':[0,1,2],
    'alloca':[0], '_alloca':[0], 'aligned_alloc':[0,1], 'posix_memalign':[0,1,2],
    'valloc':[0], 'pvalloc':[0], 'strdup':[0], 'strndup':[0,1],
    'ALLOC_N':[1], 'ZALLOC_N':[1], 'ALLOCA_N':[1], 'ALLOCV':[1], 'ALLOCV_N':[2],
    'RB_ALLOC_N':[1], 'RB_ZALLOC_N':[1], 'RB_ALLOCA_N':[1], 'RB_ALLOCV':[1], 'RB_ALLOCV_N':[2],
    'REALLOC_N':[0,2], 'RB_REALLOC_N':[0,2], 'xmalloc':[0], 'xcalloc':[0,1], 'xrealloc':[0,1],
    'xmalloc2':[0,1], 'xrealloc2':[0,1,2], 'ruby_xmalloc':[0], 'ruby_xcalloc':[0,1],
    'ruby_xmalloc2':[0,1], 'ruby_xcalloc2':[0,1], 'ruby_xrealloc':[0,1], 'ruby_xrealloc2':[0,1,2],
    'ruby_xrealloc2_sized':[0,1,2,3], 'rb_alloc_tmp_buffer':[0,1], 'rb_alloc_tmp_buffer_with_count':[0,1,2],
    'OPENSSL_malloc':[0], 'OPENSSL_zalloc':[0], 'OPENSSL_realloc':[0,1],
    'CRYPTO_malloc':[0], 'CRYPTO_zalloc':[0], 'CRYPTO_realloc':[0,1],
    'mmap':[0,1], 'mremap':[0,1,2]}
FREE = set('free cfree xfree ruby_xfree ruby_sized_xfree OPENSSL_free CRYPTO_free munmap ALLOCV_END RB_ALLOCV_END rb_free_tmp_buffer'.split())
COPY = {'memcpy':(0,1,2), 'memmove':(0,1,2), 'mempcpy':(0,1,2), 'memccpy':(0,1,3),
    'bcopy':(1,0,2), 'strcpy':(0,1,None), 'stpcpy':(0,1,None), 'strcat':(0,1,None),
    'strncpy':(0,1,2), 'stpncpy':(0,1,2), 'strncat':(0,1,2), 'strlcpy':(0,1,2), 'strlcat':(0,1,2),
    'wmemcpy':(0,1,2), 'wmemmove':(0,1,2), 'wcscpy':(0,1,None), 'wcsncpy':(0,1,2),
    'MEMCPY':(0,1,3), 'MEMMOVE':(0,1,3), 'RB_MEMCPY':(0,1,3), 'RB_MEMMOVE':(0,1,3),
    'CopyMemory':(0,1,2), 'MoveMemory':(0,1,2), 'RtlCopyMemory':(0,1,2), 'RtlMoveMemory':(0,1,2)}
SET = {'memset':(0,1,2), 'explicit_memset':(0,1,2), 'bzero':(0,None,1),
    'explicit_bzero':(0,None,1), 'wmemset':(0,1,2), 'MEMZERO':(0,None,2), 'MEMFILL':(0,1,3),
    'ZeroMemory':(0,None,1), 'RtlZeroMemory':(0,None,1), 'rb_mem_clear':(0,None,1)}
FORMAT = {'sprintf':1,'vsprintf':1,'snprintf':2,'vsnprintf':2,'swprintf':2,'vswprintf':2,
          'asprintf':1,'vasprintf':1,'rb_sprintf':0,'rb_vsprintf':0,'rb_enc_sprintf':1,
          'rb_str_catf':1,'rb_str_vcatf':1}
READ = {name:[(0,'source'),(1,'source'),(2,'length')] for name in
    ('memcmp','bcmp','wmemcmp','strncmp','wcsncmp','strncasecmp','timingsafe_bcmp','CRYPTO_memcmp')}
READ.update({name:[(0,'source'),(1,'source')] for name in
    ('strcmp','wcscmp','strcasecmp','strstr','strcasestr','wcsstr','strpbrk','strspn','strcspn')})
READ.update({name:[(0,'source')] for name in ('strlen','wcslen')})
READ.update({name:[(0,'source'),(1,'length')] for name in ('strnlen','wcsnlen')})
READ.update({name:[(0,'source'),(1,'value'),(2,'length')] for name in ('memchr','memrchr')})
READ.update({name:[(0,'source'),(1,'value')] for name in ('rawmemchr','strchr','strrchr','wcschr','wcsrchr')})
READ_POINTERS={'memchr','memrchr','rawmemchr','strchr','strrchr','wcschr','wcsrchr','strstr','strcasestr','wcsstr','strpbrk'}
RUBY_MEM = re.compile(r'^rb_(?:(?:str|utf8_str|usascii_str|enc_str|external_str|locale_str|ary|hash|obj|class|module|struct|regexp|reg|bignum|big|data|imemo|rational|complex|sym|intern|float|integer|time|typeddata)\w*(?:new|alloc|resize|expand|cat|append|concat|reserve|dup|plus|times|push|store|set)\w*|str_modify|str_free|str_export|str_export_to_enc|str_encode|str_substr|str_subseq|data_object_wrap|data_typed_object_wrap|data_typed_object_zalloc)$')
PROTECTED = set(ALLOC)|set(COPY)|set(SET)|FREE|BOX|ACCESS|COERCE|WRAP|CLASS_MEMORY|set(FORMAT)|REG|{
    'rb_define_alloc_func','rb_define_alias','StringValue','SafeStringValue','ExportStringValue',
    'Data_Get_Struct','TypedData_Get_Struct','Data_Make_Struct','TypedData_Make_Struct',
    'rb_scan_args','rb_scan_args_kw','rb_get_kwargs','rb_funcall','rb_funcallv','rb_funcallv_kw',
    'rb_ensure','rb_protect','rb_rescue','rb_rescue2','rb_block_call','rb_iterate',
    'rb_thread_call_without_gvl','rb_thread_call_without_gvl2','rb_thread_call_with_gvl',
    'RB_OBJ_WRITE','RB_OBJ_WRITTEN','RB_GC_GUARD','RUBY_METHOD_FUNC'}

def walk(node):
    stack=[node]
    while stack:
        n=stack.pop(); yield n; stack.extend(reversed(n.named_children))
def txt(n,b): return b[n.start_byte:n.end_byte].decode('utf8',errors='replace') if n else ''
def decl(n,b):
    while n:
        if n.type in {'identifier','field_identifier','qualified_identifier','operator_name'}: return txt(n,b)
        child=n.child_by_field_name('declarator')
        if child is None and n.type=='parenthesized_declarator' and n.named_children: child=n.named_children[0]
        n=child
    return ''
def args(n):
    a=n.child_by_field_name('arguments'); return a.named_children if a else []
def callee(n,b):
    name=txt(n.child_by_field_name('function'),b).removeprefix('::')
    # Keep C++ algorithms qualified: an unrelated C helper named copy or move
    # must be traversed rather than mistaken for a standard memory algorithm.
    return name if name.startswith('std::') and name[5:] in CPP_COPY|CPP_FILL else name.removeprefix('std::')
def literal(n,b):
    s=txt(n,b)
    strings=re.findall(r'"((?:\\.|[^"\\])*)"',s)
    if strings: return ''.join(strings)
    try: return int(re.sub(r'[uUlL]+$','',re.sub(r'\s+','',s)),0)
    except ValueError: return None

def lexical_functions(source):
    """Recover C function boundaries obscured by file-level parser recovery.

    Balanced tokens distinguish definitions from calls, declarations and
    initializers. Each candidate is reparsed independently; no flow is inferred
    from a regular expression. C has no ordinary nested function definitions,
    but retained preprocessor alternatives can obscure the apparent brace level.
    """
    tokens=list(TOKEN.finditer(source)); positions=[]; byte=0; previous=0
    for token in tokens:
        byte+=len(source[previous:token.start()].encode()); start=byte
        byte+=len(token[0].encode()); positions.append((start,byte)); previous=token.end()
    pairs={}; stack=[]; boundary=-1; candidates=[]
    controls={'if','for','while','switch','catch','__attribute__','__declspec'}
    for j,m in enumerate(tokens):
        token=m[0]
        if token in {'(', '{','['}: stack.append((token,j))
        elif token in {')','}',']'}:
            expected={')':'(', '}':'{', ']':'['}[token]
            if stack and stack[-1][0]==expected:
                _,opening=stack.pop(); pairs[j]=opening; pairs[opening]=j
        if token=='{' and j and tokens[j-1][0]==')':
            opening=pairs.get(j-1)
            if opening is not None and opening and IDENT.fullmatch(tokens[opening-1][0]):
                name=tokens[opening-1][0]; prefix=[t[0] for t in tokens[boundary+1:opening-1]]
                if name not in controls and prefix and '=' not in prefix and not any(t in {'return','if','for','while','else'} for t in prefix):
                    candidates.append((boundary+1,opening-1,opening,j))
        if token in {';', '{','}'}: boundary=j
    for start,name,parameters,body in candidates:
        end=pairs.get(body)
        if end is not None: yield tokens,positions,start,name,parameters,body,end

class Macros:
    def __init__(self): self.defs=collections.defaultdict(list); self.issues=set(); self.expansions=0
    def add_file(self, package, file, source):
        pattern=re.compile(r'^[ \t]*#\s*define\s+([A-Za-z_]\w*)(\([^\n]*?\))?[ \t]*(.*)$')
        lines=source.splitlines(); i=0
        while i<len(lines):
            start=i; logical=lines[i]; i+=1
            while logical.endswith('\\') and i<len(lines): logical=logical[:-1]+' '+lines[i]; i+=1
            m=pattern.match(logical)
            if not m: continue
            ps=None if m[2] is None else tuple(p.strip() for p in m[2][1:-1].split(',') if p.strip())
            body=m[3].replace('\\\n',' ')
            toks=[x[0] for x in TOKEN.finditer(body) if not x[0].startswith(('//','/*'))]
            self.defs[(package,m[1])].append((file,ps,tuple(toks),start+1))
    def get(self,package,file,name):
        ds=self.defs.get((package,name),[]); local=[d for d in ds if d[0]==file]; ds=local or ds
        unique={(d[1],d[2]) for d in ds}
        if len(unique)==1: return next(iter(unique))
        if ds: self.issues.add((package,file,name,'conditional/ambiguous macro definitions'))
        return None
    def expand(self,package,file,tokens,active=()):
        out=[]; i=0
        while i<len(tokens):
            tok,line=tokens[i]; definition=None
            if IDENT.fullmatch(tok) and tok not in PROTECTED and not RUBY_MEM.fullmatch(tok) and tok not in active:
                definition=self.get(package,file,tok)
            if definition is None: out.append(tokens[i]); i+=1; continue
            params,body=definition; actual=[]; end=i+1
            if params is not None:
                if end>=len(tokens) or tokens[end][0]!='(': out.append(tokens[i]); i+=1; continue
                depth=1; current=[]; j=end+1
                while j<len(tokens) and depth:
                    t=tokens[j][0]
                    if t=='(': depth+=1
                    elif t==')': depth-=1
                    if not depth:
                        if current or params: actual.append(current)
                        break
                    if t==',' and depth==1: actual.append(current); current=[]
                    else: current.append(tokens[j])
                    j+=1
                if depth: out.append(tokens[i]); i+=1; continue
                end=j+1
                if params and params[-1] in {'...','__VA_ARGS__'}:
                    actual=actual[:len(params)-1]+[[x for k,a in enumerate(actual[len(params)-1:]) for x in (([(',',line)] if k else [])+a)]]
                if len(actual)!=len(params): out.append(tokens[i]); i+=1; continue
            substitutions=dict(zip(params or (),actual))
            if params and params[-1]=='...': substitutions['__VA_ARGS__']=substitutions.pop('...')
            replaced=[]; j=0
            while j<len(body):
                if body[j]=='#' and j+1<len(body) and body[j+1] in substitutions:
                    s=' '.join(t for t,_ in substitutions[body[j+1]])
                    replaced.append((json.dumps(s),line)); j+=2; continue
                t=body[j]; replaced.extend(substitutions.get(t,[(t,line)])); j+=1
            pasted=[]; j=0
            while j<len(replaced):
                if replaced[j][0]=='##' and pasted and j+1<len(replaced):
                    t,l=pasted.pop(); pasted.append((t+replaced[j+1][0],l)); j+=2
                else: pasted.append(replaced[j]); j+=1
            out.extend(self.expand(package,file,pasted,active+(tok,))); self.expansions+=1; i=end
        return out
    def source(self,package,file,source):
        # Conditional alternatives are retained. Directives themselves are syntax,
        # not calls; macro replacement never invokes a preprocessor or a build hook.
        lines=source.splitlines(keepends=True); masked=[]; continuation=False
        for s in lines:
            directive=continuation or bool(re.match(r'^[ \t]*#',s))
            continuation=directive and s.rstrip('\r\n').endswith('\\')
            masked.append('\n' if directive and s.endswith('\n') else '' if directive else s)
        source=''.join(masked)
        starts=[0]+[m.end() for m in re.finditer('\n',source)]
        tokens=[(m[0],bisect.bisect_right(starts,m.start())) for m in TOKEN.finditer(source) if not m[0].startswith(('//','/*'))]
        expanded=self.expand(package,file,tokens)
        pieces=[]; offsets=[]; offset=0
        for token,line in expanded:
            pieces.append(token+' '); offsets.append((offset,line)); offset+=len((token+' ').encode())
        return ''.join(pieces).encode(),offsets

def sink_model(name,n):
    name=re.sub(r'^__builtin_','',name); name=re.sub(r'^__(\w+)_chk$',r'\1',name)
    if name in ALLOC:
        reallocation={'realloc','reallocarray','xrealloc','xrealloc2','ruby_xrealloc','ruby_xrealloc2','ruby_xrealloc2_sized','REALLOC_N','RB_REALLOC_N','OPENSSL_realloc','CRYPTO_realloc','mremap'}
        roles={'posix_memalign':{0:'destination',1:'alignment'},'aligned_alloc':{0:'alignment'},'strdup':{0:'source'},'strndup':{0:'source',1:'length'},
            'mmap':{0:'address_hint'},'rb_alloc_tmp_buffer':{0:'destination'},
            'rb_alloc_tmp_buffer_with_count':{0:'destination',2:'count'}}.get(name,{})
        return 'allocation',[(i,roles.get(i,'pointer' if i==0 and name in reallocation else 'size')) for i in ALLOC[name] if i<n]
    if name in FREE: return 'release',[(i,'pointer' if i==0 else 'size') for i in range(n)]
    if name in READ: return 'memory_read',[(i,role) for i,role in READ[name] if i<n]
    if name in COPY:
        d,s,l=COPY[name]; return 'copy',[(i,role) for i,role in [(d,'destination'),(s,'source'),(l,'length')] if i is not None and i<n]
    if name in SET:
        d,v,l=SET[name]; return 'memory_set',[(i,role) for i,role in [(d,'destination'),(v,'value'),(l,'length')] if i is not None and i<n]
    if name in FORMAT:
        return 'format_buffer',[(i,'destination' if i==0 and not name.startswith('rb_') else 'size' if i==1 and name in {'snprintf','vsnprintf','swprintf','vswprintf'} else 'format' if i==FORMAT[name] else 'data') for i in range(n)]
    if name in BOX: return 'ruby_conversion',[(i,'value') for i in range(n)]
    if name in COERCE: return 'ruby_coercion',[(0,'value')] if n else []
    if name in WRAP|CLASS_MEMORY: return 'ruby_memory',[(i,'argument') for i in range(n)]
    if name.startswith('std::') and name[5:] in CPP_COPY|CPP_FILL:
        return 'copy' if name[5:] in CPP_COPY else 'memory_set',[(i,'operand') for i in range(n)]
    if name in INTERN: return 'ruby_memory',[(i,'argument') for i in range(n)]
    if RUBY_MEM.fullmatch(name): return 'ruby_memory',[(i,'argument') for i in range(n)]
    return None

@dataclass
class Value:
    deps: dict=field(default_factory=dict)
    refs: frozenset=field(default_factory=frozenset)
    funcs: frozenset=field(default_factory=frozenset)
    const: object=None
    def signature(self): return (self.deps,self.refs,self.funcs,self.const)

def merge(*values):
    deps={}; refs=set(); funcs=set(); const=None
    seen=set()
    for v in values:
        if id(v) in seen: continue
        seen.add(id(v))
        refs.update(v.refs); funcs.update(v.funcs)
        for atom,path in v.deps.items():
            if atom not in deps or (len(path),path)<(len(deps[atom]),deps[atom]): deps[atom]=path
    if values and all(v.const==values[0].const for v in values): const=values[0].const
    return Value(deps,frozenset(refs),frozenset(funcs),const)

def root_ref(ref): return ref[:4] if ref and ref[0]=='global' else ref[:2]
def projected_ref(ref,selector): return root_ref(ref)+(('projection',selector),)
def implicit_selector(ref):
    root=root_ref(ref)
    return ref[len(root)][1] if len(ref)>len(root) and isinstance(ref[len(root)],tuple) and ref[len(root)][0] in {'projection','value_projection','address_projection'} else None

class Index:
    def __init__(self):
        self.functions={}; self.names=collections.defaultdict(list); self.roots=[]; self.aliases=[]
        self.files=[]; self.events={}; self.event_keys={}; self.global_methods={}; self.macro=Macros()
        self.package_dependencies={}; self.global_tables={};self.global_visibility={};self.callback_sources={};self.global_table_index={}
        self.includes=None;self.include_cache={};self.include_boundaries=[]
    def source_includes(self,manifest):
        self.includes,self.include_boundaries=include_graph(manifest,package_key);self.include_cache={}
    def event(self,fn,line,kind,expression,extra=None):
        key=(fn,line,kind,expression,json.dumps(extra,sort_keys=True))
        if key not in self.event_keys:
            eid=hashlib.sha256(json.dumps(key).encode()).hexdigest()
            self.event_keys[key]=eid
            self.events[eid]=dict(function=fn,line=line,kind=kind,expression=expression,**(extra or {}))
        return self.event_keys[key]
    def resolve(self,package,file,name):
        name=name.removeprefix('&').removeprefix('::')
        if (package,name) not in self.names and re.search(r'[()\s]',name):
            # C method registration casts carry a symbol, not a callable cast.
            # Only a unique identifier already indexed in this package is used.
            candidates=sorted({n for n in re.findall(r'[A-Za-z_]\w*',name) if (package,n) in self.names})
            if len(candidates)==1 and not re.search(r'->|\.',name.replace('...','')): name=candidates[0]
        ds=self.names.get((package,name),[])
        if not ds:
            linked=[f for dependency in self.package_dependencies.get(package,[]) for f in self.names.get((dependency,name),[])]
            ds=[f for f in linked if not self.functions[f]['static']]
        if not ds and '::' in name: ds=self.names.get((package,name.split('::')[-1]),[])
        local=[f for f in ds if self.functions[f]['file']==file]
        if local: return sorted(local)
        headers=visible_headers(self.includes,package,file,self.include_cache) if self.includes is not None else None
        visible=[f for f in ds if not self.functions[f]['static'] or
                 self.functions[f]['file'].endswith(('.h','.hpp','.hh','.inc','.inl','.in')) and
                 (headers is None or self.functions[f]['file'] in headers)]
        # Identical inline header implementations can appear repeatedly. An
        # unresolved same-name collision is recorded rather than arbitrarily bound.
        signatures={self.functions[f]['source'] for f in visible}
        return sorted(visible)[:1] if len(signatures)==1 else sorted(visible) if len(visible)==1 or visible and all(self.functions[f]['parser']=='c' for f in visible) else []

    def function_symbols(self,package,file,name):
        normalized=re.sub(r'^__builtin_','',name);normalized=re.sub(r'^__(\w+)_chk$',r'\1',normalized)
        if sink_model(normalized,100):return ['@memory:'+normalized]
        return self.resolve(package,file,name)

    def global_bindings(self,package,file,name):
        local=(package,file,name)
        if local in self.global_tables:return [(file,self.global_tables[local])]
        headers=visible_headers(self.includes,package,file,self.include_cache) if self.includes is not None else None
        return [(f,fields) for f,fields in self.global_table_index.get((package,name),[]) if
            (not self.global_visibility.get((package,f,name),False) or f.endswith(('.h','.hpp','.hh','.inc','.inl','.in')) and
             (headers is None or f in headers))]

    def rebuild_global_bindings(self):
        self.global_table_index=collections.defaultdict(list)
        for (package,file,name),fields in sorted(self.global_tables.items()):self.global_table_index[(package,name)].append((file,fields))
    def build(self,manifest,selected=None):
        files=[]
        for package in manifest:
            if selected and package['gem'] not in selected: continue
            key=package_key(package)
            for r in package['source_files']:
                path=Path(package['directory'])/r['file']
                b=path.read_bytes(); assert hashlib.sha256(b).hexdigest()==r['sha256']
                source=b.decode('utf8',errors='replace')
                files.append((key,package,r,path,source)); self.macro.add_file(key,r['file'],source)
        for count,(key,package,r,path,source) in enumerate(files,1):
            header_code=TOKEN.sub(lambda m:' ' if m[0].startswith(('//','/*','"',"'")) else m[0],source[:12000])
            language='cpp' if path.suffix in {'.cc','.cpp','.cxx','.hpp','.hh','.mm'} or path.suffix in {'.h','.inc','.inl'} and re.search(r'\b(namespace|template|class|constexpr)\b',header_code) else 'c'
            expanded,offsets=self.macro.source(key,r['file'],source)
            tree=PARSERS[language].parse(expanded); nodes=list(walk(tree.root_node))
            offkeys=[o for o,_ in offsets]
            def line(n): return offsets[max(0,bisect.bisect_right(offkeys,n.start_byte)-1)][1] if offsets else 1
            definitions=[]
            for n in nodes:
                if n.type!='function_definition': continue
                name=decl(n.child_by_field_name('declarator'),expanded)
                if not name: continue
                fd=n.child_by_field_name('declarator')
                while fd and fd.type!='function_declarator': fd=fd.child_by_field_name('declarator')
                ps=fd.child_by_field_name('parameters') if fd else None
                parms=[decl(p.child_by_field_name('declarator'),expanded) for p in ps.named_children if p.type in {'parameter_declaration','optional_parameter_declaration'}] if ps else []
                fid=f'{key}:{r["file"]}:{line(n)}:{name}'
                if fid in self.functions:
                    fid+=':'+str(n.start_byte)
                lo=n.start_byte; hi=n.end_byte
                mapping=compact_offsets((o-lo,l) for o,l in offsets[bisect.bisect_left(offkeys,lo):bisect.bisect_left(offkeys,hi)])
                function=dict(id=fid,package=key,gem=package['gem'],version=package['version'],
                    locked_version=package['locked_version'],file=r['file'],path=str(path),source_sha256=r['sha256'],
                    line=line(n),name=name,parameters=parms,parser=language,source=txt(n,expanded),
                    static=bool(re.search(r'\bstatic\b',txt(n,expanded).split('{',1)[0])),
                    parse_error=n.has_error,offsets=mapping)
                self.functions[fid]=function; self.names[(key,name)].append(fid); definitions.append((n.start_byte,n.end_byte,fid))
            recovered=0
            if language=='c' and tree.root_node.has_error:
                for tokens,positions,start,ni,pi,body,end in lexical_functions(expanded.decode('utf8',errors='replace')):
                    name=tokens[ni][0]; lo,hi=positions[start][0],positions[end][1]; body_start=positions[body][0]
                    if any(self.functions[f]['name']==name and a<=body_start<z for a,z,f in definitions): continue
                    standalone=expanded[lo:hi]; parsed=PARSERS['c'].parse(standalone)
                    n=next((n for n in walk(parsed.root_node) if n.type=='function_definition' and decl(n.child_by_field_name('declarator'),standalone)==name),None)
                    normalized=False; synthetic_mapping=[]
                    if not n and ni>start and (IDENT.fullmatch(tokens[ni-1][0]) or tokens[ni-1][0]=='*'):
                        # A broken preceding declaration can swallow a valid
                        # definition. Preserve its complete parameters/body and
                        # replace only the return declaration for independent IR.
                        parameter_start=positions[pi][0]; prefix=('VALUE '+name+' ').encode()
                        standalone=prefix+expanded[parameter_start:hi]; parsed=PARSERS['c'].parse(standalone)
                        n=next((n for n in walk(parsed.root_node) if n.type=='function_definition' and decl(n.child_by_field_name('declarator'),standalone)==name),None)
                        ln=offsets[max(0,bisect.bisect_right(offkeys,positions[ni][0])-1)][1]
                        synthetic_mapping=[(0,ln)]+[(o-parameter_start+len(prefix),l) for o,l in offsets[bisect.bisect_left(offkeys,parameter_start):bisect.bisect_left(offkeys,hi)]]
                        normalized=True
                    if not n: continue
                    fd=n.child_by_field_name('declarator')
                    while fd and fd.type!='function_declarator': fd=fd.child_by_field_name('declarator')
                    ps=fd.child_by_field_name('parameters') if fd else None
                    parms=[decl(p.child_by_field_name('declarator'),standalone) for p in ps.named_children if p.type in {'parameter_declaration','optional_parameter_declaration'}] if ps else []
                    begin=positions[ni][0] if normalized else lo+n.start_byte; finish=hi if normalized else lo+n.end_byte
                    ln=offsets[max(0,bisect.bisect_right(offkeys,begin)-1)][1]
                    fid=f'{key}:{r["file"]}:{ln}:{name}'
                    if fid in self.functions: fid+=':'+str(begin)
                    mapping=synthetic_mapping if normalized else [(o-begin,l) for o,l in offsets[bisect.bisect_left(offkeys,begin):bisect.bisect_left(offkeys,finish)]]
                    function=dict(id=fid,package=key,gem=package['gem'],version=package['version'],locked_version=package['locked_version'],
                        file=r['file'],path=str(path),source_sha256=r['sha256'],line=ln,name=name,parameters=parms,parser='c',
                        source=txt(n,standalone),static=bool(re.search(r'\bstatic\b',expanded[lo:positions[pi][0]].decode('utf8',errors='replace'))),
                        parse_error=n.has_error,offsets=compact_offsets(mapping),parser_recovery='balanced-token independent function parse')
                    self.functions[fid]=function; self.names[(key,name)].append(fid); definitions.append((begin,finish,fid)); recovered+=1
            namespace={}; method_ids={}
            for n in nodes:
                if n.type!='call_expression': continue
                name=callee(n,expanded); aa=args(n)
                if name in {'rb_intern','rb_intern_const'} and aa:
                    p=n.parent; target=decl(p.child_by_field_name('declarator'),expanded) if p and p.type=='init_declarator' else txt(p.child_by_field_name('left'),expanded) if p and p.type=='assignment_expression' else ''
                    if target and isinstance(literal(aa[0],expanded),str): method_ids[target]=literal(aa[0],expanded)
                if name.startswith(('rb_define_class','rb_define_module')) and aa:
                    under=name.endswith('_under'); i=1 if under else 0
                    if i>=len(aa): continue
                    label=literal(aa[i],expanded)
                    if not isinstance(label,str): continue
                    if under: label=namespace.get(txt(aa[0],expanded),txt(aa[0],expanded))+'::'+label
                    p=n.parent; target=decl(p.child_by_field_name('declarator'),expanded) if p and p.type=='init_declarator' else txt(p.child_by_field_name('left'),expanded) if p and p.type=='assignment_expression' else ''
                    if target: namespace[target]=label
                if name in REG and len(aa)>=(3 if name=='rb_define_global_function' else 4):
                    shift=-1 if name=='rb_define_global_function' else 0
                    method=literal(aa[1+shift],expanded); arity=literal(aa[3+shift],expanded)
                    target=txt(aa[2+shift],expanded)
                    target=re.sub(r'RUBY_METHOD_FUNC\s*\(\s*(\w+)\s*\)',r'\1',target).strip(' ()&')
                    if not isinstance(method,str) or not isinstance(arity,int): continue
                    receiver='Kernel' if shift else txt(aa[0],expanded)
                    self.roots.append(dict(gem=package['gem'],version=package['version'],locked_version=package['locked_version'],
                        package=key,method=method,receiver=namespace.get(receiver,receiver),receiver_expression=receiver,
                        c_function=target,arity=arity,registration=name,file=r['file'],line=line(n)))
                if name=='rb_define_alias' and len(aa)>=3:
                    self.aliases.append(dict(package=key,file=r['file'],line=line(n),receiver_expression=txt(aa[0],expanded),
                        new=literal(aa[1],expanded),old=literal(aa[2],expanded)))
            self.global_methods[key]=dict(self.global_methods.get(key,{}),**method_ids)
            self.files.append(dict(package=key,file=r['file'],source_sha256=r['sha256'],bytes=r['bytes'],
                                   parser=language,parse_error=tree.root_node.has_error,functions=len(definitions),recovered_functions=recovered))
            if count%250==0: print(f'Indexed {count}/{len(files)} files; {len(self.functions)} functions; {len(self.roots)} roots',flush=True)
        # Resolve after all translation units have been indexed.
        for root in self.roots:
            root['targets']=self.resolve(root['package'],root['file'],root['c_function'])
            root['entry_id']=f'{root["package"]}:{root["file"]}:{root["line"]}:{root["receiver_expression"]}:{root["method"]}'
        extra=[]
        for alias in self.aliases:
            for root in self.roots:
                if (root['package'],root['file'],root['receiver_expression'],root['method'])!=(alias['package'],alias['file'],alias['receiver_expression'],alias['old']): continue
                r=dict(root,method=alias['new'],line=alias['line'],registration='rb_define_alias')
                r['entry_id']=f'{r["package"]}:{r["file"]}:{r["line"]}:{r["receiver_expression"]}:{r["method"]}'
                extra.append(r)
        self.roots.extend(extra)

    def link_packages(self,repo,manifest):
        """Only explicit locked gem dependencies permit a cross-package C edge."""
        dependencies=collections.defaultdict(set); current=None
        for line in (repo/'static-catalog/Gemfile.lock').read_text().splitlines():
            m=re.match(r'^    (\S+) \(',line)
            if m: current=m[1]
            m=re.match(r'^      (\S+)(?: |$)',line)
            if m and current: dependencies[current].add(m[1])
        packages=collections.defaultdict(list); source={package_key(p):p for p in manifest}
        for p in manifest: packages[p['gem']].append(p)
        locked={r['gem']:r['version'] for r in csv.DictReader((repo/'static-catalog/locked-gems.csv').open())}
        for package in sorted({f['package'] for f in self.files}):
            current=source[package]; links=[]
            for dep in sorted(dependencies[current['gem']]):
                candidates=[p for p in packages[dep] if p['version']==locked.get(dep)]
                if not candidates and len({p['version'] for p in packages[dep]})==1: candidates=packages[dep]
                same=[p for p in candidates if bool(p.get('source_variant'))==bool(current.get('source_variant'))]
                links.extend(package_key(p) for p in (same or candidates))
            self.package_dependencies[package]=sorted(set(links))

    def callback_tables(self,manifest):
        """Recover concrete C callback tables and field order from inert ASTs."""
        types={}; initializers=[];scanned=0;total=sum(len(p['source_files']) for p in manifest)
        for package in manifest:
            key=package_key(package)
            if not any(f['package']==key for f in self.files): continue
            for record in package['source_files']:
                scanned+=1
                if scanned%2000==0:print('Callback source scan:',scanned,'/',total,flush=True)
                path=Path(package['directory'])/record['file']; b=path.read_bytes()
                if b'(*' not in b and not re.search(rb'=\s*(?:\{|\(?&?[A-Za-z_])',b): continue
                language='cpp' if path.suffix in {'.cpp','.cc','.cxx','.hpp','.hh'} else 'c'
                tree=PARSERS[language].parse(b)
                for n in walk(tree.root_node):
                    if n.type=='struct_specifier':
                        body=n.child_by_field_name('body')
                        if not body: continue
                        label=txt(n.child_by_field_name('name'),b)
                        if n.parent and n.parent.type=='type_definition': label=decl(n.parent.child_by_field_name('declarator'),b) or label
                        fields=[]
                        for field in body.named_children:
                            d=field.child_by_field_name('declarator')
                            if d: fields.append(decl(d,b))
                        if label and fields: types[(key,label)]=fields
                    if n.type!='init_declarator': continue
                    value=n.child_by_field_name('value')
                    if not value: continue
                    ancestor=n.parent
                    while ancestor and ancestor.type not in {'function_definition','translation_unit'}: ancestor=ancestor.parent
                    if not ancestor or ancestor.type=='function_definition': continue
                    name=decl(n.child_by_field_name('declarator'),b)
                    type_=txt(n.parent.child_by_field_name('type'),b).removeprefix('struct ')
                    binding=(key,record['file'],name)
                    static=bool(re.search(r'\bstatic\b',txt(n.parent,b).split('=',1)[0]))
                    origin=dict(line=n.start_point.row+1,source_sha256=record['sha256'],expression=txt(n,b))
                    if value.type!='initializer_list':
                        if value.type not in {'identifier','parenthesized_expression','pointer_expression','cast_expression'}:continue
                        nodes=list(walk(value))
                        if any(x.type in {'call_expression','binary_expression','subscript_expression','field_expression'} for x in nodes):continue
                        names=[txt(x,b) for x in nodes if x.type=='identifier']
                        targets=sorted({f for s in names for f in self.function_symbols(key,record['file'],s)})
                        if targets:
                            self.global_tables[binding]={'*':targets};self.global_visibility[binding]=static;self.callback_sources[binding]=origin
                        continue
                    entries=[]
                    for position,child in enumerate(value.named_children):
                        designator=child.child_by_field_name('designator') if child.type=='initializer_pair' else None
                        rhs=child.child_by_field_name('value') if child.type=='initializer_pair' else child
                        field_name=txt(designator,b).lstrip('.') if designator else None
                        names=[txt(x,b) for x in walk(rhs) if x.type=='identifier']
                        targets=sorted({f for s in names for f in self.function_symbols(key,record['file'],s)})
                        if targets: entries.append((position,field_name,targets))
                    if entries: initializers.append((key,record['file'],name,type_,entries,static,origin))
        for package,file,name,type_,entries,static,origin in initializers:
            fields=types.get((package,type_),[])
            if not fields:
                alternatives=[types.get((p,type_),[]) for p in self.package_dependencies.get(package,[]) if types.get((p,type_))]
                if len(alternatives)==1: fields=alternatives[0]
            binding=(package,file,name)
            self.global_tables[binding]={field_name or (fields[position] if position<len(fields) else str(position)):targets
                for position,field_name,targets in entries}
            self.global_visibility[binding]=static;self.callback_sources[binding]=origin
        self.rebuild_global_bindings()

    def cached_callback_tables(self,manifest,index_path,manifest_path):
        if not index_path:self.callback_tables(manifest);return
        def digest(path):
            h=hashlib.sha256()
            with path.open('rb') as f:
                for block in iter(lambda:f.read(4*1024*1024),b''):h.update(block)
            return h.hexdigest()
        identity=dict(index=digest(index_path),manifest=digest(manifest_path),
            parser_requirements=digest(Path(__file__).with_name('requirements.txt')),
            implementation=digest(Path(__file__)),
            dependencies=self.package_dependencies)
        key=hashlib.sha256(json.dumps(identity,sort_keys=True).encode()).hexdigest()
        cache=index_path.with_suffix('.callbacks.jsonl')
        if cache.exists():
            with cache.open() as f:
                metadata=json.loads(next(f))
                if metadata.get('cache_key')==key:
                    for line in f:
                        r=json.loads(line);binding=(r['package'],r['file'],r['name']);self.global_tables[binding]=r['fields']
                        self.global_visibility[binding]=r['static'];self.callback_sources[binding]=r['origin']
                    self.rebuild_global_bindings()
                    print('Loaded concrete callback tables:',len(self.global_tables),flush=True);return
        self.callback_tables(manifest)
        temporary=cache.with_suffix('.'+str(os.getpid())+'.tmp')
        with temporary.open('w') as f:
            f.write(json.dumps(dict(cache_key=key))+'\n')
            for (package,file,name),fields in sorted(self.global_tables.items()):
                binding=(package,file,name)
                f.write(json.dumps(dict(package=package,file=file,name=name,fields=fields,static=self.global_visibility[binding],origin=self.callback_sources[binding]),sort_keys=True)+'\n')
        temporary.replace(cache)
        print('Saved concrete callback tables:',len(self.global_tables),flush=True)

    def saved_roots(self,repo,native_data):
        """Reconcile all saved registrations; do not inherit graph-only verdicts."""
        if not native_data: return
        def load(name,key):
            return {r[key]:r for l in (native_data/name).open() if (r:=json.loads(l))}
        gems=load('gems.jsonl','gem_id'); files=load('c_files.jsonl','file_id'); funcs=load('c_functions.jsonl','function_id')
        owners=load('ruby_native_registrations.jsonl','registration_id')
        bindings=collections.defaultdict(list);api_bindings=collections.defaultdict(list)
        norm=lambda s:re.sub(r'\s+','',s or '')
        for r in self.roots:
            bindings[(r['gem'],r['version'],norm(r['c_function']),r['method'],norm(r['receiver_expression']))].append(r)
            api_bindings[(r['gem'],r['version'],r['method'],norm(r['receiver_expression']),r['registration'],str(r['arity']))].append(r)
        ledger=[]
        for l in (native_data/'c_registrations.jsonl').open():
            reg=json.loads(l); gem=gems[reg['gem_id']]; owner=owners.get(reg['registration_id'],{})
            name=owner.get('method') or reg.get('ruby_name'); fn=funcs.get(reg.get('c_function_id'),{}).get('name') or reg.get('c_function_expression','')
            receiver='Kernel' if reg['registration_api']=='rb_define_global_function' else reg.get('receiver_expression',''); arity=reg.get('arity','')
            key=(gem['name'],gem['version'],norm(fn),name,norm(receiver)); matches=bindings.get(key,[])
            record=dict(registration_id=reg['registration_id'],gem=gem['name'],version=gem['version'],method=name,c_function=fn,registration=reg['registration_api'])
            record['binding_match']='c_symbol_and_api' if matches else None
            if not matches and reg['registration_api'] in REG and name:
                matches=api_bindings.get((gem['name'],gem['version'],name,norm(receiver),reg['registration_api'],str(arity)),[])
                if matches:record['binding_match']='ruby_api_and_argument_abi'
            if not matches and reg['registration_api'] in REG and name:
                try: n=int(arity)
                except (TypeError,ValueError): n=None
                package=gem['name']+'@'+gem['version']; oldpath=files.get(reg.get('file_id'),{}).get('path','')
                candidates=[f for f in self.files if f['package']==package and oldpath.endswith('/'+f['file'])]
                file=max(candidates,key=lambda f:len(f['file']))['file'] if candidates else ''
                targets=self.resolve(package,file,fn)
                if n is not None:
                    root=dict(gem=gem['name'],version=gem['version'],locked_version=gem['version'],package=package,
                        method=name,receiver=owner.get('namespace') or ('Kernel' if reg['registration_api']=='rb_define_global_function' else receiver),receiver_expression=receiver,c_function=fn,
                        arity=n,registration=reg['registration_api'],file=file or oldpath,line=reg['line'],targets=targets,
                        entry_id='saved:'+reg['registration_id'],saved_only=True)
                    self.roots.append(root); bindings[key].append(root); matches=[root]
            for r in matches:
                r.setdefault('saved_registration_ids',[]).append(reg['registration_id'])
                r['primary_bundle']=bool(gem.get('primary_bundle')) or r.get('primary_bundle',False)
                if owner.get('namespace') and owner.get('owner_candidate_count',1)==1: r['receiver']=owner['namespace']
            record['entries']=[r['entry_id'] for r in matches]
            record['status']='reconciled' if matches else 'allocator_or_attribute' if reg['registration_api'] not in REG else 'unresolved_saved_registration'
            ledger.append(record)
        # Current roots cover methods which never appeared in the older memory
        # candidate catalogue, including macro-generated primitive-free entries.
        packages={f['package'] for f in self.files}
        for l in (repo/'static-catalog/argument-inventory-roots.jsonl').open():
            old=json.loads(l); package=old['gem']+'@'+old['source_variants'].split(';')[0]
            if package not in packages or old['registration'] not in REG: continue
            key=(old['gem'],old['version'],norm(old['c_function']),old['ruby_method_name'],norm(old['ruby_receiver']))
            if key in bindings: continue
            try: arity=int(old['arity'])
            except ValueError: continue
            root=dict(gem=old['gem'],version=old['version'],locked_version=old['source_variants'].split(';')[0],
                package=package,method=old['ruby_method_name'],receiver=old['ruby_receiver'],receiver_expression=old['ruby_receiver'],
                c_function=old['c_function'],arity=arity,registration=old['registration'],file=old['registration_file'],
                line=int(old['registration_line']),targets=self.resolve(package,old['registration_file'],old['c_function']),
                entry_id='catalogue:'+old['entry_id'],saved_only=True,primary_bundle=True)
            self.roots.append(root); bindings[key].append(root)
        self.saved_registration_ledger=ledger

    def global_roots(self):
        """Also recover the three-operand global registration form from cached AST functions."""
        existing={(r['package'],r['file'],r['line'],r['method'],r['registration']) for r in self.roots}
        for fn in self.functions.values():
            if 'rb_define_global_function' not in fn['source']: continue
            b=fn['source'].encode(); tree=PARSERS[fn['parser']].parse(b); keys=[o for o,_ in fn['offsets']]
            for n in walk(tree.root_node):
                if n.type!='call_expression' or callee(n,b)!='rb_define_global_function': continue
                aa=args(n)
                if len(aa)<3: continue
                method,arity=literal(aa[0],b),literal(aa[2],b)
                if not isinstance(method,str) or not isinstance(arity,int): continue
                line=fn['offsets'][max(0,bisect.bisect_right(keys,n.start_byte)-1)][1]
                key=(fn['package'],fn['file'],line,method,'rb_define_global_function')
                if key in existing: continue
                target=txt(aa[1],b).strip(' ()&'); existing.add(key)
                self.roots.append(dict(gem=fn['gem'],version=fn['version'],locked_version=fn['locked_version'],package=fn['package'],
                    method=method,receiver='Kernel',receiver_expression='Kernel',c_function=target,arity=arity,
                    registration='rb_define_global_function',file=fn['file'],line=line,
                    targets=self.resolve(fn['package'],fn['file'],target),
                    entry_id=f'{fn["package"]}:{fn["file"]}:{line}:Kernel:{method}'))

    def normalize_roots(self):
        """Keep distinct ABI bindings; merge identical alias declarations."""
        grouped=collections.defaultdict(list)
        for r in self.roots: grouped[r['entry_id']].append(r)
        result=[]; replacement={}
        for original,rs in sorted(grouped.items()):
            variants={}
            for r in rs:
                binding=(r['c_function'],r['arity'],r['registration'],tuple(r['targets']))
                if binding not in variants: variants[binding]=dict(r)
                else:
                    old=variants[binding]
                    if r.get('saved_registration_ids'): old['saved_registration_ids']=sorted(set(old.get('saved_registration_ids',[])+r['saved_registration_ids']))
            replacement[original]=[]
            for binding,r in sorted(variants.items(),key=str):
                if len(variants)>1: r['entry_id']=original+':binding:'+hashlib.sha256(json.dumps(binding).encode()).hexdigest()[:12]
                result.append(r); replacement[original].append(r['entry_id'])
        self.roots=result
        for r in getattr(self,'saved_registration_ledger',[]):
            r['entries']=sorted({n for old in r['entries'] for n in replacement.get(old,[old])})

class IR:
    """Build a scope-aware small IR from tree-sitter, preserving original locations."""
    def __init__(self,index,fn):
        self.index,self.fn=index,fn; self.b=fn['source'].encode(); self.offsets=fn['offsets']; self.keys=[o for o,_ in self.offsets]
        self.tree=PARSERS[fn['parser']].parse(self.b)
        self.node=next((n for n in walk(self.tree.root_node) if n.type=='function_definition'),None)
        self.scopes=[{p:'p'+str(i) for i,p in enumerate(fn['parameters'])}]; self.declared=set(self.scopes[0].values()); self.calls=[]
        self.body=self.stmt(self.node.child_by_field_name('body')) if self.node else ('block',[])
    def variable(self,name):
        for scope in reversed(self.scopes):
            if name in scope: return scope[name]
        return 'g:'+name
    def location(self,n,kind=None,extra=None):
        line=self.offsets[max(0,bisect.bisect_right(self.keys,n.start_byte)-1)][1] if self.offsets else self.fn['line']
        expression=re.sub(r'\s+',' ',txt(n,self.b)).strip()
        return self.index.event(self.fn['id'],line,kind or n.type,expression,extra)
    def ex(self,n):
        if not n: return ('constant',None)
        t=n.type
        if t in LITERALS: return ('constant',literal(n,self.b))
        if t in {'identifier','field_identifier','qualified_identifier'}:
            s=txt(n,self.b); return ('constant',None) if s in CONSTANTS else ('var',self.variable(s),s)
        if t in {'parenthesized_expression','cast_expression'}:
            c=n.child_by_field_name('value') if t=='cast_expression' else next(iter(n.named_children),None)
            return self.ex(c)
        if t=='sizeof_expression':
            # sizeof does not read object bytes. VLA declarations are separate size sinks.
            return ('constant',None)
        if t=='call_expression':
            name=callee(n,self.b); f=n.child_by_field_name('function')
            event=self.location(n,'call',dict(target=name))
            call=('call',name,[self.ex(a) for a in args(n)],event,self.ex(f))
            self.calls.append(call); return call
        if t=='field_expression': return ('field',self.ex(n.child_by_field_name('argument')),txt(n.child_by_field_name('field'),self.b))
        if t=='subscript_expression':
            ix=n.child_by_field_name('index'); indexes=n.child_by_field_name('indices')
            ix=ix or (indexes.named_children[0] if indexes and indexes.named_children else None)
            return ('sub',self.ex(n.child_by_field_name('argument')),self.ex(ix))
        if t=='pointer_expression':
            op=txt(n.child_by_field_name('operator'),self.b)
            return ('addr' if op=='&' else 'deref',self.ex(n.child_by_field_name('argument')))
        if t=='assignment_expression':
            return ('assign',self.ex(n.child_by_field_name('left')),self.ex(n.child_by_field_name('right')),
                    txt(n.child_by_field_name('operator'),self.b),self.location(n,'assignment'))
        if t=='update_expression': return ('update',self.ex(n.child_by_field_name('argument')),self.location(n,'update'))
        if t=='conditional_expression':
            return ('conditional',self.ex(n.child_by_field_name('condition')),self.ex(n.child_by_field_name('consequence')),self.ex(n.child_by_field_name('alternative')))
        if t in {'new_expression','delete_expression'}: return ('memory_expr',t,[self.ex(c) for c in n.named_children],self.location(n,t))
        return ('op',[self.ex(c) for c in n.named_children if c.type not in {'type_descriptor','primitive_type','type_identifier','struct_specifier'}])
    def stmt(self,n):
        if not n: return ('block',[])
        t=n.type
        if t=='compound_statement':
            self.scopes.append({}); body=[self.stmt(c) for c in n.named_children]
            scope=self.scopes.pop(); return ('block',body,tuple(scope.values()))
        if t=='declaration':
            result=[]
            for c in n.named_children:
                if c.type not in {'init_declarator','identifier','pointer_declarator','array_declarator','function_declarator','reference_declarator'}: continue
                d=c.child_by_field_name('declarator') if c.type=='init_declarator' else c
                name=decl(d,self.b)
                if not name: continue
                uid=f'v:{n.start_byte}:{name}'; self.scopes[-1][name]=uid; self.declared.add(uid)
                val=c.child_by_field_name('value') if c.type=='init_declarator' else None
                arrays=[a for a in walk(d) if a.type=='array_declarator']
                result.append(('declare',uid,self.ex(val),bool(arrays),self.location(c,'declaration')))
                for a in arrays:
                    result.append(('vla',self.ex(a.child_by_field_name('size')),self.location(a,'array_extent')))
            return ('block',result)
        if t=='if_statement': return ('if',self.ex(n.child_by_field_name('condition')),self.stmt(n.child_by_field_name('consequence')),self.stmt(n.child_by_field_name('alternative')))
        if t in {'for_statement','while_statement','do_statement'}:
            self.scopes.append({})
            init=n.child_by_field_name('initializer'); init=self.stmt(init) if init and init.type=='declaration' else ('expr',self.ex(init))
            result=('loop',init,self.ex(n.child_by_field_name('condition')),self.stmt(n.child_by_field_name('body')),self.ex(n.child_by_field_name('update')))
            self.scopes.pop(); return result
        if t=='return_statement': return ('return',self.ex(n.named_children[0] if n.named_children else None),self.location(n,'return'))
        if t=='expression_statement': return ('expr',self.ex(n.named_children[0] if n.named_children else None))
        if t=='switch_statement': return ('switch',self.ex(n.child_by_field_name('condition')),[self.stmt(c) for c in (n.child_by_field_name('body').named_children if n.child_by_field_name('body') else [])])
        if t in {'case_statement','else_clause','labeled_statement','ERROR','preproc_if','preproc_ifdef','preproc_else'}: return ('block',[self.stmt(c) for c in n.named_children if c.type not in LITERALS])
        return ('block',[self.stmt(c) for c in n.named_children])

@dataclass
class Summary:
    result: Value=field(default_factory=Value)
    outputs: dict=field(default_factory=dict)
    sinks: dict=field(default_factory=dict)
    def signature(self): return (self.result.signature(),tuple(sorted((str(k),v.signature()) for k,v in self.outputs.items())),tuple(sorted((str(k),v) for k,v in self.sinks.items())))

def stable_paths(new,old):
    """Join may-effects across arbitrary recursive invocation depths.

    A recursive buffer permutation can alternate its input dependencies at
    successive depths. Replacing summaries would oscillate rather than close
    that set. Body-local assignment/shadowing still use strong overwrites;
    interprocedural summaries retain every discovered may-effect and its
    shortest established derivation.
    """
    new.result=merge(old.result,new.result)
    new.outputs={key:merge(old.outputs.get(key,Value()),new.outputs.get(key,Value()))
        for key in sorted(set(old.outputs)|set(new.outputs),key=str)}
    for key,path in old.sinks.items():
        previous=new.sinks.get(key)
        if previous is None or (len(path),path)<(len(previous),previous): new.sinks[key]=path
    return new

class Solver:
    def __init__(self,index):
        self.index=index; self.irs={}; self.summaries={}; self.reverse=collections.defaultdict(set)
        self.reachable=set(); self.edges=collections.defaultdict(set); self.boundaries={}
        self.pointer_inputs=collections.defaultdict(set); self.table_inputs=collections.defaultdict(set); self.analyses=0; self.changes=0; self.change_counts=collections.Counter()
        self.abi_cache={};self.abi_boundaries={}
    def compatible_arguments(self,target,n,event,caller):
        if target.startswith('@memory:'):return True
        if target not in self.abi_cache:
            fn=self.index.functions[target];prefix=fn['source'].split('{',1)[0];parameters=fn['parameters']
            known=fn['parser']=='c' and bool(parameters) and all(parameters) and not re.search(r'\b[A-Z_][A-Z_0-9]*\s*\(',prefix)
            self.abi_cache[target]=(len(parameters),'...' in prefix) if known else None
        signature=self.abi_cache[target]
        if signature is None:return True
        minimum,variadic=signature
        if n>=minimum if variadic else n==minimum:return True
        self.abi_boundaries[(caller,event,target,n)]=dict(function=caller,event=event,target=target,actual_arguments=n,formal_arguments=minimum,variadic=variadic,reason='incompatible fixed C call argument count')
        return False
    def prepare(self,fid):
        if fid not in self.irs:
            self.irs[fid]=IR(self.index,self.index.functions[fid]); self.summaries[fid]=Summary()
        return self.irs[fid]
    def dependencies(self,fid):
        ir=self.prepare(fid); fn=self.index.functions[fid]
        result=set()
        for call in ir.calls:
            name=call[1]; fexpr=call[4]
            local_pointer=fexpr[0]=='var' and not fexpr[1].startswith('g:')
            ds=[] if local_pointer else self.index.resolve(fn['package'],fn['file'],name)
            # Primitive calls use explicit contracts even when a compatibility
            # implementation is also present; callback arguments remain traversed.
            if not sink_model(name,len(call[2])) and name not in ACCESS: result.update(ds)
            for actual in call[2]:
                if actual[0]=='var' and actual[1].startswith('g:'): result.update(self.index.resolve(fn['package'],fn['file'],actual[2]))
            if not ds and not sink_model(name,len(call[2])) and name not in ACCESS and name not in PROTECTED:
                self.boundaries[(fid,call[3])]=dict(function=fid,event=call[3],target=name,reason='no unique source definition or external data contract')
        return result
    def initial_worklist(self,roots):
        queue=collections.deque(sorted({t for r in roots for t in r['targets']}))
        while queue:
            fid=queue.popleft()
            if fid in self.reachable: continue
            self.reachable.add(fid)
            for target in sorted(self.dependencies(fid)):
                self.edges[fid].add(target); self.reverse[target].add(fid); queue.append(target)
        print(f'Worklist starts: {len(self.reachable)} reachable functions',flush=True)
        # Evaluate callees before callers across the initial graph. The worklist
        # still closes every recursive and subsequently discovered callback edge.
        order=[]; visited=set()
        for start in sorted(self.reachable):
            stack=[(start,False)]
            while stack:
                node,done=stack.pop()
                if done: order.append(node); continue
                if node in visited: continue
                visited.add(node); stack.append((node,True))
                stack.extend((child,False) for child in reversed(sorted(self.edges[node])) if child not in visited)
        priority={fid:i for i,fid in enumerate(order)}
        return [(priority[fid],fid) for fid in order],priority
    def solve(self,roots,checkpoint=None):
        resumed=checkpoint.load(self,Value,Summary) if checkpoint else None
        queue,priority=resumed if resumed is not None else self.initial_worklist(roots)
        heapq.heapify(queue); pending={fid for _,fid in queue}
        next_priority=max((p for p,_ in queue),default=-1)+1
        def enqueue(fid):
            nonlocal next_priority
            if fid in pending:return
            # Preserve the initial callee-first pass. Subsequent updates wait
            # behind already pending work so recursive callers collect changes
            # from all their callees instead of starving those callees.
            first_discovery=fid not in priority
            priority[fid]=next_priority
            heapq.heappush(queue,(-1 if first_discovery else next_priority,fid))
            next_priority+=1;pending.add(fid)
        while queue:
            _,fid=heapq.heappop(queue); pending.discard(fid); old=self.summaries[fid]
            ctx=Context(self,fid); ctx.statement(self.irs[fid].body)
            new=stable_paths(ctx.summary,old); self.analyses+=1
            if new.signature()!=old.signature():
                self.summaries[fid]=new; self.changes+=1
                self.change_counts[fid]+=1
                for caller in sorted(self.reverse[fid]):
                    enqueue(caller)
            for target in sorted(ctx.new_targets):
                if target not in self.reachable:
                    discovery=collections.deque([target])
                    while discovery:
                        child=discovery.popleft()
                        if child in self.reachable: continue
                        self.reachable.add(child)
                        for dep in sorted(self.dependencies(child)):
                            self.edges[child].add(dep); self.reverse[dep].add(child); discovery.append(dep)
                        enqueue(child)
                self.edges[fid].add(target); self.reverse[target].add(fid)
            for target in sorted(ctx.dirty_targets):
                enqueue(target)
            if self.analyses%2000==0: print(f'Fixed point: {self.analyses} function evaluations, {len(queue)} queued, {self.changes} changed; {fid}',flush=True)
            if checkpoint and checkpoint.due():checkpoint.save(self,queue,priority)
        print(f'FIXED POINT: {self.analyses} evaluations; {len(self.reachable)} functions; queue empty',flush=True)

class Context:
    def __init__(self,solver,fid):
        self.solver,self.index,self.fid=solver,solver.index,fid; self.fn=self.index.functions[fid]
        self.env={}; self.cells={}; self.cell_selectors=collections.defaultdict(set); self.read_cache={}; self.summary=Summary(); self.new_targets=set(); self.dirty_targets=set(); self.tainted_unknowns=set()
        for i,p in enumerate(self.fn['parameters']):
            self.env['p'+str(i)]=Value({(i,None):()},frozenset({('param',i)}|solver.table_inputs[(fid,i)]),frozenset(solver.pointer_inputs[(fid,i)]))
    def step(self,v,event): return Value({a:p+(event,) for a,p in v.deps.items()},v.refs,v.funcs,v.const)
    def sink(self,kind,role,value,event):
        # &local and an automatic array have source contents but constant local
        # addresses. Their contents taint a copy's source, not its destination.
        if role in {'destination','pointer'} and value.refs and all(r and r[0] in {'local','array'} and
            (len(r)<=len(root_ref(r)) or r[len(root_ref(r))][0]=='projection') for r in value.refs):
            return
        for atom,path in value.deps.items():
            key=(atom,kind,role); candidate=path+(event,)
            if key not in self.summary.sinks or (len(candidate),candidate)<(len(self.summary.sinks[key]),self.summary.sinks[key]): self.summary.sinks[key]=candidate
    def read_cell(self,base,selector=None):
        cache_key=(base.refs,selector)
        if cache_key in self.read_cache: return self.read_cache[cache_key]
        values=[]; seen_cells=set(); seen_globals=set()
        for ref in sorted(base.refs,key=str):
            root=root_ref(ref); selected=implicit_selector(ref) if selector is None else selector
            for key in ((root,selected),(root,'*')):
                if key in self.cells and key not in seen_cells:
                    seen_cells.add(key); values.append(self.cells[key])
            if selector=='*':
                for s in sorted(self.cell_selectors[root],key=str):
                    key=(root,s)
                    if key in self.cells and key not in seen_cells:
                        seen_cells.add(key); values.append(self.cells[key])
            if root and root[0]=='global' and (root,selected) not in self.cells and (root,selected) not in seen_globals:
                seen_globals.add((root,selected))
                fields=self.index.global_tables.get((root[1],root[2],root[3]),{})
                if selected in fields: values.append(Value(funcs=frozenset(fields[selected])))
                elif selector=='*' and fields: values.append(Value(funcs=frozenset(f for targets in fields.values() for f in targets)))
        result=merge(*values) if values else None
        self.read_cache[cache_key]=result
        return result
    def projection(self,base,selector):
        known=self.read_cell(base,selector)
        if known is not None: return known
        deps={}
        for (i,s),path in base.deps.items(): deps[(i,selector if s is None and isinstance(selector,(int,str)) else s)]=path
        return Value(deps,base.refs,base.funcs)
    def evaluate(self,x):
        t=x[0]
        if t=='constant': return Value(const=x[1])
        if t=='var':
            if x[1] in self.env:
                value=self.env[x[1]]
                contents=self.read_cell(value,'*')
                if contents is not None:
                    combined=merge(value,contents)
                    # Reading a container pointer observes its content taint,
                    # but does not make it alias every pointer stored inside.
                    return Value(combined.deps,value.refs,combined.funcs,value.const)
                return value
            name=x[2]; ds=self.index.function_symbols(self.fn['package'],self.fn['file'],name)
            method=self.index.global_methods.get(self.fn['package'],{}).get(name)
            tables=self.index.global_bindings(self.fn['package'],self.fn['file'],name)
            if tables:return Value(refs=frozenset(('global',self.fn['package'],file,name) for file,_ in tables),funcs=frozenset(f for _,fields in tables for targets in fields.values() for f in targets))
            return Value(funcs=frozenset(ds),const=method)
        if t=='op': return merge(*(self.evaluate(c) for c in x[1]))
        if t=='field':
            v=self.evaluate(x[1]); known=self.read_cell(v,x[2])
            # Object contents are argument-derived. A known field overwrite kills
            # that field's prior taint; unrelated sibling fields stay distinct.
            return known if known is not None else Value(self.projection(v,x[2]).deps,frozenset(root_ref(r)+(('value_projection',x[2]),) for r in v.refs),v.funcs)
        if t=='sub':
            base=self.evaluate(x[1]); ix=self.evaluate(x[2]); selector=ix.const if isinstance(ix.const,int) else '*'
            return merge(self.projection(base,selector),ix)
        if t=='deref':
            v=self.evaluate(x[1]); known=self.read_cell(v,None)
            return known if known is not None else v
        if t=='addr':
            v=self.evaluate(x[1]); refs=v.refs if x[1][0]=='var' and x[1][1].startswith('g:') and v.refs else self.lrefs(x[1]); return Value(v.deps,frozenset(refs or v.refs),v.funcs)
        if t=='assign':
            v=self.evaluate(x[2]); v=merge(v,self.evaluate(x[1])) if x[3]!='=' else v
            v=self.step(v,x[4]); self.write(x[1],v,x[4]); return v
        if t=='update':
            v=self.step(self.evaluate(x[1]),x[2]); v.const=None; self.write(x[1],v,x[2]); return v
        if t=='conditional':
            condition=self.evaluate(x[1]); yes=self.evaluate(x[2]); no=self.evaluate(x[3])
            result=merge(yes,no)
            if yes.const is None or no.const is None or yes.const!=no.const:
                result.deps=merge(result,condition).deps
            return result
        if t=='memory_expr':
            v=merge(*(self.evaluate(c) for c in x[2])); self.sink('allocation' if x[1]=='new_expression' else 'release','operand',v,x[3]); return self.step(v,x[3])
        if t=='call': return self.call(x)
        return Value()
    def lrefs(self,x):
        if x[0]=='var': return {('local',x[1])}
        if x[0]=='field': return {projected_ref(r,x[2]) for r in self.evaluate(x[1]).refs}
        if x[0]=='sub':
            base=self.evaluate(x[1]); ix=self.evaluate(x[2]); selector=ix.const if isinstance(ix.const,int) else '*'
            tag='address_projection' if ix.deps else 'projection'
            return {root_ref(r)+((tag,selector),) for r in base.refs}
        if x[0]=='deref': return set(self.evaluate(x[1]).refs)
        return set()
    def cell_write(self,base,selector,value):
        self.read_cache.clear()
        for ref in sorted(base.refs,key=str):
            selected=implicit_selector(ref) if selector is None else selector
            root=root_ref(ref); key=(root,selected); self.cells[key]=value
            self.cell_selectors[root].add(selected)
            if ref and ref[0]=='local' and selected is None: self.env[ref[1]]=value
            if ref and ref[0]=='param':
                output=(ref[1],selected); self.summary.outputs[output]=merge(self.summary.outputs.get(output,Value()),value)
    def write(self,x,value,event):
        t=x[0]
        if t=='var': self.env[x[1]]=value; return
        if t in {'sub','deref','field'}:
            base=self.evaluate(x[1]); selector=None
            if t=='sub':
                index=self.evaluate(x[2]); selector=index.const if isinstance(index.const,int) else '*'; self.sink('buffer_store','index',index,event)
            if t=='field': selector=x[2]
            kind='field_store' if t=='field' else 'buffer_store'
            self.sink(kind,'destination',base,event); self.sink(kind,'value',value,event)
            self.cell_write(base,selector,value)
    def bind_atom(self,atom,actuals):
        i,selector=atom
        if i>=len(actuals): return Value()
        value=actuals[i]
        return self.projection(value,selector) if selector is not None else value
    def substitute(self,value,actuals,event,target,reference_cache=None):
        out=[]
        for atom,path in sorted(value.deps.items(),key=lambda item:str(item[0])):
            v=self.bind_atom(atom,actuals)
            binding=self.index.event(self.fid,self.index.events[event]['line'],'argument_binding',
                self.index.events[event]['expression'],dict(target=target,formal_index=atom[0],projection=atom[1]))
            out.append(Value({a:p+(binding,)+path for a,p in v.deps.items()}))
        result=merge(*out); result.funcs=value.funcs
        if reference_cache is not None and value.refs in reference_cache:
            result.refs=reference_cache[value.refs]
        else:
            refs=set()
            for ref in value.refs:
                if ref and ref[0]=='param' and ref[1]<len(actuals):
                    selector=implicit_selector(ref)
                    tag=ref[len(root_ref(ref))][0] if selector is not None else None
                    known=self.read_cell(actuals[ref[1]],selector) if tag=='value_projection' else None
                    if known is not None:refs.update(known.refs)
                    elif selector is not None:refs.update(root_ref(r)+((tag,selector),) for r in actuals[ref[1]].refs)
                    else:refs.update(actuals[ref[1]].refs)
                elif ref and ref[0] not in {'local','array'}: refs.add(ref)
            result.refs=frozenset(refs)
            if reference_cache is not None:reference_cache[value.refs]=result.refs
        return result
    def apply(self,target,actuals,event):
        if not self.solver.compatible_arguments(target,len(actuals),event,self.fid):return Value()
        if target.startswith('@memory:'):
            name=target.removeprefix('@memory:');original=self.index.events[event]
            operation=self.index.event(self.fid,original['line'],'call',original['expression'],
                dict(target=name,indirect_source_target=original.get('target')))
            return self.memory_call(name,actuals,operation)
        self.new_targets.add(target)
        for i,v in enumerate(actuals):
            table_refs={r for r in v.refs if r and r[0]=='global'}
            if table_refs-set(self.solver.table_inputs[(target,i)]):
                self.solver.table_inputs[(target,i)].update(table_refs); self.dirty_targets.add(target)
            if v.funcs:
                key=(target,i); old=len(self.solver.pointer_inputs[key]); self.solver.pointer_inputs[key].update(v.funcs)
                if len(self.solver.pointer_inputs[key])!=old:
                    # The caller will be reevaluated as this callee's summary changes.
                    self.new_targets.add(target)
                    self.dirty_targets.add(target)
        summary=self.solver.summaries.get(target,Summary())
        reference_cache={}
        result=self.substitute(summary.result,actuals,event,target,reference_cache)
        outputs=[(i,selector,self.substitute(value,actuals,event,target,reference_cache))
            for (i,selector),value in sorted(summary.outputs.items(),key=lambda item:str(item[0])) if i<len(actuals)]
        sinks=[]
        for (atom,kind,role),path in sorted(summary.sinks.items(),key=lambda item:str(item[0])):
            value=self.substitute(Value({atom:path}),actuals,event,target,reference_cache)
            sinks.append((kind,role,value))
        for i,selector,value in outputs:self.cell_write(actuals[i],selector,value)
        for kind,role,value in sinks:
            for source,trace in value.deps.items():
                key=(source,kind,role)
                if key not in self.summary.sinks or (len(trace),trace)<(len(self.summary.sinks[key]),self.summary.sinks[key]): self.summary.sinks[key]=trace
        return result
    def memory_call(self,name,actuals,event):
        combined=merge(*actuals)
        def at(i): return actuals[i] if i<len(actuals) else Value()
        model=sink_model(name,len(actuals))
        if model:
            kind,slots=model
            for i,role in slots: self.sink(kind,role,at(i),event)
            if name in COPY:
                dest,source,_=COPY[name]; self.cell_write(at(dest),'*',self.step(at(source),event))
            if name in SET:
                dest,value,_=SET[name]; self.cell_write(at(dest),'*',self.step(at(value),event) if value is not None else Value())
            # Constructors return a new object; input references are data
            # dependencies, not aliases of that object's storage. Mixing these
            # locations corrupts field states and makes large AST builders dense.
            refs=frozenset()
            if kind in {'allocation','ruby_memory'}: refs=frozenset({('heap',event)})
            if name in COPY: refs=at(COPY[name][0]).refs
            if name in SET: refs=at(SET[name][0]).refs
            if name in READ_POINTERS: refs=at(0).refs
            if kind=='ruby_memory' and re.search(r'(?:cat|append|concat|resize|expand|push|store|aset|modify)',name): refs=at(0).refs
            if kind=='ruby_coercion': refs=at(0).refs
            result=Value() if kind=='release' else Value(self.step(combined,event).deps,refs,combined.funcs)
            if name in INTERN: result.const=at(0).const
            return result
        raise ValueError('unknown memory contract: '+name)
    def call(self,x):
        _,name,expressions,event,fexpr=x
        name=re.sub(r'^__builtin_','',name); name=re.sub(r'^__(\w+)_chk$',r'\1',name)
        actuals=[self.evaluate(a) for a in expressions]; combined=merge(*actuals)
        def at(i): return actuals[i] if i<len(actuals) else Value()
        if fexpr[0]=='var' and not fexpr[1].startswith('g:'):
            targets=sorted(self.evaluate(fexpr).funcs)
            if targets:return merge(*(self.apply(target,actuals,event) for target in targets))
            if combined.deps:self.tainted_unknowns.add(event)
            return Value()
        if sink_model(name,len(actuals)):return self.memory_call(name,actuals,event)
        if name in ACCESS:
            # Projections are taint transfers, not unchanged-value contracts.
            if name in {'rb_ary_entry','RARRAY_AREF'} and len(actuals)>1:
                v=self.projection(at(0),at(1).const if isinstance(at(1).const,int) else '*'); return self.step(merge(v,at(1)),event)
            return self.step(combined,event)
        if name in {'StringValue','SafeStringValue','ExportStringValue'}:
            if expressions: self.write(expressions[0],at(0),event)
            return self.step(at(0),event)
        if name in {'Data_Get_Struct','TypedData_Get_Struct'}:
            if expressions: self.write(expressions[-1],self.step(at(0),event),event)
            return Value()
        if name in {'Data_Make_Struct','TypedData_Make_Struct'}:
            for i,v in enumerate(actuals): self.sink('allocation','argument',v,event)
            if expressions: self.write(expressions[-1],Value(refs=frozenset({('heap',event)})),event)
            return Value(refs=frozenset({('heap',event)}))
        if name in {'rb_scan_args','rb_scan_args_kw'}:
            shift=1 if name.endswith('_kw') else 0; fmt=at(2+shift).const
            if isinstance(fmt,str):
                digits=re.match(r'^(\d)(\d)?',fmt); fixed=sum(int(s or 0) for s in digits.groups()) if digits else 0
                for i,expression in enumerate(expressions[3+shift:]):
                    target=expression[1] if expression[0]=='addr' else expression
                    is_block=fmt.endswith('&') and i==len(expressions[3+shift:])-1
                    v=Value() if is_block else self.projection(at(1+shift),i if i<fixed else '*')
                    self.write(target,self.step(v,event),event)
            return self.step(at(shift),event)
        if name=='rb_get_kwargs':
            if actuals: self.cell_write(actuals[-1],'*',self.step(at(0),event))
            return Value()
        if name in {'rb_intern','rb_intern_const','rb_intern2'}: return Value(const=at(0).const)
        if name in {'rb_funcall','rb_funcallv','rb_funcallv_kw','rb_funcall2','rb_funcall3','rb_funcall_with_block'}:
            method=at(1).const
            if method in {'to_s','to_str','to_i','to_int','to_f','to_ary','to_a','to_h','length','size','bytesize','read','readpartial','read_nonblock','gets','encoding','encode','dup','b','unpack','unpack1','[]','fetch','keys','values'}:
                return self.step(merge(at(0),*actuals[3:]),event)
            if combined.deps: self.tainted_unknowns.add(event)
            return Value()
        callbacks=[]
        if name in {'rb_protect','rb_ensure','rb_rescue','rb_rescue2','rb_thread_call_without_gvl','rb_thread_call_without_gvl2','rb_thread_call_with_gvl'}:
            callbacks=[(at(0).funcs,[at(1)])]
            if name in {'rb_ensure','rb_rescue','rb_rescue2'}: callbacks.append((at(2).funcs,[at(3),Value()]))
        if name=='rb_block_call': callbacks=[(at(4).funcs,[at(0),at(5),Value(),at(0),Value()])]
        if name=='rb_iterate': callbacks=[(at(0).funcs,[at(1)]),(at(2).funcs,[at(1),at(3)])]
        if callbacks:
            return merge(*(self.apply(target,values,event) for functions,values in callbacks for target in sorted(functions)))
        if name=='RB_OBJ_WRITE' and len(expressions)>=3:
            target=expressions[1][1] if expressions[1][0]=='addr' else ('deref',expressions[1]); self.write(target,at(2),event); return Value()
        targets=self.index.resolve(self.fn['package'],self.fn['file'],name)
        if not targets: targets=sorted(self.evaluate(fexpr).funcs)
        if targets: return merge(*(self.apply(target,actuals,event) for target in targets))
        if combined.deps: self.tainted_unknowns.add(event)
        return Value()
    def snapshot(self): return (dict(self.env),dict(self.cells))
    def restore(self,state):
        self.env,self.cells=map(dict,state); self.read_cache.clear()
    def joined(self,*states):
        return tuple({k:merge(*(s[i].get(k,Value()) for s in states)) for k in sorted(set().union(*(s[i] for s in states)),key=str)} for i in (0,1))
    def state_signature(self,state): return tuple(tuple(sorted((str(k),v.signature()) for k,v in part.items())) for part in state)
    def statement(self,s):
        t=s[0]
        if t=='block':
            continues=True
            for c in s[1]:
                if not self.statement(c): continues=False; break
            if len(s)>2:
                for uid in s[2]: self.env.pop(uid,None)
            if not continues: return False
        elif t=='expr': self.evaluate(s[1])
        elif t=='declare':
            v=self.evaluate(s[2]); v=self.step(v,s[4])
            if s[3]:
                v.refs=frozenset({('array',s[1])}); self.sink('buffer_store','value',v,s[4])
            elif s[2]==('constant',None) and not v.refs:
                v.refs=frozenset({('local',s[1])})
            self.env[s[1]]=v
        elif t=='vla': self.sink('stack_allocation','size',self.evaluate(s[1]),s[2])
        elif t=='return': self.summary.result=merge(self.summary.result,self.step(self.evaluate(s[1]),s[2])); return False
        elif t=='if':
            self.evaluate(s[1]); initial=self.snapshot(); a=self.statement(s[2]); sa=self.snapshot()
            self.restore(initial); b=self.statement(s[3]); sb=self.snapshot()
            self.restore(self.joined(*([sa] if a else []),*([sb] if b else [])) if a or b else initial)
            if not a and not b: return False
        elif t=='switch':
            self.evaluate(s[1]); initial=self.snapshot(); branches=[]
            for branch in s[2]:
                self.restore(initial); self.statement(branch); branches.append(self.snapshot())
            self.restore(self.joined(initial,*branches))
        elif t=='loop':
            self.statement(s[1]); initial=self.snapshot(); prior=initial; iterations=0
            while True:
                iterations+=1
                if iterations%250==0: print('Local loop fixed point',self.fid,'iterations',iterations,'variables',len(self.env),'cells',len(self.cells),flush=True)
                self.restore(prior); self.evaluate(s[2]); self.statement(s[3]); self.evaluate(s[4])
                state=self.joined(prior,self.snapshot())
                if self.state_signature(state)==self.state_signature(prior): break
                prior=state
            self.restore(state)
        return True

def output(index,solver,roots,out,repo):
    out.mkdir(parents=True,exist_ok=True); apis=[]; witnesses=[]; root_ledger=[]
    for r in sorted(roots,key=lambda r:r['entry_id']):
        root=dict(r); hit=[]
        if r['arity']==0: root['status']='no_explicit_arguments'; root_ledger.append(root); continue
        for target in r['targets']:
            summary=solver.summaries.get(target,Summary())
            for (atom,kind,role),path in sorted(summary.sinks.items(),key=str):
                formal,projection=atom; argument=None
                if r['arity']>0 and 1<=formal<=r['arity']: argument=formal-1
                elif r['arity']==-1 and formal==1: argument=projection if isinstance(projection,int) else '*'
                elif r['arity']==-2 and formal==1: argument=projection if isinstance(projection,int) else '*'
                if argument is None or isinstance(argument,int) and argument<0: continue
                events=[index.events[e] for e in path]
                tail=events[-1]; sitefn=index.functions[tail['function']]
                witness=dict(entry_id=r['entry_id'],gem=r['gem'],version=r['version'],method=r['method'],receiver=r['receiver'],
                    argument_index=argument,kind=kind,operand_role=role,site_file=sitefn['file'],site_line=tail['line'],
                    site_function=sitefn['name'],site_expression=tail['expression'],events=list(path),
                    call_depth=sum(e['kind']=='argument_binding' for e in events),source_sha256=sitefn['source_sha256'])
                witnesses.append(witness); hit.append(witness)
        core=[w for w in hit if w['kind']!='field_store']
        root['status']='argument_memory_flow' if core else 'field_store_only' if hit else 'no_witness' if r['targets'] else 'unresolved_root'
        root['witnesses']=len(hit); root_ledger.append(root)
        if hit:
            apis.append(dict(entry_id=r['entry_id'],gem=r['gem'],version=r['version'],locked_version=r['locked_version'],
                receiver=r['receiver'],receiver_expression=r['receiver_expression'],method=r['method'],registration=r['registration'],
                registration_file=r['file'],registration_line=r['line'],c_function=r['c_function'],arity=r['arity'],
                arguments=';'.join(map(str,sorted({w['argument_index'] for w in hit},key=str))),
                memory_kinds=';'.join(sorted({w['kind'] for w in hit})),witnesses=len(hit),memory_operation_witness=bool(core)))
    def jsonl(name,rows):
        with (out/name).open('w') as f:
            for row in rows: f.write(json.dumps(row,sort_keys=True)+'\n')
    jsonl('apis-by-registration.jsonl',apis); jsonl('witnesses.jsonl',witnesses); jsonl('roots.jsonl',root_ledger)
    jsonl('events.jsonl',(dict(id=e,**r) for e,r in sorted(index.events.items())))
    jsonl('functions.jsonl',({k:v for k,v in index.functions[f].items() if k not in {'source','offsets'}} for f in sorted(index.functions)))
    jsonl('files.jsonl',index.files); jsonl('unmodeled-calls.jsonl',[r for _,r in sorted(solver.boundaries.items())])
    jsonl('callback-table-bindings.jsonl',(dict(package=p,file=f,name=n,fields=fields,static=index.global_visibility[(p,f,n)],**index.callback_sources[(p,f,n)]) for (p,f,n),fields in sorted(index.global_tables.items())))
    jsonl('function-pointer-arguments.jsonl',(dict(function=f,formal_index=i,targets=sorted(targets)) for (f,i),targets in sorted(solver.pointer_inputs.items()) if targets))
    jsonl('saved-registration-reconciliation.jsonl',getattr(index,'saved_registration_ledger',[]))
    cited={index.events[e]['function'] for w in witnesses for e in w['events']}
    jsonl('witness-functions.jsonl',(index.functions[f] for f in sorted(cited)))
    jsonl('macro-boundaries.jsonl',[dict(package=p,file=f,name=n,reason=reason) for p,f,n,reason in sorted(index.macro.issues)])
    jsonl('include-boundaries.jsonl',index.include_boundaries)
    jsonl('call-abi-boundaries.jsonl',[row for _,row in sorted(solver.abi_boundaries.items())])
    (out/'memory-operation-models.json').write_text(json.dumps(dict(allocators=ALLOC,copy=COPY,memory_set=SET,
        release=sorted(FREE),format_buffer=FORMAT,memory_read=READ,ruby_memory_pattern=RUBY_MEM.pattern,
        ruby_conversion=sorted(BOX),ruby_coercion=sorted(COERCE),ruby_wrappers=sorted(WRAP),ruby_class_memory=sorted(CLASS_MEMORY),
        cpp_copy=sorted(CPP_COPY),cpp_fill=sorted(CPP_FILL),ruby_symbol_interning=sorted(INTERN),external_taint_accessors=sorted(ACCESS),
        output_and_callback_models=['rb_scan_args','rb_scan_args_kw','Data_Get_Struct','TypedData_Get_Struct',
            'rb_protect','rb_ensure','rb_rescue','rb_rescue2','rb_block_call','rb_iterate',
            'rb_thread_call_without_gvl','rb_thread_call_without_gvl2','rb_thread_call_with_gvl'],
        implicit_stores=['subscript assignment','dereference assignment'],separate=['field assignment']),indent=2,sort_keys=True)+'\n')
    groups=collections.defaultdict(list)
    for api in apis:
        if api['memory_operation_witness']:
            kind='singleton' if api['registration']=='rb_define_singleton_method' else 'module_function' if api['registration'] in {'rb_define_module_function','rb_define_global_function'} else 'instance'
            groups[(api['gem'],api['version'],api['receiver'],api['method'],kind)].append(api)
    distinct=[]
    for key,rows in sorted(groups.items()):
        gem,version,receiver,method,kind=key
        distinct.append(dict(gem=gem,version=version,receiver=receiver,method=method,
            kind=kind,
            c_functions=';'.join(sorted({r['c_function'] for r in rows})),
            memory_kinds=';'.join(sorted({k for r in rows for k in r['memory_kinds'].split(';') if k!='field_store'})),
            registration_ids=';'.join(r['entry_id'] for r in rows)))
    with (out/'apis.csv').open('w',newline='') as f:
        writer=csv.DictWriter(f,list(distinct[0]) if distinct else ['gem','version','receiver','method']); writer.writeheader(); writer.writerows(distinct)
    locked={(r['gem'],r['version']) for r in csv.DictReader((repo/'static-catalog/locked-gems.csv').open())}
    primary=[r for r in distinct if (r['gem'],r['version']) in locked]
    with (out/'apis-primary-lock.csv').open('w',newline='') as f:
        writer=csv.DictWriter(f,list(distinct[0]) if distinct else ['gem','version','receiver','method']); writer.writeheader(); writer.writerows(primary)
    summary=dict(work_commit=__import__('subprocess').check_output(['git','-C',str(repo),'rev-parse','HEAD'],text=True).strip(),
        source_files=len(index.files),function_definitions=len(index.functions),roots=len(roots),
        roots_by_status=dict(collections.Counter(r['status'] for r in root_ledger)),
        api_registrations_with_memory_flow=sum(a['memory_operation_witness'] for a in apis),
        distinct_versioned_apis=len(distinct),primary_locked_apis=len(primary),distinct_apis_ignoring_version=len({(r['gem'],r['receiver'],r['method'],r['kind']) for r in distinct}),
        witnessed_gems=len({r['gem'] for r in distinct}),witnesses=len(witnesses),
        reachable_functions=len(solver.reachable),function_evaluations=solver.analyses,fixed_point_reached=True,
        call_depth_limit=None,max_witness_call_depth=max((w['call_depth'] for w in witnesses),default=0),
        unmodeled_call_sites=len(solver.boundaries),macro_expansions=index.macro.expansions,
        macro_collisions=len(index.macro.issues),per_gem=dict(sorted(collections.Counter(r['gem'] for r in distinct).items())),
        definition='Explicit Ruby positional argument taint reaches a listed memory operation operand or C buffer store. Field stores are reported separately. Static may-data-flow, branch-insensitive across calls; does not assert execution.',
        root_inventory='All parsed rb_define_* registrations plus aliases in all restored packages; saved registrations are reconciled separately.')
    (out/'summary.json').write_text(json.dumps(summary,indent=2,sort_keys=True)+'\n')
    print(json.dumps(summary,indent=2,sort_keys=True),flush=True)

def main():
    import faulthandler, signal
    faulthandler.register(signal.SIGUSR1)
    ap=argparse.ArgumentParser(); ap.add_argument('--manifest',type=Path,required=True); ap.add_argument('--out',type=Path,required=True)
    ap.add_argument('--repo',type=Path,required=True); ap.add_argument('--index-cache',type=Path); ap.add_argument('--gems',nargs='*')
    ap.add_argument('--native-data',type=Path)
    ap.add_argument('--index-only',action='store_true')
    ap.add_argument('--refresh-changed-packages',action='store_true')
    ap.add_argument('--checkpoint',type=Path)
    ap.add_argument('--checkpoint-interval',type=float,default=600)
    args_=ap.parse_args(); index=Index()
    def save_index():
        temporary=args_.index_cache.with_suffix(args_.index_cache.suffix+'.tmp')
        with temporary.open('w') as f:
            json.dump(dict(functions=index.functions,roots=index.roots,files=index.files,global_methods=index.global_methods,
                macro_expansions=index.macro.expansions,macro_issues=sorted(index.macro.issues)),f)
        temporary.replace(args_.index_cache)
    if args_.index_cache and args_.index_cache.exists() and args_.index_cache.stat().st_size:
        data=load_index(args_.index_cache); index.functions=data['functions']; index.roots=data['roots']; index.files=data['files']; index.global_methods=data['global_methods']
        for fid,fn in index.functions.items(): index.names[(fn['package'],fn['name'])].append(fid)
        if args_.refresh_changed_packages:
            manifest=json.loads(args_.manifest.read_text()); existing=collections.defaultdict(dict)
            for r in index.files: existing[r['package']][r['file']]=r['source_sha256']
            dirty={package_key(p) for p in manifest if existing[package_key(p)]!={r['file']:r['sha256'] for r in p['source_files']}}
            if dirty:
                index.functions={f:r for f,r in index.functions.items() if r['package'] not in dirty}
                index.roots=[r for r in index.roots if r['package'] not in dirty]; index.files=[r for r in index.files if r['package'] not in dirty]
                index.names=collections.defaultdict(list)
                for f,r in index.functions.items(): index.names[(r['package'],r['name'])].append(f)
                data={'macro_expansions':data.get('macro_expansions',0),'macro_issues':data.get('macro_issues',[])}
                index.build([p for p in manifest if package_key(p) in dirty])
                index.macro.issues.update(tuple(r) for r in data['macro_issues'] if r[0] not in dirty)
                save_index()
            print('Refreshed changed source packages:',len(dirty),flush=True)
    else:
        index.build(json.loads(args_.manifest.read_text()),set(args_.gems or ()) or None)
        if args_.index_cache:
            save_index()
    if args_.index_cache and args_.index_cache.exists():
        if not index.macro.expansions: index.macro.expansions=data.get('macro_expansions',0) if 'data' in locals() else index.macro.expansions
        if not index.macro.issues and 'data' in locals(): index.macro.issues=set(tuple(r) for r in data.get('macro_issues',[]))
    index.global_roots(); index.saved_roots(args_.repo,args_.native_data)
    manifest=json.loads(args_.manifest.read_text()); index.link_packages(args_.repo,manifest);index.source_includes(manifest)
    for r in index.roots: r['targets']=index.resolve(r['package'],r['file'],r['c_function'])
    index.normalize_roots()
    args_.out.mkdir(parents=True,exist_ok=True)
    preflight=dict(source_files=len(index.files),functions=len(index.functions),registered_roots=len(index.roots),
        recovered_functions=sum(f.get('recovered_functions',0) for f in index.files),
        root_statuses=dict(collections.Counter('resolved' if r['targets'] else 'unresolved' for r in index.roots)),
        unresolved_roots=[r for r in index.roots if not r['targets']],
        duplicate_root_ids=len(index.roots)-len({r['entry_id'] for r in index.roots}))
    (args_.out/'index-validation.json').write_text(json.dumps(preflight,indent=2,sort_keys=True)+'\n')
    if args_.index_only:
        print(json.dumps({k:v for k,v in preflight.items() if k!='unresolved_roots'},indent=2,sort_keys=True)); return
    index.cached_callback_tables(manifest,args_.index_cache,args_.manifest)
    roots=[r for r in index.roots if r['arity']!=0]
    checkpoint=None
    if args_.checkpoint:
        from checkpoint import Checkpoints,identity
        paths=[Path(__file__),Path(__file__).with_name('checkpoint.py'),Path(__file__).with_name('includes.py'),Path(__file__).with_name('requirements.txt'),args_.manifest]
        if args_.index_cache:paths.append(args_.index_cache)
        checkpoint=Checkpoints(args_.checkpoint,identity(paths,index.roots),args_.checkpoint_interval)
    solver=Solver(index); solver.solve(roots,checkpoint); output(index,solver,index.roots,args_.out,args_.repo)

if __name__=='__main__': main()

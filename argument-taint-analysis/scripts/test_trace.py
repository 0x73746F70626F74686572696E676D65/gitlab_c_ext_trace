#!/usr/bin/env python3
"""Semantic fixtures for argument-to-memory tracing; target code is never run."""
import bisect,hashlib,json,tempfile,unittest
from pathlib import Path
from trace import Context, Index, Solver,Value,merge
from index_cache import compact_offsets,load_index
from checkpoint import Checkpoints

def analyze(source):
    with tempfile.TemporaryDirectory() as directory:
        p=Path(directory)/'fixture.c'; p.write_text(source)
        manifest=[dict(gem='fixture',version='1',locked_version='1',directory=directory,
            source_files=[dict(file=p.name,sha256=hashlib.sha256(p.read_bytes()).hexdigest(),bytes=p.stat().st_size)])]
        index=Index(); index.build(manifest); index.callback_tables(manifest)
        index.normalize_roots(); solver=Solver(index); solver.solve(index.roots)
        result={}
        for root in index.roots:
            hits=[]
            for f in root['targets']:
                for (atom,kind,role),path in solver.summaries[f].sinks.items():
                    formal,projection=atom
                    arg=formal-1 if root['arity']>0 and 0<formal<=root['arity'] else projection if root['arity']==-1 and formal==1 else None
                    if arg is not None: hits.append((arg,kind,role,path))
            result[root['method']]=hits
        return index,solver,result

class SemanticTests(unittest.TestCase):
    def test_returned_stack_field_pointer_is_a_memory_destination(self):
        _,_,results=analyze('''
        struct State { void *destination; };
        void *get_destination(struct State *s){return s->destination;}
        long api(long self,void *destination){struct State s;s.destination=destination;memset(get_destination(&s),0,8);return 0;}
        void Init_fixture(void){rb_define_method(C,"api",api,1);}''')
        self.assertTrue(any(arg==0 and kind=='memory_set' and role=='destination' for arg,kind,role,_ in results['api']))
    def test_dynamic_stack_buffer_address_taints_destination(self):
        _,_,results=analyze('''
        long api(long self,long index){char out[128];memset(&out[index],0,8);return 0;}
        long fixed(long self,long n){char out[128];out[0]=n;memset(&out[8],0,8);return 0;}
        void Init_fixture(void){rb_define_method(C,"api",api,1);rb_define_method(C,"fixed",fixed,1);}''')
        self.assertTrue(any(arg==0 and kind=='memory_set' and role=='destination' for arg,kind,role,_ in results['api']))
        self.assertFalse(any(kind=='memory_set' for _,kind,_,_ in results['fixed']))
    def test_helper_outputs_read_the_call_input_state(self):
        _,_,results=analyze('''
        struct State { char *a; char *z; };
        void save(struct State *s){s->z=s->a;s->a="fixed";}
        long api(long self,char *source){struct State s;s.a=source;save(&s);memcpy(destination,s.z,8);return 0;}
        void Init_fixture(void){rb_define_method(C,"api",api,1);}''')
        self.assertTrue(any(arg==0 and kind=='copy' and role=='source' for arg,kind,role,_ in results['api']))
    def test_stack_struct_fields_flow_between_helpers(self):
        _,_,results=analyze('''
        struct State { char *source; long length; };
        void prepare(struct State *s,char *source,long length){s->source=source;s->length=length;}
        void consume(struct State *s){memcpy(destination,s->source,s->length);}
        long api(long self,char *source,long length){struct State s;prepare(&s,source,length);consume(&s);return 0;}
        long clean(long self,char *source,long length){struct State s;prepare(&s,source,length);s.source="fixed";s.length=8;consume(&s);return 0;}
        void Init_fixture(void){rb_define_method(C,"api",api,2);rb_define_method(C,"clean",clean,2);}
        ''')
        self.assertTrue(any(arg==0 and kind=='copy' and role=='source' for arg,kind,role,_ in results['api']))
        self.assertTrue(any(arg==1 and kind=='copy' and role=='length' for arg,kind,role,_ in results['api']))
        self.assertFalse(any(kind=='copy' for _,kind,_,_ in results['clean']))
    def test_callback_argument_counts_exclude_incompatible_allocator(self):
        _,_,results=analyze('''
        typedef long(*compare_t)(long,long);
        long wrong(long a,long b,long c,long d){malloc(a);return 0;}
        long right(long a,long b){malloc(a);return 0;}
        long dispatch(compare_t compare,long a,long b){return compare(a,b);}
        long negative(long self,long n){return dispatch(wrong,n,0);}
        long positive(long self,long n){return dispatch(right,n,0);}
        void Init_fixture(void){rb_define_method(C,"negative",negative,1);rb_define_method(C,"positive",positive,1);}''')
        # The shared dispatch abstraction sees both callbacks; only the matching
        # two-argument declaration is a valid C target, even for mixed contexts.
        self.assertTrue(results['positive'])
        index,solver,negative=analyze('''
        long wrong(long a,long b,long c,long d){malloc(a);return 0;}
        long api(long self,long n){long(*compare)(long,long)=wrong;return compare(n,0);}
        void Init_fixture(void){rb_define_method(C,"negative",api,1);}''')
        self.assertFalse(negative['negative']);self.assertTrue(solver.abi_boundaries)
    def test_static_header_helpers_require_transitive_include_visibility(self):
        sources={'included.h':'static void chosen(long n){malloc(n);}',
                 'bridge.h':'#include "included.h"\n',
                 'unrelated.h':'static void forbidden(long n){malloc(n);}',
                 'api.c':'#include "bridge.h"\nlong yes(long self,long n){chosen(n);return 0;}long no(long self,long n){forbidden(n);return 0;}void Init_fixture(void){rb_define_method(C,"yes",yes,1);rb_define_method(C,"no",no,1);}'}
        with tempfile.TemporaryDirectory() as directory:
            records=[]
            for name,source in sources.items():
                path=Path(directory)/name;path.write_text(source);records.append(dict(file=name,sha256=hashlib.sha256(path.read_bytes()).hexdigest(),bytes=path.stat().st_size))
            manifest=[dict(gem='fixture',version='1',locked_version='1',directory=directory,source_files=records)]
            index=Index();index.build(manifest);index.source_includes(manifest);index.callback_tables(manifest)
            solver=Solver(index);solver.solve(index.roots)
            flows={r['method']:solver.summaries[r['targets'][0]].sinks for r in index.roots}
            self.assertTrue(flows['yes']);self.assertFalse(flows['no'])
    def test_checkpoint_resume_preserves_complete_evidence(self):
        source='''void tail(long n){malloc(n);}void middle(long n){tail(n);}
        long api(long self,long n){middle(n);return 0;}
        void Init_fixture(void){rb_define_method(C,"api",api,1);}'''
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'fixture.c';path.write_text(source)
            manifest=[dict(gem='fixture',version='1',locked_version='1',directory=directory,
                source_files=[dict(file=path.name,sha256=hashlib.sha256(path.read_bytes()).hexdigest(),bytes=path.stat().st_size)])]
            def make():
                index=Index();index.build(manifest);index.callback_tables(manifest);index.normalize_roots()
                return index,Solver(index)
            clean_index,clean=make();clean.solve(clean_index.roots)
            class InterruptingCheckpoint(Checkpoints):
                def save(self,solver,queue,priority):
                    super().save(solver,queue,priority)
                    if solver.analyses==2:raise InterruptedError('fixture interruption')
            key={'fixture':'same inert sources'}
            first_index,first=make();check=InterruptingCheckpoint(Path(directory)/'checkpoint',key,0)
            with self.assertRaises(InterruptedError):first.solve(first_index.roots,check)
            resumed_index,resumed=make();resumed.solve(resumed_index.roots,Checkpoints(Path(directory)/'checkpoint',key))
            self.assertEqual(clean_index.events,resumed_index.events)
            self.assertEqual(clean.analyses,resumed.analyses)
            self.assertEqual({f:s.signature() for f,s in clean.summaries.items()},
                             {f:s.signature() for f,s in resumed.summaries.items()})
            with self.assertRaises(ValueError):
                Checkpoints(Path(directory)/'checkpoint',{'fixture':'different'}).load(resumed,Value,type(next(iter(resumed.summaries.values()))))
    def test_cached_memory_reads_follow_overwrite_and_branch_restore(self):
        _,_,results=analyze('''
        long api(long self,long n){long a[2];a[0]=n;long observed=a[0];a[0]=8;malloc(a[0]);return observed;}
        long branched(long self,long n){long a[2];a[0]=8;if(n){a[0]=n;malloc(a[0]);}else{malloc(a[0]);}return 0;}
        void Init_fixture(void){rb_define_method(C,"clean",api,1);rb_define_method(C,"branch",branched,1);}''')
        self.assertFalse(any(kind=='allocation' for _,kind,_,_ in results['clean']))
        self.assertTrue(any(kind=='allocation' for _,kind,_,_ in results['branch']))
    def test_long_witness_joins_are_order_independent(self):
        short=Value({(1,None):tuple(range(1000))},frozenset({('param',1)}),frozenset({'callback'}))
        long=Value({(1,None):tuple(range(1001)),(2,'field'):(9,)},frozenset({('param',2)}))
        self.assertEqual(merge(short,long,short).signature(),merge(long,short).signature())
        self.assertEqual(merge(short,long).deps[(1,None)],tuple(range(1000)))
    def test_file_static_callback_hooks_keep_their_own_bindings(self):
        sources={'first.c':'''typedef void*(*allocator_t)(long);static void* clean(long n){return 0;}static allocator_t hook=clean;long first(long self,long n){return hook(n);}void Init_first(void){rb_define_method(C,"first",first,1);}''',
            'second.c':'''typedef void*(*allocator_t)(long);static allocator_t hook=malloc;long second(long self,long n){return hook(n);}void Init_second(void){rb_define_method(C,"second",second,1);}'''}
        with tempfile.TemporaryDirectory() as directory:
            records=[]
            for name,source in sources.items():
                path=Path(directory)/name;path.write_text(source);records.append(dict(file=name,sha256=hashlib.sha256(path.read_bytes()).hexdigest(),bytes=path.stat().st_size))
            manifest=[dict(gem='fixture',version='1',locked_version='1',directory=directory,source_files=records)]
            index=Index();index.build(manifest);index.callback_tables(manifest);solver=Solver(index);solver.solve(index.roots)
            flows={r['method']:solver.summaries[r['targets'][0]].sinks for r in index.roots}
        self.assertFalse(flows['first'])
        self.assertTrue(any(k[1]=='allocation' for k in flows['second']))
    def test_external_memory_function_pointer_and_global_hook(self):
        _,_,r=analyze('''
        typedef void*(*allocator_t)(long);allocator_t hook=malloc;
        void* helper(allocator_t fn,long n){return fn(n);}
        long api(long self,long n){return helper(malloc,n);}
        long global_api(long self,long n){return hook(n);}
        void Init_fixture(void){rb_define_method(C,"indirect",api,1);rb_define_method(C,"global",global_api,1);}''')
        self.assertTrue(any(arg==0 and k=='allocation' and role=='size' for arg,k,role,_ in r['indirect']))
        self.assertTrue(any(len(path)>1 for _,k,_,path in r['indirect'] if k=='allocation'))
        self.assertTrue(any(k=='allocation' for _,k,_,_ in r['global']))
    def test_saved_macro_symbol_joins_fresh_api_binding(self):
        index,_,_=analyze('''
        #define legacy_name actual
        long actual(long self,long n){return malloc(n);}
        void Init_fixture(void){rb_define_method(C,"api",legacy_name,1);}''')
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);native=root/'native';native.mkdir();catalog=root/'static-catalog';catalog.mkdir()
            (catalog/'argument-inventory-roots.jsonl').write_text('')
            tables={'gems':[dict(gem_id='g',name='fixture',version='1')],
                'c_files':[dict(file_id='f',path='sources/fixture.c')],
                'c_functions':[dict(function_id='c',name='legacy_name')],
                'c_registrations':[dict(registration_id='r',gem_id='g',file_id='f',c_function_id='c',registration_api='rb_define_method',receiver_expression='C',ruby_name='api',arity=1,line=4)],
                'ruby_native_registrations':[dict(registration_id='r',method='api',namespace='Fixture',owner_candidate_count=1)]}
            for name,rows in tables.items():(native/(name+'.jsonl')).write_text(''.join(json.dumps(r)+'\n' for r in rows))
            index.saved_roots(root,native)
        self.assertEqual(len(index.roots),1)
        self.assertEqual(index.roots[0]['receiver'],'Fixture')
        self.assertEqual(index.saved_registration_ledger[0]['binding_match'],'ruby_api_and_argument_abi')
        self.assertTrue(index.roots[0]['targets'])
    def test_local_callback_shadows_same_named_function(self):
        _,_,negative=analyze('''
        void selected(long n){malloc(n);}void clean(long n){}
        void helper(void(*selected)(long),long n){selected(n);}
        long api(long self,long n){helper(clean,n);return 0;}
        void Init_fixture(void){rb_define_method(C,"negative",api,1);}''')
        self.assertFalse(negative['negative'])
        _,_,positive=analyze('''
        void selected(long n){}void allocate(long n){malloc(n);}
        void helper(void(*selected)(long),long n){selected(n);}
        long api(long self,long n){helper(allocate,n);return 0;}
        void Init_fixture(void){rb_define_method(C,"positive",api,1);}''')
        self.assertTrue(any(k=='allocation' for _,k,_,_ in positive['positive']))
    def test_streamed_cache_preserves_locations_and_unicode(self):
        index,_,_=analyze('''long api(long self,long x){return malloc(x);}void Init_fixture(void){rb_define_method(C,"a",api,1);}''')
        original=next(iter(index.functions.values()))
        mapping=[(0,1),(2,1),(5,3),(8,3),(12,2)]
        reduced=compact_offsets(mapping)
        for position in range(20):
            lookup=lambda rows:rows[max(0,bisect.bisect_right([p for p,_ in rows],position)-1)][1]
            self.assertEqual(lookup(mapping),lookup(reduced))
        data=dict(functions=index.functions,roots=index.roots,files=index.files,global_methods=index.global_methods,macro_expansions=123456789,unicode='\\"☃')
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'index.json';path.write_text(json.dumps(data))
            restored=load_index(path,chunk_size=7)
        self.assertEqual(restored['macro_expansions'],123456789)
        self.assertEqual(restored['unicode'],data['unicode'])
        self.assertEqual(restored['roots'],data['roots'])
        self.assertEqual(next(iter(restored['functions'].values()))['source'],original['source'])
    def test_memory_reads_and_pointer_search_return(self):
        _,_,r=analyze('''
        char* search(char* s,long n){return memchr(s,0,n);}
        long api(long self,char* a,char* b,long n){memcmp(a,b,n);memcpy(search(a,n),b,n);return strlen(a);}
        void Init_fixture(void){rb_define_method(C,"reads",api,3);}''')
        self.assertEqual({arg for arg,k,_,_ in r['reads'] if k=='memory_read'},{0,1,2})
        self.assertTrue(any(arg==0 and k=='copy' and role=='destination' and len(path)>1 for arg,k,role,path in r['reads']))
    def test_recursive_buffer_permutation_closes_both_origins(self):
        _,s,r=analyze('''
        void swap(long* p,long n){long t=p[0];p[0]=p[1];p[1]=t;if(n)swap(p,n-1);}
        long api(long self,long a,long b){long p[]={a,b};swap(p,NUM2LONG(a));return malloc(p[0]);}
        void Init_fixture(void){rb_define_method(C,"permutation",api,2);}''')
        self.assertEqual({arg for arg,k,_,_ in r['permutation'] if k=='allocation'},{0,1})
        self.assertLess(s.analyses,100)
    def test_scan_args_block_is_not_a_positional_source(self):
        _,_,r=analyze('''
        long only_block(int argc,long* argv,long self){long block;rb_scan_args(argc,argv,"0&",&block);return malloc(block);}
        long positional(int argc,long* argv,long self){long n,block;rb_scan_args(argc,argv,"1&",&n,&block);malloc(block);return malloc(n);}
        void Init_fixture(void){rb_define_method(C,"block",only_block,-1);rb_define_method(C,"positional",positional,-1);}''')
        self.assertFalse(r['block']); self.assertTrue(r['positional'])
    def test_cast_registration_and_parser_recovery(self):
        _,_,r=analyze('''
        malformed_top_level_token(
        long hidden(long self,long n){return malloc(n);}
        void Init_fixture(void){rb_define_method(C,"hidden",(VALUE(*)(...))hidden,1);}
        ''')
        self.assertTrue(r['hidden'])
    def test_alias_bindings_keep_distinct_argument_abis(self):
        index,_,r=analyze('''
        long fixed(long self,long n){return malloc(n);}
        long vector(int argc,long* argv,long self){return malloc(argv[1]);}
        void Init_fixture(void){rb_define_method(C,"original",fixed,1);
          rb_define_method(C,"original",vector,-1);rb_define_alias(C,"alias","original");}''')
        aliases=[x for x in index.roots if x['method']=='alias']
        self.assertEqual(len(aliases),2)
        self.assertEqual(len({x['entry_id'] for x in aliases}),2)
        self.assertEqual({x['arity'] for x in aliases},{1,-1})
    def test_wrapper_coercion_and_qualified_copy_models(self):
        _,_,r=analyze('''
        long wrapped(long self,long p){return TypedData_Wrap_Struct(C,T,p);}
        long coerced(long self,long p){return rb_obj_as_string(p);}
        long copied(long self,long p){char b[8];__builtin_memcpy(b,p,8);return 0;}
        long copy(long x){return 4;}
        long unrelated(long self,long p){return copy(p);}
        void Init_fixture(void){rb_define_method(C,"wrapped",wrapped,1);rb_define_method(C,"coerced",coerced,1);
          rb_define_method(C,"copied",copied,1);rb_define_method(C,"unrelated",unrelated,1);}''')
        self.assertTrue(any(k=='ruby_memory' for _,k,_,_ in r['wrapped']))
        self.assertTrue(any(k=='ruby_coercion' for _,k,_,_ in r['coerced']))
        self.assertTrue(any(k=='copy' and role=='source' for _,k,role,_ in r['copied']))
        self.assertFalse(r['unrelated'])
    def test_assignment_shadow_and_control_are_not_flows(self):
        _,_,r=analyze('''
        long overwrite(long self, long n) { n=8; return malloc(n); }
        long shadow(long self, long n) { { long n=8; malloc(n); } return 0; }
        long control(long self, long n) { if (n) malloc(8); return 0; }
        long data(long self, long n) { long k=n*3+1; return malloc(k); }
        void Init_fixture(void) {
          rb_define_method(C,"overwrite",overwrite,1); rb_define_method(C,"shadow",shadow,1);
          rb_define_method(C,"control",control,1); rb_define_method(C,"data",data,1);
        }''')
        self.assertFalse(r['overwrite']); self.assertFalse(r['shadow']); self.assertFalse(r['control'])
        self.assertTrue(any(a==0 and k=='allocation' for a,k,_,_ in r['data']))
    def test_explicit_boolean_size_selection(self):
        _,_,r=analyze('''
        long api(long self,long flag){return malloc(RTEST(flag)?8:32);}
        void Init_fixture(void){rb_define_method(C,"selected_size",api,1);}''')
        self.assertTrue(any(k=='allocation' for _,k,_,_ in r['selected_size']))
    def test_no_depth_limit_and_return_binding(self):
        helpers=['long h0(long n){return n+1;}']
        helpers += [f'long h{i}(long n){{return h{i-1}(n)+1;}}' for i in range(1,121)]
        _,_,r=analyze('\n'.join(helpers)+'''
        long api(long self,long n){return malloc(h120(n));}
        void Init_fixture(void){rb_define_method(C,"deep",api,1);}''')
        self.assertTrue(r['deep']); self.assertGreater(max(len(p) for _,_,_,p in r['deep']),120)
    def test_recursion_reaches_fixed_point(self):
        _,solver,r=analyze('''
        long cycle_b(long n){return cycle_a(n);}
        long cycle_a(long n){if(n) return cycle_b(n-1); return n;}
        long api(long self,long n){return malloc(cycle_a(n));}
        void Init_fixture(void){rb_define_method(C,"recursive",api,1);}''')
        self.assertTrue(r['recursive']); self.assertLess(solver.analyses,100)
    def test_output_pointer_and_content_copy(self):
        _,_,r=analyze('''
        void helper(long n,long *out){*out=n*2;}
        long api(long self,long n){long tmp=0;helper(n,&tmp);memcpy(dest,&tmp,8);return 0;}
        void Init_fixture(void){rb_define_method(C,"out",api,1);}''')
        self.assertTrue(any(k=='copy' and role=='source' for _,k,role,_ in r['out']))
    def test_local_destination_address_is_independent(self):
        _,_,r=analyze('''
        long api(long self,long n){memcpy(&n,constant_source,8);return 0;}
        void Init_fixture(void){rb_define_method(C,"address",api,1);}''')
        self.assertFalse(any(k=='copy' for _,k,_,_ in r['address']))
    def test_array_initializer_and_symbol_interning(self):
        _,_,r=analyze('''
        long array(long self,long n){long tmp[1]={n};return unavailable(tmp);}
        long symbol(long self,long str){return rb_intern(RSTRING_PTR(str));}
        void Init_fixture(void){rb_define_method(C,"array",array,1);rb_define_method(C,"symbol",symbol,1);}''')
        self.assertTrue(any(k=='buffer_store' for _,k,_,_ in r['array']))
        self.assertTrue(any(k=='ruby_memory' for _,k,_,_ in r['symbol']))
    def test_macro_generated_function_registration_and_paste(self):
        _,_,r=analyze('''
        #define MAKE(name) long api_##name(long self,long n){return malloc(n);}
        #define REG(name) rb_define_method(C,#name,api_##name,1)
        MAKE(one)
        void Init_fixture(void){REG(one);}
        ''')
        self.assertTrue(r['one'])
    def test_multiline_macro_and_code_after_definition(self):
        _,_,r=analyze('''
        #define TRANSFORM(x) ((x) + \\
          7)
        long api(long self,long n){return malloc(TRANSFORM(n));}
        void Init_fixture(void){rb_define_method(C,"multiline",api,1);}
        ''')
        self.assertTrue(r['multiline'])
    def test_known_output_overwrite_kills_prior_taint(self):
        _,_,r=analyze('''
        void clear(long *out){*out=8;}
        long api(long self,long n){clear(&n);return malloc(n);}
        void Init_fixture(void){rb_define_method(C,"clear",api,1);}
        ''')
        self.assertFalse(any(k=='allocation' for _,k,_,_ in r['clear']))
    def test_scan_args_and_positional_selection(self):
        _,_,r=analyze('''
        long api(int argc, long *argv, long self){long a,b;rb_scan_args(argc,argv,"11",&a,&b); return malloc(b);}
        long direct(int argc,long *argv,long self){return malloc(argv[3]);}
        void Init_fixture(void){rb_define_method(C,"scan",api,-1);rb_define_method(C,"direct",direct,-1);}
        ''')
        self.assertEqual({a for a,_,_,_ in r['scan']},{1}); self.assertEqual({a for a,_,_,_ in r['direct']},{3})
    def test_unknown_return_does_not_create_proof(self):
        _,_,r=analyze('''
        long api(long self,long n){return malloc(unavailable(n));}
        void Init_fixture(void){rb_define_method(C,"unknown",api,1);}''')
        self.assertFalse(r['unknown'])
    def test_callback_binding(self):
        _,_,r=analyze('''
        long body(long n){return malloc(n);}
        long api(long self,long n){return rb_protect(body,n,status);}
        void Init_fixture(void){rb_define_method(C,"callback",api,1);}''')
        self.assertTrue(r['callback'])
    def test_concrete_function_pointer(self):
        _,_,r=analyze('''
        long body(long n){return malloc(n);}
        long forward(long (*fn)(long),long n){return fn(n);}
        long api(long self,long n){return forward(body,n);}
        void Init_fixture(void){rb_define_method(C,"pointer",api,1);}''')
        self.assertTrue(r['pointer'])
    def test_callback_table_field_binding(self):
        _,_,r=analyze('''
        struct Ops { long (*alloc)(long); long (*other)(long); };
        long body(long n){return malloc(n);}
        long other(long n){return 0;}
        struct Ops callbacks={body,other};
        long forward(struct Ops *ops,long n){return ops->alloc(n);}
        long api(long self,long n){return forward(&callbacks,n);}
        void Init_fixture(void){rb_define_method(C,"table",api,1);}''')
        self.assertTrue(r['table'])
    def test_sibling_field_overwrite(self):
        _,_,r=analyze('''
        long api(long self, struct S *s){s->n=10;malloc(s->n);return 0;}
        void Init_fixture(void){rb_define_method(C,"field",api,1);}''')
        self.assertFalse(any(k=='allocation' for _,k,_,_ in r['field']))
    def test_infinite_pointer_chain_is_finite_abstraction(self):
        _,solver,r=analyze('''
        long api(long self,struct S *s){while(s){s=s->next;memcpy(dest,s,8);}return 0;}
        void Init_fixture(void){rb_define_method(C,"chain",api,1);}''')
        self.assertTrue(r['chain']); self.assertLess(solver.analyses,100)
    def test_address_of_field_chain_is_finite(self):
        _,solver,r=analyze('''
        long api(long self,struct S *s){while(s){s=&s->next;memcpy(dest,s,8);}return 0;}
        void Init_fixture(void){rb_define_method(C,"address_chain",api,1);}''')
        self.assertTrue(r['address_chain']); self.assertLess(solver.analyses,100)
    def test_pointer_container_does_not_alias_its_elements(self):
        index,solver,r=analyze('''
        long api(long self,long n){long *items[2];items[0]=malloc(n);items[1]=malloc(8);return 0;}
        void Init_fixture(void){rb_define_method(C,"container",api,1);}''')
        self.assertTrue(r['container'])
        f=index.roots[0]['targets'][0]
        ctx=Context(solver,f); ctx.statement(solver.irs[f].body)
        self.assertFalse(any(root[0]=='heap' for root,selector in ctx.cells))

if __name__=='__main__': unittest.main()

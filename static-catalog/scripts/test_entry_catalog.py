"""Static transfer tests; all C snippets are inert parser input."""
import unittest
from entry_catalog import Origin, Tracer, function_parameters
from catalog import PARSERS, decl_name, text, walk

def traced(source,arity=2,macros=None):
    data=source.encode()
    tree=PARSERS['c'].parse(data)
    functions={}
    for node in walk(tree.root_node):
        if node.type=='function_definition':
            name=decl_name(node.child_by_field_name('declarator'),data)
            functions[name]=dict(id=name,gem='fixture',version='1',file='ext/fixture.c',name=name,
                line=node.start_point.row+1,parameters=function_parameters(node,data),static=False,
                parser='c',source=text(node,data).encode(),recovered=node.has_error,extension_groups=['ext'])
    tracer=Tracer(functions,macros or {})
    tracer.root=dict(entry_id='fixture:root',gem='fixture',ruby_method_name='test',ruby_receiver='klass',
        c_function='root',arity=arity,registration_file='ext/fixture.c',registration_line=1)
    inputs=[set() for _ in functions['root']['parameters']]
    if arity>=0:
        for i in range(arity): inputs[i+1]={Origin(i)}
    elif arity==-1: inputs[1]={Origin(0,pack=True)}
    tracer.trace('root',inputs)
    return tracer

class EntryTransfers(unittest.TestCase):
    def test_direct_count_and_pointer(self):
        t=traced('void root(void*self,int n,char*s) { char dst[16]; memcpy(dst,s,n); }')
        self.assertEqual({(r['argument_index'],r['slot'],r['note']) for r in t.kept.values()},
                         {(0,'count','direct'),(1,'pointer','direct')})

    def test_helper_argument_position(self):
        t=traced('void helper(char*s,int n) { memcpy(dst,s,n); } void root(void*self,int n,char*s) { helper(s,n); }')
        self.assertEqual({(r['argument_index'],r['slot'],r['note']) for r in t.kept.values()},
                         {(0,'count','via one helper'),(1,'pointer','via one helper')})

    def test_helper_return_identity(self):
        t=traced('int identity(int n) { return n; } void root(void*self,int n) { n=identity(n); memcpy(dst,src,n); }',1)
        row=next(iter(t.kept.values()))
        self.assertEqual(row['note'],'via one helper')
        self.assertEqual(row['path'],'root -> identity -> root')

    def test_local_length_and_literal_rewrite_stop_flow(self):
        t=traced('void root(void*self,int n,char*s) { n=8; memcpy(dst,src,n); n=strlen(s); memcpy(dst,src,n); }')
        self.assertEqual(list(t.kept.values()),[])
        self.assertTrue(t.drops)

    def test_unresolved_macro_is_not_kept(self):
        t=traced('void root(void*self,int n) { n=NUM2INT(n); memcpy(dst,src,n); }',1)
        self.assertEqual(list(t.kept.values()),[])
        self.assertIn('unexpanded macro',{r['reason'] for r in t.unresolved.values()})

    def test_function_pointer_is_not_kept(self):
        t=traced('void root(void*self,int n) { n=callback(n); memcpy(dst,src,n); }',1)
        self.assertEqual(list(t.kept.values()),[])
        self.assertTrue(t.unresolved)

    def test_allocator_arithmetic_pair(self):
        t=traced('void root(void*self,int n) { char*p=malloc(n+1); memcpy(p,src,n); }',1)
        self.assertEqual({(r['slot'],r['callee_or_store']) for r in t.kept.values()},
                         {('size','malloc'),('count','memcpy')})

    def test_sizeof_operand_does_not_bind_input_multiplication(self):
        t=traced('void root(void*self,int n) { char*p=malloc(n*sizeof(char)); memcpy(p,src,n); }',1)
        self.assertEqual({(r['slot'],r['callee_or_store']) for r in t.kept.values()},
                         {('size','malloc'),('count','memcpy')})

    def test_literal_format_drops_only_format_slot(self):
        t=traced('void root(void*self,int n,char*fmt) { snprintf(dst,n,"%s",src); printf(fmt); }')
        self.assertEqual({(r['argument_index'],r['slot']) for r in t.kept.values()},
                         {(0,'count'),(1,'format')})

    def test_ruby_format_object_argument(self):
        t=traced('void root(void*self,void*fmt) { rb_str_format(0,args,fmt); }',1)
        self.assertEqual({(r['argument_index'],r['slot']) for r in t.kept.values()},{(0,'format')})

    def test_nonliteral_ruby_argument_extraction_format_is_a_site(self):
        t=traced('void root(void*self,char*fmt) { rb_scan_args(argc,args,fmt); }',1)
        self.assertEqual({(r['argument_index'],r['slot']) for r in t.kept.values()},{(0,'format')})

    def test_return_prevents_dead_store_and_branch_flow(self):
        t=traced('void root(void*self,int n) { return; memcpy(dst,src,n); }',1)
        self.assertEqual(list(t.kept.values()),[])
        t=traced('void root(void*self,int n) { if(n) { return; } else { n=4; } memcpy(dst,src,n); }',1)
        self.assertEqual(list(t.kept.values()),[])

    def test_argv_static_index_maps_to_ruby_argument(self):
        t=traced('void root(int argc,void**argv,void*self) { printf((char*)argv[1]); }',-1)
        self.assertEqual({(r['argument_index'],r['slot']) for r in t.kept.values()},{(1,'format')})

    def test_scalar_output_parameter(self):
        t=traced('void helper(int n,int*out) { *out=n; } void root(void*self,int n) { int c; helper(n,&c); memcpy(dst,src,c); }',1)
        self.assertEqual({(r['argument_index'],r['slot'],r['note']) for r in t.kept.values()},
                         {(0,'count','via one helper')})

    def test_method_self_is_not_a_ruby_passed_argument(self):
        t=traced('void root(char*self,int n) { strcpy(dst,self); }',1)
        self.assertEqual(list(t.kept.values()),[])

if __name__=='__main__':
    unittest.main()

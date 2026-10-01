"""Inert syntax fixtures exercise the requested inventory's interpretation."""
import unittest
from call_argument_inventory import Inventory, dedup_key
from catalog import PARSERS, decl_name, text, walk
from entry_catalog import function_parameters

def inventory(source, arity=2, macros=()):
    data = source.encode()
    tree = PARSERS['c'].parse(data)
    functions = {}
    for node in walk(tree.root_node):
        if node.type != 'function_definition':
            continue
        name = decl_name(node.child_by_field_name('declarator'), data)
        functions[name] = dict(id=name, gem='fixture', version='1', file='ext/fixture.c',
            name=name, line=node.start_point.row+1, parameters=function_parameters(node, data),
            static=False, parser='c', source=text(node, data).encode(),
            recovered=node.has_error, extension_groups=['ext'])
    entry = dict(gem='fixture', version='1', ruby_method_name='test', ruby_receiver='klass',
        c_function='root', arity=str(arity), registration='rb_define_method',
        function_expression='root', registration_file='ext/fixture.c', registration_line='1',
        entry_id='fixture:root', extension_groups="['ext']")
    result = Inventory(functions, {('fixture', m) for m in macros}, [entry])
    result.run_root(entry)
    return result

class CallArgumentInventoryTests(unittest.TestCase):
    def test_literal_length_kept_when_source_is_parameter(self):
        result = inventory('void root(void*self,int n,char*s) { memcpy(dst,s,16); }')
        self.assertEqual([(r['argument_index'], r['slot'], r['argument_label']) for r in result.rows],
                         [(1, 'length', 'literal')])

    def test_sizeof_length_and_cast(self):
        result = inventory('void root(void*self,int n,char*s) { memcpy(dst,(char*)s,sizeof(dst)); }')
        self.assertEqual(result.rows[0]['argument_label'], 'sizeof')
        self.assertEqual(result.rows[0]['argument_index'], 1)
        result = inventory('void root(void*self,int n,char*s) { malloc(sizeof(n)); }')
        self.assertEqual(result.rows[0]['argument_label'], 'sizeof')
        self.assertEqual(result.rows[0]['argument_index'], 0)

    def test_local_length_and_macro_argument_occurrence(self):
        result = inventory('void root(void*self,int n,char*s) { int len=RSTRING_LEN(s); memcpy(dst,RSTRING_PTR(s),len); }')
        self.assertEqual(result.rows[0]['argument_label'], 'local')
        self.assertEqual({r['target'] for r in result.hops.values()}, {'RSTRING_LEN', 'RSTRING_PTR'})

    def test_standalone_allocation_requires_no_arithmetic_or_copy(self):
        result = inventory('void root(void*self,int n,char*s) { malloc(n); }')
        self.assertEqual([(r['argument_index'], r['slot']) for r in result.rows], [(0, 'size')])

    def test_helpers_permute_arguments_through_arbitrary_depth(self):
        result = inventory('void leaf(char*p,int count) { memcpy(dst,p,count); }\n'
                           'void middle(int len,char*str) { leaf(str,len); }\n'
                           'void root(void*self,int n,char*s) { middle(n,s); }')
        self.assertEqual({r['argument_index'] for r in result.rows}, {0, 1})
        self.assertEqual({r['hop_count'] for r in result.rows}, {2})
        self.assertEqual({r['path'] for r in result.rows}, {'root -> middle -> leaf'})

    def test_formats_keep_literal_and_parameter_formats(self):
        result = inventory('void root(void*self,int n,char*fmt) { printf("%d",n);\n printf(fmt); }')
        self.assertEqual({(r['argument_index'], r['argument_label']) for r in result.rows},
                         {(0, 'literal'), (1, 'param(fmt,1)')})

    def test_index_store_value_parameter_with_literal_index(self):
        result = inventory('void root(void*self,int n,char*s) { dst[3]=n;\n dst[n]+=1; }')
        self.assertEqual([(r['slot'], r['argument_label']) for r in result.rows],
                         [('index', 'literal'), ('index', 'param(n,0)')])

    def test_function_pointer_hop_is_unresolved(self):
        result = inventory('void leaf(int n) { malloc(n); }\n'
                           'void root(void*self,int n,char*s) { void(*callback)(int)=leaf; callback(n); }')
        self.assertFalse(result.rows)
        self.assertEqual([r['reason'] for r in result.hops.values()], ['function-pointer or member dispatch'])

    def test_macro_hop_is_unresolved_even_with_definition(self):
        result = inventory('void helper(int n) { malloc(n); }\n'
                           'void root(void*self,int n,char*s) { helper(n); }', macros=['helper'])
        self.assertFalse(result.rows)
        self.assertEqual([r['reason'] for r in result.hops.values()], ['unexpanded macro'])

    def test_nested_macro_does_not_map_helper_return_argument(self):
        result = inventory('void helper(int n) { malloc(n); }\n'
                           'void root(void*self,int n,char*s) { helper(NUM2INT(n)); }')
        self.assertFalse(result.rows)
        self.assertIn('NUM2INT', {r['target'] for r in result.hops.values()})
        result = inventory('int identity(int n) { return n; }\n'
                           'void helper(int n) { malloc(n); }\n'
                           'void root(void*self,int n,char*s) { helper(identity(n)); }')
        self.assertFalse(result.rows)

    def test_argv_and_scan_args_positions(self):
        result = inventory('void root(int argc,void**argv,void*self) { void*str; rb_scan_args(argc,argv,"11",&str,&x); printf("%s",str); }', -1)
        self.assertEqual({r['argument_index'] for r in result.rows}, {0})
        result = inventory('void root(int argc,void**argv,void*self) { void*str=argv[2]; printf("%s",str); }', -1)
        self.assertEqual({r['argument_index'] for r in result.rows}, {2})

    def test_self_free_and_aliases_do_not_seed_positions(self):
        result = inventory('void root(char*self,int n,char*s) { free(s); printf(self); char*alias=s; memcpy(dst,alias,10); }')
        self.assertFalse(result.rows)

    def test_unbounded_copy_has_no_length_operand(self):
        result = inventory('void root(void*self,int n,char*s) { strcpy(dst,s); }')
        self.assertFalse(result.rows)

    def test_exact_requested_dedup_key(self):
        result = inventory('void root(void*self,int n,char*s) { snprintf(dst,n,s); }')
        self.assertEqual(len(result.rows), 4)
        self.assertEqual(len({dedup_key(r) for r in result.rows}), 2)

if __name__ == '__main__':
    unittest.main()

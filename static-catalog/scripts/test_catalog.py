"""Check classification boundaries with inert C snippets parsed as text."""
import unittest
from catalog import analyze

def sites(source):
    return analyze(source.encode(), 'c')[0]

def labels(source, callee):
    return [s['labels'] for s in sites(source) if s['callee_or_store'] == callee]

class CatalogBoundaries(unittest.TestCase):
    def test_local_array_and_parameter_with_same_named_struct_field(self):
        source = 'void f(char *dst, char *src, int n) { struct { char dst[8]; } s; memcpy(dst,src,n); }'
        self.assertEqual(labels(source, 'memcpy'), [[]])
        source = 'void f(char *src, int n) { char dst[8]; memcpy(dst,src,n); }'
        self.assertEqual(labels(source, 'memcpy'), [['A']])

    def test_array_parameter_does_not_supply_capacity(self):
        self.assertEqual(labels('void f(char dst[8], char *src, int n) { memcpy(dst,src,n); }', 'memcpy'), [[]])

    def test_visible_bound_takes_precedence(self):
        source = 'void f(char *src,int n) { char dst[8]; memcpy(dst,src,sizeof dst); memcpy(dst,src,8); snprintf(dst,n,"%s",src); }'
        self.assertEqual(labels(source, 'memcpy'), [['F'], ['F']])
        self.assertEqual(labels(source, 'snprintf'), [['F']])

    def test_arithmetic_copy_pair_is_local_and_matches_destination(self):
        source = 'void f(int n,char *src) { char *p=malloc(n+1); memcpy(p,src,n); memcpy(src,p,n); } void g(int n,char *p,char *src) { memcpy(p,src,n); }'
        self.assertEqual(labels(source, 'malloc'), [['B']])
        self.assertEqual(labels(source, 'memcpy'), [['B'], [], []])

    def test_reassignment_breaks_allocation_copy_pair(self):
        source = 'void f(int n,char *src) { char *p=malloc(n+1); p=other(); memcpy(p,src,n); }'
        self.assertEqual(labels(source, 'malloc'), [[]])
        self.assertEqual(labels(source, 'memcpy'), [[]])

    def test_narrowing_requires_local_integer_type(self):
        source = 'void f(uint64_t n,char *src) { char *p=malloc((uint32_t)n); memcpy(p,src,n); }'
        self.assertEqual(labels(source, 'malloc'), [['B']])
        source = 'void f(int n,char *src) { char *p=malloc((int)n); memcpy(p,src,n); }'
        self.assertEqual(labels(source, 'malloc'), [[]])

    def test_nonliteral_format_and_ruby_format_index(self):
        source = 'void f(char *fmt) { printf(fmt); rb_enc_sprintf(enc,fmt); rb_raise(exc,"fixed"); }'
        self.assertEqual(labels(source, 'printf'), [['C']])
        self.assertEqual(labels(source, 'rb_enc_sprintf'), [['C']])
        self.assertEqual(labels(source, 'rb_raise'), [['F']])

    def test_pointer_provenance_and_same_block_free(self):
        source = 'void f(char *p) { char *q=malloc(8); free(q); free(p); free(s->p); char *r=other(); free(r); }'
        self.assertEqual(labels(source, 'free'), [['F'], ['D'], ['D'], ['D']])

    def test_field_assignment_prevents_free_drop(self):
        source = 'void f(void) { char *q=malloc(8); s->p=q; free(q); }'
        self.assertEqual(labels(source, 'free'), [[]])

    def test_index_store_and_immediate_condition(self):
        source = 'void f(char *p,int i,int n) {\n p[i]=0;\n if(i<n)\n p[i]=0;\n *(p+i)=0;\n }'
        self.assertEqual(labels(source, 'p[i] ='), [['E'], []])
        self.assertEqual(labels(source, '*(p + i) ='), [['E']])

    def test_calloc_second_argument_bound(self):
        self.assertEqual(labels('void f(int n) { char *p=calloc(n,sizeof(char)); }', 'calloc'), [['F']])

    def test_comments_and_strings_do_not_create_sites(self):
        source = 'void f(void) { /* free(p); */ char *s="printf(fmt); p[i]=0;"; }'
        self.assertEqual(sites(source), [])

if __name__ == '__main__':
    unittest.main()

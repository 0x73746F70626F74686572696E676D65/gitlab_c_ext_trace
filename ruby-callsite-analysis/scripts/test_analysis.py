import unittest
from analyze import Engine

def run(source,arguments=(0,),method='write',kind='instance',arity=None,wrapper=None):
    api=dict(id='native',owner='Native',method=method,kinds=[kind],arguments=list(arguments),arities=[] if arity is None else [arity])
    e=Engine([api])
    if wrapper:e.index(wrapper.encode(),'@gem/example/lib/example.rb','gem_wrapper')
    e.index(source.encode(),'app/example.rb');e.solve()
    return e,[c for c in e.calls.values() if c['hits'] and not c['receiver_unknown'] and len(set(map(str,c['dispatches'])))==1]

class Tests(unittest.TestCase):
    def test_receiver_and_reassignment(self):
        e,sites=run('class Native; end; n=Native.new; n.write(1); n=Object.new; n.write(2); Other.write(3)')
        self.assertEqual([e.events[c['event']]['expression'] for c in sites],['n.write(1)'])
    def test_empty_method_with_default_parameter(self):
        e,sites=run('class Native; end; class App; def no_body(x=1); end; def go; no_body; Native.new.write(1); end; end')
        self.assertEqual(len(sites),1)
    def test_required_flow_argument(self):
        e,sites=run('class Native; end; n=Native.new; n.write(1); n.write(1,2)',(1,))
        self.assertEqual([e.events[c['event']]['expression'] for c in sites],['n.write(1,2)'])
    def test_constructor_has_no_fake_argument(self):
        e,sites=run('class Native; end; Native.new; Native.new(1)',method='initialize')
        self.assertEqual([e.events[c['event']]['expression'] for c in sites],['Native.new(1)'])
    def test_constant_alias_and_shadow(self):
        e,sites=run('class Native; end; Alias=Native; Alias.new.write(1); Native=Other; Native.new.write(2)')
        self.assertEqual(len(sites),1)
    def test_branch_ambiguous_receiver(self):
        _,sites=run('class Native; end; if unknown; n=Native.new; else; n=Object.new; end; n.write(1)')
        self.assertFalse(sites)
    def test_literal_splat(self):
        e,sites=run('class Native; end; n=Native.new; n.write(*[1,2])',(1,))
        self.assertEqual(sites[0]['hits'][0]['ruby_argument_index'],1)
    def test_unknown_splat_does_not_shift(self):
        _,sites=run('class Native; end; n=Native.new; n.write(*unknown,2)',(0,))
        self.assertFalse(sites)
    def test_keywords_group_as_native_hash(self):
        e,sites=run('class Native; end; n=Native.new; n.write(1, mode: :x)',(1,))
        self.assertEqual(sites[0]['arguments'][1]['kind'],'keywords')
    def test_fixed_arity_failure(self):
        _,sites=run('class Native; end; Native.new.write(1,2)',arity=1)
        self.assertFalse(sites)
    def test_application_override(self):
        _,sites=run('class Native; def write(x); Other.write(x); end; end; Native.new.write(1)')
        self.assertFalse(sites)
    def test_wrapper_preserves_operand_argument(self):
        wrapper='class Native; end; module Public; def self.go(a,b=nil); Native.new.write(b,a); end; end'
        e,sites=run('Public.go(7); Public.go(7,8)',arguments=(0,1),wrapper=wrapper)
        first=next(c for c in sites if e.events[c['event']]['expression']=='Public.go(7)')
        self.assertEqual({h['native_argument_index'] for h in first['hits']},{1})
    def test_inherited_receiver(self):
        _,sites=run('class Native; end; class Child < Native; end; Child.new.write(1)')
        self.assertEqual(len(sites),1)
    def test_factory_override(self):
        _,sites=run('class Native; def self.new; Object.new; end; end; Native.new.write(1)')
        self.assertFalse(sites)
    def test_deep_return_resolution(self):
        methods='\n'.join('def f%d; %s; end'%(i,'Native.new' if i==100 else 'f%d'%(i+1)) for i in range(101))
        e,sites=run('class Native; end; class App; '+methods+'\ndef use; f0.write(1); end; end')
        self.assertEqual(len(sites),1)
    def test_wrapper_internal_receiver_must_resolve(self):
        wrapper='class Native; end; class Other; end; module Public; def self.go(a); if unknown; n=Native.new; else; n=Other.new; end; n.write(a); end; end'
        e,sites=run('Public.go(7)',wrapper=wrapper)
        self.assertFalse(sites)
    def test_unknown_conversion_preserves_argument_taint(self):
        wrapper='class Native; end; module Public; def self.go(a); Native.new.write(a.to_s); end; end'
        e,sites=run('Public.go(unknown)',wrapper=wrapper)
        self.assertEqual(len(sites),1)
        self.assertEqual(sites[0]['hits'][0]['ruby_argument_index'],0)
    def test_unknown_field_assignment_prevents_receiver_claim(self):
        e,sites=run('class Native; end; class Holder; def initialize; @x=Native.new; end; def set(v); @x=v; end; def run; @x.write(1); end; end; h=Holder.new; h.run')
        self.assertFalse(sites)
    def test_known_array_formal_splat(self):
        wrapper='class Native; end; module Public; def self.go(values); Native.new.write(*values); end; end'
        e,sites=run('Public.go([1,2])',arguments=(1,),wrapper=wrapper)
        self.assertEqual(len(sites),1)
        self.assertEqual(sites[0]['hits'][0]['ruby_argument_index'],0)
    def test_field_array_does_not_borrow_unrelated_formal(self):
        wrapper='class Native; end; class Public; def initialize(v); @values=[v]; end; def go(unused); Native.new.write(*@values); end; end'
        e,sites=run('p=Public.new(123); p.go(456)',wrapper=wrapper)
        self.assertFalse(sites)
    def test_other_gem_does_not_replace_ruby_wrapper(self):
        api=dict(id='native',gem='other_gem',owner='Public',method='go',kinds=['singleton'],arguments=[0])
        e=Engine([api]);e.index(b'module Public; def self.go(x); x; end; end','@gem/ruby_gem@1/lib/public.rb','gem_wrapper');e.index(b'Public.go(1)','app/use.rb');e.solve()
        self.assertFalse(any(c['hits'] for c in e.calls.values()))
    def test_arbitrary_read_has_no_string_contract(self):
        e,sites=run('class Native; end; Other.read.write(1)')
        self.assertFalse(sites)
    def test_bound_helper_receiver(self):
        e,sites=run('class Native; end; class App; def use(io); io.write(1); end; def call; use(Native.new); end; end')
        self.assertEqual(len(sites),1)

if __name__=='__main__':unittest.main()

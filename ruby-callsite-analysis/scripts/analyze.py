#!/usr/bin/env python3
"""Static Ruby receiver/argument analysis joined to saved native taint witnesses."""
import argparse,collections,dataclasses,gzip,hashlib,json,re,subprocess,sys,tarfile,io,pickle,os
from pathlib import Path
import tree_sitter,tree_sitter_ruby

PARSER=tree_sitter.Parser(tree_sitter.Language(tree_sitter_ruby.language()))
CONSTANT=re.compile(r'^(?:::)?[A-Z]\w*(?:::[A-Z]\w*)*$')
CORE={'rb_cIO':'IO','rb_cString':'String','rb_cArray':'Array','rb_cHash':'Hash','rb_cObject':'Object','rb_cClass':'Class','rb_cModule':'Module','rb_mKernel':'Kernel','rb_cInteger':'Integer','rb_cNumeric':'Numeric','rb_cTime':'Time','rb_cRegexp':'Regexp'}
TRANSFERS={'to_s':'String','to_str':'String','to_i':'Integer','to_int':'Integer','to_f':'Float','to_a':'Array','to_ary':'Array','to_h':'Hash','to_hash':'Hash','read':'String','readpartial':'String','gets':'String','encode':'String','force_encoding':'String','scrub':'String','strip':'String','gsub':'String','sub':'String','unpack':'Array','bytes':'Array','pack':'String'}

def txt(n):return n.text.decode('utf-8','replace') if n else ''
def fld(n,k):return n.child_by_field_name(k) if n else None
def walk(n):
    if n:
        todo=[n]
        while todo:
            x=todo.pop();yield x;todo.extend(reversed(x.named_children))
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def ident(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()
def rows(p):
    with p.open() as stream:
        for line in stream:
            if line.strip():yield json.loads(line)
def jsonl(p,rs):
    with p.open('w') as stream:
        for r in rs:stream.write(json.dumps(r,sort_keys=True,separators=(',',':'))+'\n')

@dataclasses.dataclass
class V:
    types:dict=dataclasses.field(default_factory=dict)
    unknown:bool=False
    deps:frozenset=dataclasses.field(default_factory=frozenset)
    items:object=None
    literal:object=None
    def signature(self):return (tuple(sorted(self.types)),self.unknown,self.deps,tuple(x.signature() for x in self.items) if self.items is not None else None,self.literal)

def join(*vs):
    vs=tuple(v for v in vs if v.types or v.unknown or v.deps or v.items is not None or v.literal is not None)
    t={}
    for v in vs:
        for k,p in v.types.items():
            if k not in t or (len(p),p)<(len(t[k]),t[k]):t[k]=p
    literals=[v.literal for v in vs];lit=literals[0] if literals and all(x==literals[0] for x in literals) else None
    items=None
    if vs and all(v.items is not None for v in vs) and len({len(v.items) for v in vs})==1:
        items=tuple(join(*(v.items[i] for v in vs)) for i in range(len(vs[0].items)))
    return V(t,any(v.unknown for v in vs),frozenset().union(*(v.deps for v in vs)),items,lit)
def relabel(v,deps):
    return dataclasses.replace(v,deps=deps,items=tuple(relabel(item,deps) for item in v.items) if v.items is not None else None)
def nested_deps(v):
    return v.items is not None and any(item.deps or nested_deps(item) for item in v.items)
def typed(kind,owner,event,deps=frozenset()):return V({(kind,owner):(event,)},False,deps)
UNKNOWN=V(unknown=True)

class Engine:
    def __init__(self,apis):
        self.native=collections.defaultdict(list)
        for a in apis:
            for k in a['kinds']:self.native[(a['owner'],k,a['method'])].append(a)
        self.known={a['owner'] for a in apis};self.units={};self.methods=collections.defaultdict(list);self.classes={}
        self.aliases={};self.class_fields={};self.constants={};self.inputs={};self.returns={};self.effects={};self.sinks={}
        self.reverse=collections.defaultdict(set);self.events={};self.files=[];self.calls={};self.evaluations=0
        self.watchers=collections.defaultdict(set)
        self.sources={};self.trees=collections.OrderedDict();self.candidate_names=None
        self.pending=collections.deque();self.queued=set();self.active=None;self.changed=False
    def event(self,file,n,kind='expression',**extra):
        e=dict(file=file,line=n.start_point.row+1,column=n.start_point.column+1,end_line=n.end_point.row+1,byte_start=n.start_byte,byte_end=n.end_byte,kind=kind,expression=txt(n),**extra)
        key=ident(e);self.events[key]=e;return key
    def qualify(self,name,owner):
        if name.startswith('::'):return name[2:]
        return owner+'::'+name if owner else name
    def resolve(self,name,owner):
        if name.startswith('::'):return name[2:]
        parts=owner.split('::') if owner else []
        for i in range(len(parts),-1,-1):
            c='::'.join(parts[:i]+[name])
            if c in self.classes or c in self.known or c in self.constants:return c
        return name
    def index(self,source,file,scope='gitlab',metadata=None):
        getattr(self,'lookup_cache',{}).clear();self.sources[file]=source;tree=PARSER.parse(source);indexed=[];self.files.append(dict(metadata or {},file=file,scope=scope,sha256=hashlib.sha256(source).hexdigest(),bytes=len(source),parser_error=tree.root_node.has_error))
        def add(node,body,owner,name,kind,top=False):
            uid=file+':'+str(node.start_byte)+':'+kind+':'+name
            params=[]
            for p in (fld(node,'parameters').named_children if fld(node,'parameters') else []):
                if p.type=='block_parameter':continue
                name_=txt(fld(p,'name')) or txt(p)
                offset=sum(isinstance(x[1],int) for x in params)
                label='kw:'+name_ if p.type=='keyword_parameter' else 'rest:'+str(offset) if p.type=='splat_parameter' else 'kwrest' if p.type=='hash_splat_parameter' else 'forward:'+str(offset) if p.type=='forward_parameter' else offset
                params.append((name_,label,p.type,fld(p,'value')))
            u=dict(id=uid,file=file,node=node,body=body,owner=owner,name=name,kind=kind,params=params,scope=scope,top=top)
            self.units[uid]=u;indexed.append(uid);self.returns[uid]=V();self.effects[uid]={};self.sinks[uid]={}
            if not top:self.methods[(owner,kind,name)].append(uid)
            return uid
        def visit(n,owner='',mode='instance'):
            if n.type in {'class','module'}:
                name=self.qualify(txt(fld(n,'name')),owner);self.known.add(name)
                self.classes.setdefault(name,dict(parents=[],includes=[],extends=[],extend_self=False,module_function=False,aliases={},namespace_kind=n.type))
                parent=fld(n,'superclass')
                if parent and parent.named_children:self.classes[name]['parents'].append((txt(parent.named_children[0]),owner))
                body=fld(n,'body');add(n,body,name,'<class-body>','singleton',True)
                for c in (body.named_children if body else []):visit(c,name)
                return
            if n.type=='singleton_class':
                value=txt(fld(n,'value'));o=owner if value=='self' else self.resolve(value,owner)
                for c in (fld(n,'body').named_children if fld(n,'body') else []):visit(c,o,'singleton')
                return
            if n.type in {'method','singleton_method'}:
                o=owner;k=mode
                if n.type=='singleton_method':
                    value=txt(fld(n,'object'));o=owner if value=='self' else self.resolve(value,owner);k='singleton'
                add(n,fld(n,'body'),o,txt(fld(n,'name')),k);return
            if n.type=='call' and owner:
                name=txt(fld(n,'method'));aa=fld(n,'arguments');vals=[txt(c) for c in aa.named_children] if aa else []
                cls=self.classes.get(owner)
                if cls:
                    if name in {'include','prepend','extend'}:
                        for v in vals:
                            if v=='self' and name=='extend':cls['extend_self']=True
                            elif CONSTANT.fullmatch(v):cls['extends' if name=='extend' else 'includes'].append((v,owner))
                    if name=='module_function':cls['module_function']=True
                    if name=='alias_method' and len(vals)>=2:cls['aliases'][vals[0].strip(':\'"')]=vals[1].strip(':\'"')
                    if name in {'attr_reader','attr_accessor'}:
                        for v in vals:
                            attr=v.strip(':\'"');self.aliases[(owner,mode,attr)]=('@'+attr)
            for c in n.named_children:visit(c,owner,mode)
        add(tree.root_node,tree.root_node,'','<file-body>','singleton',True);visit(tree.root_node)
        # Persist coordinates, not Node objects: Nodes retain entire native parse trees.
        def loc(n):return (n.start_byte,n.end_byte,n.type) if n else None
        for uid in indexed:
            u=self.units[uid];u['node']=loc(u['node']);u['body']=loc(u['body'])
            u['params']=[(name,label,kind,loc(default)) for name,label,kind,default in u['params']]
    def materialize(self,unit):
        if not isinstance(unit['node'],tuple):return unit
        file=unit['file'];tree=self.trees.pop(file,None)
        if tree is None:tree=PARSER.parse(self.sources[file])
        self.trees[file]=tree
        if len(self.trees)>64:self.trees.popitem(last=False)
        def node(loc):
            if loc is None:return None
            start,end,kind=loc;n=tree.root_node.descendant_for_byte_range(start,max(start,end-1))
            while n and (n.start_byte!=start or n.end_byte!=end or n.type!=kind):n=n.parent
            if n is None:raise ValueError((file,loc))
            return n
        return dict(unit,node=node(unit['node']),body=node(unit['body']),params=[(name,label,kind,node(default)) for name,label,kind,default in unit['params']])
    def lineage(self,owner,kind,seen=None):
        seen=set() if seen is None else seen
        if (owner,kind) in seen:return []
        seen.add((owner,kind));result=[(owner,kind)];c=self.classes.get(owner,{})
        for name,lex in reversed(c.get('includes' if kind=='instance' else 'extends',[])):result+=self.lineage(self.resolve(name,lex),'instance',seen)
        if kind=='singleton' and (c.get('extend_self') or c.get('module_function')):result.append((owner,'instance'))
        for name,lex in c.get('parents',[]):result+=self.lineage(self.resolve(name,lex),kind,seen)
        if kind=='instance' and owner=='File':result+=self.lineage('IO',kind,seen)
        if kind=='instance' and owner not in {'Object','Kernel'}:result+=self.lineage('Object',kind,seen)
        if kind=='instance' and owner=='Object':result.append(('Kernel','instance'))
        return result
    def lookup(self,owner,kind,name):
        cache=getattr(self,'lookup_cache',None)
        if cache is None:self.lookup_cache=cache={}
        key=(owner,kind,name)
        if key not in cache:
            if len(cache)>100000:cache.clear()
            cache[key]=self.lookup_uncached(owner,kind,name)
        return cache[key]
    def lookup_uncached(self,owner,kind,name):
        for o,k in self.lineage(owner,kind):
            c=self.classes.get(o,{})
            n=c.get('aliases',{}).get(name,name)
            ruby=self.methods.get((o,k,n),[]);native=self.native.get((o,k,n),[])
            app=[u for u in ruby if self.units[u]['scope']=='gitlab' and not self.units[u]['file'].startswith(('spec/','ee/spec/','qa/'))]
            if app:return 'ruby',app,(o,k,n)
            # A wrapper from another gem is a real Ruby implementation, not a
            # bootstrap stub for every installed C extension sharing the name.
            if native and ruby:
                wrapper_gems={self.units[u]['file'].split('/')[1].split('@')[0] for u in ruby if self.units[u]['scope']=='gem_wrapper'}
                native=[a for a in native if a['gem'] in wrapper_gems]
            if native:return 'native',native,(o,k,n)
            if ruby:return 'ruby',ruby,(o,k,n)
            if (o,k,n) in self.aliases:return 'field',self.aliases[(o,k,n)],(o,k,n)
        return 'unknown',None,(owner,kind,name)
    def enqueue(self,u):
        if u not in self.queued:self.queued.add(u);self.pending.append(u)
    def wake_all(self):
        for u in self.units:self.enqueue(u)
    def wake_key(self,key):
        for u in sorted(self.watchers[key]):self.enqueue(u)
    def compact_events(self):
        live=set();visited=set()
        def value(v):
            if id(v) in visited:return
            visited.add(id(v))
            for proof in v.types.values():live.update(proof)
            if v.items is not None:
                for item in v.items:value(item)
        for mapping in (self.inputs,self.returns,self.constants,self.class_fields):
            for v in mapping.values():value(v)
        for effects in self.effects.values():
            for v in effects.values():value(v)
        for sinks in self.sinks.values():
            for path in sinks.values():live.update(path)
        for c in self.calls.values():
            live.add(c['event']);live.update(c['receiver_proof'])
            for h in c['hits']:live.update(h['path'])
        pending=list(live)
        while pending:
            event=pending.pop();origin=self.events[event].get('call_event')
            if origin and origin not in live:live.add(origin);pending.append(origin)
        self.events={event:self.events[event] for event in live}
    def checkpoint(self):
        path=getattr(self,'checkpoint_path',None)
        if not path:return
        self.compact_events()
        cache=self.trees;self.trees=collections.OrderedDict()
        try:
            temp=Path(str(path)+'.tmp')
            with temp.open('wb') as stream:pickle.dump(self,stream,protocol=5)
            os.replace(temp,path)
        finally:self.trees=cache
    def solve(self):
        if getattr(self,'initial_closed',False):self.close_tail();return
        self.candidate_names={key[2] for key in self.native}|{u['name'] for u in self.units.values() if u['scope']=='gem_wrapper'}|{'new'}
        if not getattr(self,'started',False):self.wake_all();self.started=True
        while self.pending:
            uid=self.pending.popleft();self.queued.discard(uid);self.active=uid;ctx=Context(self,self.units[uid]);result=ctx.run()
            old=self.returns[uid];new=join(old,result)
            signature=(new.signature(),ctx.effect_signature(),ctx.sink_signature())
            prior=(old.signature(),tuple(sorted((k,v.signature()) for k,v in self.effects[uid].items())),tuple(sorted(self.sinks[uid].items(),key=str)))
            self.returns[uid]=new;self.effects[uid]=ctx.effects;self.sinks[uid]=ctx.sinks
            if signature!=prior:
                for caller in sorted(self.reverse[uid]):self.enqueue(caller)
            self.evaluations+=1
            if self.evaluations%25000==0:
                print('Ruby fixed point:',self.evaluations,'evaluations;',len(self.pending),'queued',flush=True);self.checkpoint()
        print('Ruby fixed point closed:',self.evaluations,flush=True);self.initial_closed=True
        # Unbound formals cannot prove a receiver. Seed these as unknown and close again.
        changed=False
        for u,unit in self.units.items():
            for i,p in enumerate(unit['params']):
                if (u,i) not in self.inputs:self.inputs[(u,i)]=UNKNOWN;self.enqueue(u);changed=True
        if changed:
            self.close_tail()
    def close_tail(self):
        while self.pending:
            uid=self.pending.popleft();self.queued.discard(uid);self.active=uid;ctx=Context(self,self.units[uid]);result=ctx.run();old=self.returns[uid];new=join(old,result)
            signature=(new.signature(),ctx.effect_signature(),ctx.sink_signature());prior=(old.signature(),tuple(sorted((k,v.signature()) for k,v in self.effects[uid].items())),tuple(sorted(self.sinks[uid].items(),key=str)))
            self.returns[uid]=new;self.effects[uid]=ctx.effects;self.sinks[uid]=ctx.sinks
            if signature!=prior:
                for caller in sorted(self.reverse[uid]):self.enqueue(caller)
            self.evaluations+=1
            if self.evaluations%25000==0:
                print('Ruby closure:',self.evaluations,'evaluations;',len(self.pending),'queued',flush=True);self.checkpoint()

class Context:
    def __init__(self,engine,unit):
        unit=engine.materialize(unit)
        self.e=engine;self.u=unit;self.env={};self.returned=V();self.effects=dict(engine.effects[unit['id']]);self.sinks={};self.locals=set()
        for i,(name,label,kind,default) in enumerate(unit['params']):
            v=engine.inputs.get((unit['id'],i),V());items=tuple(relabel(x,frozenset({label})) for x in v.items) if v.items is not None else None
            if kind=='splat_parameter' and v.items is not None:items=tuple(relabel(x,frozenset({int(label.split(':')[1])+j})) for j,x in enumerate(v.items))
            self.env[name]=dataclasses.replace(v,deps=frozenset({label}),items=items)
        for n in walk(unit['body']):
            if n.type=='assignment' and fld(n,'left') and fld(n,'left').type=='identifier':self.locals.add(txt(fld(n,'left')))
    def event(self,n,kind='expression',**extra):return self.e.event(self.u['file'],n,kind,owner=self.u['owner'],unit=self.u['id'],**extra)
    def effect_signature(self):return tuple(sorted((k,v.signature()) for k,v in self.effects.items()))
    def sink_signature(self):return tuple(sorted(self.sinks.items(),key=str))
    def path(self,v,event):return dataclasses.replace(v,types={k:p+(event,) for k,p in v.types.items()})
    def run(self):
        result=self.eval(self.u['body']);return join(self.returned,result)
    def constant(self,name,event):
        parts=self.u['owner'].split('::') if self.u['owner'] else []
        for i in range(len(parts),-1,-1):self.e.watchers[('constant','::'.join(parts[:i]+[name.lstrip(':')]))].add(self.u['id'])
        resolved=self.e.resolve(name,self.u['owner']);v=self.e.constants.get(resolved)
        if resolved in self.env:return self.path(self.env[resolved],event)
        return self.path(v,event) if v else typed('singleton',resolved,event)
    def eval(self,n):
        if n is None:return V()
        t=n.type
        if t in {'method','singleton_method','singleton_class','comment'}:return V()
        if t in {'program','body_statement','block_body','then','else','begin','parenthesized_statements'}:
            value=V()
            for c in n.named_children:
                value=self.eval(c)
                if c.type=='return':break
            return value
        value_nodes={'class','module','constant','scope_resolution','self','identifier','instance_variable','class_variable','global_variable','string','string_content','heredoc_body','simple_symbol','hash_key_symbol','integer','float','true','false','nil','regex','array','hash','pair','assignment','operator_assignment'}
        event=self.event(n) if t in value_nodes else None
        s=txt(n) if t in value_nodes-{'class','module','array','hash','pair','assignment','operator_assignment','self'} else ''
        if t in {'class','module'}:
            key=self.e.qualify(txt(fld(n,'name')),self.u['owner']);self.env[key]=typed('singleton',key,event);return V()
        if t in {'method','singleton_method','singleton_class','comment'}:return V()
        if t in {'program','body_statement','block_body','then','else','begin','parenthesized_statements'}:
            value=V()
            for c in n.named_children:
                value=self.eval(c)
                if c.type=='return':break
            return value
        if t=='return':
            value=join(*(self.eval(c) for c in n.named_children));self.returned=join(self.returned,value);return value
        if t in {'constant','scope_resolution'}:return self.constant(s,event)
        if t=='self':return typed(self.u['kind'],self.u['owner'] or 'Object',event)
        if t in {'identifier','instance_variable','class_variable','global_variable'}:
            if s in self.env:return self.path(self.env[s],event)
            if t!='identifier':
                key=(self.u['owner'],self.u['kind'],s);self.e.watchers[('field',key)].add(self.u['id'])
                return self.path(self.e.class_fields.get(key,V()),event)
            if s in self.locals:return UNKNOWN
            return self.call(n,s,None,[])
        if t in {'string','string_content','heredoc_body','simple_symbol','hash_key_symbol','integer','float','true','false','nil','regex'}:
            owner={'integer':'Integer','float':'Float','simple_symbol':'Symbol','hash_key_symbol':'Symbol','regex':'Regexp','true':'TrueClass','false':'FalseClass','nil':'NilClass'}.get(t,'String')
            v=typed('instance',owner,event)
            if t in {'simple_symbol','hash_key_symbol'}:v.literal=s.strip(':\'"')
            elif t=='string' and not any(x.type=='interpolation' for x in walk(n)):v.literal=s[1:-1]
            elif t=='integer':
                try:v.literal=int(s)
                except ValueError:pass
            for c in n.named_children:
                if c.type=='interpolation':v.deps|=self.eval(c).deps
            return v
        if t=='array':
            items=tuple(self.eval(c) for c in n.named_children);v=typed('instance','Array',event,join(*items).deps);v.items=items;return v
        if t in {'hash','pair'}:
            values=[self.eval(c) for c in n.named_children];return typed('instance','Hash',event,join(*values).deps)
        if t in {'assignment','operator_assignment'}:
            value=self.eval(fld(n,'right'));left=fld(n,'left');name=txt(left);value=self.path(value,event)
            if left and left.type=='call':
                return self.call(left,txt(fld(left,'method'))+'=',fld(left,'receiver'),[(fld(n,'right'),value,'positional')])
            if left and left.type=='element_reference':
                return self.call(left,'[]=',fld(left,'object'),self.arguments(left)+[(fld(n,'right'),value,'positional')])
            if left and left.type=='constant' or left and left.type=='scope_resolution':
                key=(self.e.resolve(txt(fld(left,'scope')),self.u['owner'])+'::'+txt(fld(left,'name'))) if left.type=='scope_resolution' else self.e.qualify(name,self.u['owner'])
                self.env[key]=value
                prior=self.e.constants.get(key,V());new=join(prior,value)
                if new.signature()!=prior.signature():self.e.constants[key]=new;getattr(self.e,'lookup_cache',{}).clear();self.e.wake_key(('constant',key))
            elif left and left.type in {'instance_variable','class_variable','global_variable'}:
                key=(self.u['owner'],self.u['kind'],name);self.effects[name]=value
                if True:
                    prior=self.e.class_fields.get(key,V());new=join(prior,relabel(value,frozenset()))
                    if new.signature()!=prior.signature():self.e.class_fields[key]=new;self.e.wake_key(('field',key))
            else:self.env[name]=value
            return value
        if t in {'if','unless','conditional','if_modifier','unless_modifier'}:
            self.eval(fld(n,'condition'));before=dict(self.env);a=self.eval(fld(n,'consequence') or fld(n,'body'));sa=dict(self.env);self.env=dict(before);b=self.eval(fld(n,'alternative'));sb=dict(self.env)
            self.env={k:join(sa.get(k,UNKNOWN),sb.get(k,UNKNOWN)) for k in sorted(set(sa)|set(sb))};return join(a,b)
        if t in {'while','until','for'}:
            self.eval(fld(n,'condition'));old={};result=V()
            while True:
                before=dict(self.env);result=join(result,self.eval(fld(n,'body')))
                self.env={k:join(before.get(k,UNKNOWN),self.env.get(k,UNKNOWN)) for k in sorted(set(before)|set(self.env))}
                signature={k:v.signature() for k,v in self.env.items()}
                if signature==old:break
                old=signature
            return result
        if t=='call':return self.call(n,txt(fld(n,'method')),fld(n,'receiver'),self.arguments(n))
        if t=='element_reference':return self.call(n,'[]',fld(n,'object'),self.arguments(n))
        if t=='binary':
            left=fld(n,'left');right=fld(n,'right');op=txt(fld(n,'operator'));return self.call(n,op,left,[(right,self.eval(right),'positional')])
        if t in {'block','do_block'}:return self.eval(fld(n,'body'))
        return join(*(self.eval(c) for c in n.named_children))
    def arguments(self,n):
        if n.type=='call' and fld(n,'arguments') is None:return []
        aa=fld(n,'arguments');nodes=aa.named_children if aa else [c for c in n.named_children if c!=fld(n,'object')]
        out=[];keywords=[]
        for a in nodes:
            if a.type=='pair':keywords.append(a);continue
            if a.type in {'block_argument'}:continue
            if a.type=='forward_argument':out.append((a,UNKNOWN,'unknown_splat'));continue
            if a.type=='splat_argument':
                inner=a.named_children[0] if a.named_children else None;v=self.eval(inner)
                if v.items is not None:out.extend((inner,item,'expanded_splat') for item in v.items)
                else:out.append((a,v,'unknown_splat'))
            elif a.type=='hash_splat_argument':keywords.append(a)
            else:out.append((a,self.eval(a),'positional'))
        if keywords:out.append((keywords,typed('instance','Hash',self.event(keywords[0]),join(*(self.eval(x) for x in keywords)).deps),'keywords'))
        return out
    def supplied(self,actuals,position):
        # A dynamic splat can shift all later positions; only the guaranteed prefix is positional evidence.
        prefix=[]
        for a in actuals:
            if a[2]=='unknown_splat':break
            prefix.append(a)
        if position=='*':return [(i,a) for i,a in enumerate(prefix)]
        if isinstance(position,str) and position.startswith(('rest:','forward:')):return [(i,a) for i,a in enumerate(prefix) if i>=int(position.split(':')[1])]
        if position=='kwrest':return [(i,a) for i,a in enumerate(prefix) if a[2]=='keywords']
        if isinstance(position,int):return [(position,prefix[position])] if position<len(prefix) else []
        if isinstance(position,str) and position.startswith('kw:'):
            for i,(node,v,k) in enumerate(prefix):
                if k=='keywords':
                    for pair in node:
                        if pair.type=='pair' and txt(fld(pair,'key')).strip(':\'"')==position[3:]:return [(i,(fld(pair,'value'),self.eval(fld(pair,'value')),'keyword'))]
        return []
    def bind(self,target,actuals,event,sink_allowed=True):
        unit=self.e.materialize(self.e.units[target]);self.e.reverse[target].add(self.u['id']);position=0
        for i,(name,label,kind,default) in enumerate(unit['params']):
            present=self.supplied(actuals,label)
            if kind=='splat_parameter':
                value=typed('instance','Array',event);value.items=tuple(a[1][1] for a in present)
            elif kind in {'hash_splat_parameter','forward_parameter'}:value=join(*(a[1][1] for a in present))
            elif present:value=present[0][1][1]
            elif default is not None:value=self.eval(default)
            else:value=UNKNOWN if kind not in {'splat_parameter','hash_splat_parameter'} else V()
            value=self.path(relabel(value,frozenset()),event)
            prior=self.e.inputs.get((target,i),V());new=join(prior,value)
            if new.signature()!=prior.signature():self.e.inputs[(target,i)]=new;self.e.enqueue(target)
        result=self.e.returns[target];deps=set()
        for label in sorted(result.deps,key=str):
            for _,a in self.supplied(actuals,label):deps.update(a[1].deps)
        for field,v in self.e.effects[target].items():
            substituted=set()
            for label in sorted(v.deps,key=str):
                for _,a in self.supplied(actuals,label):substituted.update(a[1].deps)
            key=(unit['owner'],unit['kind'],field);updated=dataclasses.replace(v,deps=frozenset(substituted))
            if True:
                prior=self.e.class_fields.get(key,V());new=join(prior,relabel(updated,frozenset()))
                if new.signature()!=prior.signature():self.e.class_fields[key]=new;self.e.wake_key(('field',key))
        transferred=[]
        if not sink_allowed or unit['scope']!='gem_wrapper':return dataclasses.replace(self.path(result,event),deps=frozenset(deps)),transferred
        for (api,native_argument,label),path in sorted(self.e.sinks[target].items(),key=lambda x:str(x[0])):
            for actual_index,a in self.supplied(actuals,label):
                evidence=dict(self.e.events[event],kind='ruby_argument_binding',callee=target,callee_argument=label,actual_index=actual_index,call_event=event)
                binding=ident(evidence);self.e.events[binding]=evidence
                for dep in sorted(a[1].deps,key=str):
                    key=(api,native_argument,dep);candidate=(binding,)+path
                    if key not in self.sinks or (len(candidate),candidate)<(len(self.sinks[key]),self.sinks[key]):self.sinks[key]=candidate
                transferred.append(dict(api_group=api,native_argument_index=native_argument,ruby_argument_index=actual_index,path=[binding,*path],via='ruby_wrapper'))
        return dataclasses.replace(self.path(result,event),deps=frozenset(deps)),transferred
    def call(self,n,name,receiver,actuals):
        event=self.event(n,'call',method=name);v=self.eval(receiver) if receiver else typed(self.u['kind'] if self.u['owner'] else 'instance',self.u['owner'] or 'Object',event)
        if name in {'send','public_send','__send__'} and actuals and actuals[0][1].literal:
            name=actuals[0][1].literal;actuals=actuals[1:]
        # Apply the same receiver certainty rule to internal wrapper edges.
        resolved_dispatches=[]
        for kind,owner in sorted(v.types):
            lookup,payload,dispatch=self.e.lookup(owner,kind,name)
            if name=='new' and kind=='singleton' and lookup=='unknown' and self.e.classes.get(owner,{}).get('namespace_kind')!='module' and owner in self.e.known:
                lookup,payload,dispatch=self.e.lookup(owner,'instance','initialize')
            resolved_dispatches.append((lookup,dispatch))
        sink_allowed=bool(v.types) and not v.unknown and len(set(map(str,resolved_dispatches)))==1
        results=[];proofs=[];native_hits=[];dispatches=[]
        for (kind,owner),proof in sorted(v.types.items()):
            lookup,payload,dispatch=self.e.lookup(owner,kind,name);dispatches.append((lookup,dispatch));proofs.extend(proof)
            namespace=self.e.classes.get(owner,{}).get('namespace_kind')
            constructor=name=='new' and kind=='singleton' and lookup=='unknown' and namespace!='module' and owner in self.e.known
            if constructor:
                lookup,payload,dispatch=self.e.lookup(owner,'instance','initialize');dispatches[-1]=(lookup,dispatch)
            if lookup=='native':
                for api in payload if sink_allowed else []:
                    fixed=api.get('arities',[])
                    if fixed and all(x>=0 for x in fixed) and (any(a[2]=='unknown_splat' for a in actuals) or len(actuals) not in fixed):continue
                    if api.get('private') and receiver is not None and txt(receiver)!='self' and txt(fld(n,'method')) not in {'send','__send__'}:continue
                    for position in api['arguments']:
                        for index,a in self.supplied(actuals,position):
                            for dep in sorted(a[1].deps,key=str):
                                key=(api['id'],position,dep);path=(event,)
                                if key not in self.sinks or (len(path),path)<(len(self.sinks[key]),self.sinks[key]):self.sinks[key]=path
                            native_hits.append(dict(api_group=api['id'],native_argument_index=position,ruby_argument_index=index,path=[event],via='native_direct'))
                results.append(typed('instance',owner,event) if constructor else V(unknown=True))
            elif lookup=='ruby':
                for target in payload:
                    result,hits=self.bind(target,actuals,event,sink_allowed);results.append(typed('instance',owner,event) if constructor else result);native_hits+=hits
            elif lookup=='field':
                key=(dispatch[0],dispatch[1],payload);self.e.watchers[('field',key)].add(self.u['id']);results.append(self.e.class_fields.get(key,V()))
            elif constructor:results.append(typed('instance',owner,event))
            else:results.append(UNKNOWN)
        if name=='const_set' and actuals and actuals[0][1].literal and len(actuals)>1:
            for (kind,owner) in v.types:
                if kind=='singleton':
                    key=owner+'::'+actuals[0][1].literal;prior=self.e.constants.get(key,V());new=join(prior,actuals[1][1])
                    if new.signature()!=prior.signature():self.e.constants[key]=new;getattr(self.e,'lookup_cache',{}).clear();self.e.wake_key(('constant',key))
        if name in TRANSFERS and not v.unknown and v.types and all(d[0]=='unknown' for d in dispatches) and all(owner in ({'IO','File','StringIO'} if name in {'read','readpartial','gets'} else {'Array'} if name=='pack' else {'String'} if name in {'encode','force_encoding','scrub','strip','gsub','sub','unpack','bytes'} else {'Object','String','Symbol','Integer','Float','Numeric','Array','Hash','NilClass','TrueClass','FalseClass'} if name in {'to_s','to_str','to_i','to_int','to_f','to_a','to_ary','to_h','to_hash'} else set()) for kind,owner in v.types):results=[typed('instance',TRANSFERS[name],event,join(v,*(a[1] for a in actuals)).deps)]
        if name in {'dup','clone','freeze','itself','tap'} and all(d[0]=='unknown' for d in dispatches):results=[v]
        if name=='[]' and any(owner in {'String','Array','Hash'} for kind,owner in v.types):results.append(V(unknown=True,deps=join(v,*(a[1] for a in actuals)).deps))
        block=fld(n,'block')
        if block:
            saved=dict(self.env);params=fld(block,'parameters');names=[txt(c) for c in params.named_children] if params else []
            for p in names:self.env[p]=v if name in {'tap','then','yield_self'} else UNKNOWN
            self.eval(fld(block,'body'));self.env=saved
        if self.u['scope']=='gitlab' and (self.e.candidate_names is None or name in self.e.candidate_names):
            record=dict(event=event,unit=self.u['id'],receiver_expression=txt(receiver) or 'self',receiver_types=sorted([list(k) for k in v.types]),receiver_unknown=v.unknown or not v.types,
                receiver_proof=list(dict.fromkeys(proofs)),dispatches=dispatches,method=name,arguments=[dict(index=i,kind=k,expression=', '.join(txt(x) for x in node) if isinstance(node,list) else txt(node),types=sorted([list(x) for x in val.types])) for i,(node,val,k) in enumerate(actuals)],hits=native_hits)
            self.e.calls[event]=record
        result=join(*results) if results else UNKNOWN
        # Unknown callees may return a value influenced by supplied inputs; this
        # preserves taint without claiming a receiver or a concrete return type.
        if result.unknown:result=dataclasses.replace(result,deps=result.deps|join(v,*(a[1] for a in actuals)).deps)
        return result

def catalogue(repo,native_data,lock,namespace_symbols=None):
    versions=dict(re.findall(r'^    ([\w.-]+) \(([^ )]+)\)',lock,re.M));gemrows={r['gem_id']:r for r in rows(native_data/'gems.jsonl')};owners=collections.defaultdict(set)
    registration_rows={r['registration_id']:r for r in rows(native_data/'c_registrations.jsonl')};arities=collections.defaultdict(set)
    for r in rows(native_data/'ruby_native_registrations.jsonl'):
        g=gemrows[r['gem_id']]
        if r.get('owner_candidate_count')==1 and CONSTANT.fullmatch(r.get('namespace','')):
            for k in r.get('kinds',[]):
                key=(g['name'],g['version'],r['namespace'],r['method'],k);owners[(g['name'],g['version'],r['method'],k)].add(r['namespace'])
                try:arities[key].add(int(registration_rows[r['registration_id']]['arity']))
                except (KeyError,TypeError,ValueError):pass
    normalizations=[];grouped={};all_flows=[];active=[]
    layout=json.loads((repo/'argument-taint-analysis/results/gem-api-memory-flow-files.json').read_text())
    for part in layout['gem-api-memory-flows']['parts']:
        path=repo/'argument-taint-analysis/results'/part['path'];assert digest(path)==part['sha256']
        for r in rows(path):
            flowid=ident(r);r['flow_id']=flowid;all_flows.append(r)
            version=versions.get(r['gem']);version_ok=version==r['version'] or version and version.startswith(r['version']+'-')
            if not version_ok:continue
            registration=r['registration'];kinds=['singleton','instance'] if registration=='rb_define_module_function' else ['instance'] if registration=='rb_define_global_function' else ['singleton'] if registration=='rb_define_singleton_method' else ['instance']
            owner=CORE.get(r['receiver'],r['receiver']);resolution='recorded_receiver'
            if not CONSTANT.fullmatch(owner) and namespace_symbols:
                prefix,*suffix=owner.split('::');names=namespace_symbols.get((r['gem'],r['version'],prefix),set())
                if len(names)==1:owner='::'.join([next(iter(names)),*suffix]);resolution='saved_c_namespace_variable'
            if not CONSTANT.fullmatch(owner):
                candidates=set().union(*(owners[(r['gem'],r['version'],r['method'],k)] for k in kinds))
                if len(candidates)==1:owner=next(iter(candidates));resolution='single_saved_namespace_owner'
            if not CONSTANT.fullmatch(owner):normalizations.append(dict(flow_id=flowid,raw_receiver=r['receiver'],status='unresolved_native_owner'));continue
            if registration=='rb_define_global_function':owner='Kernel'
            key=(r['gem'],r['version'],owner,r['method'],tuple(kinds));gid=ident(key)
            if gid not in grouped:grouped[gid]=dict(id=gid,gem=r['gem'],version=r['version'],locked_version=version,owner=owner,method=r['method'],kinds=kinds,arguments=set(),flow_ids=[],receiver_resolution=resolution,
                arities=sorted(set().union(*(arities[(r['gem'],r['version'],owner,r['method'],k)] for k in kinds))),private=registration=='rb_define_private_method')
            grouped[gid]['arguments'].add(r['argument_index']);grouped[gid]['flow_ids'].append(flowid);r['api_group']=gid;active.append(r)
    apis=[]
    for a in grouped.values():a['arguments']=sorted(a['arguments'],key=str);a['flow_ids']=sorted(a['flow_ids']);apis.append(a)
    return sorted(apis,key=lambda a:a['id']),all_flows,active,normalizations,versions

def native_hierarchy(repo,native_data,versions,e):
    gemrows={r['gem_id']:r for r in rows(native_data/'gems.jsonl')};declarations=[];symbols={};resolved={};audit=[]
    namespace_files=[native_data/'c_namespaces.jsonl'] if (native_data/'c_namespaces.jsonl').exists() else [Path(e['path']) for e in rows(repo/'argument-taint-analysis/results/scavenged-native-evidence.jsonl') if Path(e['member']).name=='c_namespaces.jsonl']
    for namespace_file in namespace_files:
        for r in rows(namespace_file):
            g=gemrows.get(r['gem_id'],{});locked=versions.get(g.get('name'));version=g.get('version')
            if locked and (locked==version or locked.startswith(version+'-')):declarations.append(r)
    for r in declarations:symbols.setdefault(r['gem_id'],dict(CORE))
    while True:
        progress=False
        for r in declarations:
            args=r.get('arguments',[]);api=r['api'];mapping=symbols[r['gem_id']]
            if api not in {'rb_define_class','rb_define_class_under','rb_define_module','rb_define_module_under'}:continue
            under=api.endswith('_under');name=args[1 if under else 0] if len(args)>(1 if under else 0) else ''
            if not name.startswith('"'):continue
            try:name=json.loads(name)
            except ValueError:continue
            parent=mapping.get(args[0]) if under else ''
            if under and not parent:continue
            name=parent+'::'+name if parent else name
            match=re.search(r'(\w+)\s*=\s*rb_define_',r.get('assignment_context',''));variable=match[1] if match else None
            if variable and variable not in mapping:mapping[variable]=name;progress=True
            resolved[r['namespace_id']]=name
        if not progress:break
    e.namespace_symbols=collections.defaultdict(set)
    for r in declarations:
        owner=resolved.get(r['namespace_id']);mapping=symbols[r['gem_id']]
        if not owner:continue
        match=re.search(r'(\w+)\s*=\s*rb_define_',r.get('assignment_context',''))
        g=gemrows[r['gem_id']]
        if match:e.namespace_symbols[(g['name'],g['version'],match[1])].add(owner)
        kind='class' if '_class' in r['api'] else 'module';e.known.add(owner)
        c=e.classes.setdefault(owner,dict(parents=[],includes=[],extends=[],extend_self=False,module_function=False,aliases={},namespace_kind=kind))
        parent=mapping.get(r['arguments'][-1]) if kind=='class' else None
        if parent and (parent,'') not in c['parents']:c['parents'].append((parent,''))
        audit.append(dict(owner=owner,parent=parent,namespace_kind=kind,native_declaration=r))
    return audit

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--repo',type=Path,required=True);ap.add_argument('--gitlab',type=Path,required=True);ap.add_argument('--native-data',type=Path,required=True);ap.add_argument('--out',type=Path,required=True);ap.add_argument('--checkpoint',type=Path)
    a=ap.parse_args();a.out.mkdir(parents=True,exist_ok=True);commit=subprocess.check_output(['git','-C',str(a.gitlab),'rev-parse','HEAD'],text=True).strip();lock=(a.gitlab/'Gemfile.lock').read_text()
    versions=dict(re.findall(r'^    ([\w.-]+) \(([^ )]+)\)',lock,re.M));e=Engine([])
    jsonl(a.out/'native-class-hierarchy.jsonl',native_hierarchy(a.repo,a.native_data,versions,e))
    apis,all_flows,active,normalizations,versions=catalogue(a.repo,a.native_data,lock,e.namespace_symbols)
    for api in apis:
        e.known.add(api['owner'])
        for k in api['kinds']:e.native[(api['owner'],k,api['method'])].append(api)
    jsonl(a.out/'api-groups.jsonl',apis);jsonl(a.out/'native-owner-boundaries.jsonl',normalizations)
    gemfiles=json.loads((a.repo/'ruby-callsite-analysis/results/gem-ruby-source-manifest.json').read_text())
    files=subprocess.check_output(['git','-C',str(a.gitlab),'ls-files','-z','*.rb','*.rake','*.ru'],text=True).split('\0');files=sorted(f for f in files if f)
    if a.checkpoint and a.checkpoint.exists():
        with a.checkpoint.open('rb') as stream:e=pickle.load(stream)
        assert e.gitlab_commit==commit
        assert e.catalogue_hash==ident(apis)
        e.compact_events()
        if getattr(e,'receiver_rule_version',0)!=4:
            e.class_fields={key:relabel(v,frozenset()) for key,v in e.class_fields.items()}
            e.inputs={key:relabel(v,frozenset()) for key,v in e.inputs.items()}
            for uid,unit in e.units.items():
                if unit['params'] or e.sinks[uid] or nested_deps(e.returns[uid]):e.enqueue(uid)
                if nested_deps(e.returns[uid]):
                    e.returns[uid]=dataclasses.replace(relabel(e.returns[uid],frozenset()),deps=e.returns[uid].deps)
                    for caller in sorted(e.reverse[uid]):e.enqueue(caller)

            e.initial_closed=False;e.receiver_rule_version=4
        print('Resuming saved Ruby fixed point:',e.evaluations,flush=True)
    else:
        for f in gemfiles:
            raw=Path(f['path']).read_bytes();assert hashlib.sha256(raw).hexdigest()==f['source_sha256']
            e.index(raw,'@gem/'+f['gem']+'@'+f['locked_version']+'/'+f['file'],'gem_wrapper',f)
        files=subprocess.check_output(['git','-C',str(a.gitlab),'ls-files','-z','*.rb','*.rake','*.ru'],text=True).split('\0');files=sorted(f for f in files if f)
        for i,file in enumerate(files):
            p=a.gitlab/file
            if p.is_symlink() or not p.is_file():continue
            e.index(p.read_bytes(),file)
            if i%5000==0:print('GitLab Ruby files indexed:',i,flush=True)
    e.gitlab_commit=commit;e.catalogue_hash=ident(apis);e.checkpoint_path=a.checkpoint;e.receiver_rule_version=4
    print('Units:',len(e.units),'API groups:',len(apis),flush=True);e.solve()
    accepted=[];rejected=[];covered=collections.defaultdict(set);api_by_id={r['id']:r for r in apis};flows={r['flow_id']:r for r in active};file_by_name={r['file']:r for r in e.files}
    for event,c in sorted(e.calls.items()):
        site=e.events[event];proof=[]
        if c['receiver_unknown']:reason='receiver_unresolved'
        elif len(set(map(str,c['dispatches'])))>1:reason='receiver_dispatch_ambiguous'
        elif not c['hits']:reason='no_supplied_argument_reaches_native_witness'
        else:reason=None
        if reason:
            if c['method'] in {r['method'] for r in apis}:rejected.append(dict(**site,reason=reason,receiver=c['receiver_expression'],receiver_types=c['receiver_types'],receiver_unknown=c['receiver_unknown'],arguments=c['arguments']))
            continue
        hits={};seen=set()
        for hit in c['hits']:
            api=api_by_id[hit['api_group']];index=hit['ruby_argument_index'];arg=c['arguments'][index]
            for fid in api['flow_ids']:
                f=flows[fid]
                if f['argument_index']!=hit['native_argument_index']:continue
                key=(fid,index,tuple(hit['path']))
                if key in seen:continue
                seen.add(key);covered[fid].add(event)
                binding_key=(api['id'],index,hit['native_argument_index'],tuple(hit['path']))
                if binding_key not in hits:hits[binding_key]=dict(native_api_group=api['id'],native_api=dict(gem=api['gem'],version=api['version'],owner=api['owner'],method=api['method']),
                    ruby_argument_index=index,ruby_argument_expression=arg['expression'],ruby_argument_kind=arg['kind'],native_argument_index=f['argument_index'],
                    c_flow_ids=[],ruby_binding_path=[e.events[x] for x in hit['path']],via=hit['via'])
                hits[binding_key]['c_flow_ids'].append(fid)
        if not hits:continue
        record=dict(callsite_id=event,gitlab_commit=commit,source=dict(file=site['file'],line=site['line'],column=site['column'],source_sha256=file_by_name[site['file']]['sha256'],permalink='https://gitlab.com/gitlab-org/gitlab/-/blob/'+commit+'/'+site['file']+'#L'+str(site['line'])),
            expression=site['expression'],method=c['method'],receiver=dict(expression=c['receiver_expression'],types=c['receiver_types'],proof=[e.events[x] for x in c['receiver_proof']]),
            supplied_arguments=c['arguments'],native_flows=list(hits.values()),test_or_fixture=bool(re.search(r'(^|/)(spec|test|tests|fixtures|qa)(/|$)',site['file'])))
        accepted.append(record)
    for r in accepted:
        p=a.out/'callsites'/r['source']['file']/('line-'+str(r['source']['line'])+'-'+str(r['source']['column'])+'-'+r['callsite_id'][:16]+'.json');p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(r,indent=2,sort_keys=True)+'\n')
    jsonl(a.out/'callsites.jsonl',accepted);jsonl(a.out/'receiver-or-argument-boundaries.jsonl',rejected);jsonl(a.out/'files.jsonl',e.files)
    library=a.out/'c-flow-library';library.mkdir(exist_ok=True);part=1;written=0;stream=None
    try:
        for fid in sorted(covered):
            data=json.dumps(flows[fid],sort_keys=True,separators=(',',':'))+'\n'
            if stream is None or written+len(data.encode())>32*1024*1024:
                if stream:stream.close()
                stream=(library/f'part-{part:04d}.jsonl').open('w');part+=1;written=0
            stream.write(data);written+=len(data.encode())
    finally:
        if stream:stream.close()
    jsonl(a.out/'flow-coverage.jsonl',(dict(flow_id=r['flow_id'],gem=r['gem'],version=r['version'],receiver=r['receiver'],method=r['method'],argument_index=r['argument_index'],
        callsite_ids=sorted(covered[r['flow_id']]),status='matched' if covered[r['flow_id']] else 'no_verified_callsite' if r.get('api_group') else 'inactive_version_or_unresolved_native_owner') for r in all_flows))
    summary=dict(gitlab_commit=commit,gitlab_remote='https://gitlab.com/gitlab-org/gitlab.git',lockfile_sha256=digest(a.gitlab/'Gemfile.lock'),input_flow_records=len(all_flows),active_normalized_flow_records=len(active),api_groups=len(apis),
        gitlab_ruby_files=len(files),gem_wrapper_files=len(gemfiles),method_units=len(e.units),function_evaluations=e.evaluations,fixed_point_reached=not e.pending,call_depth_limit=None,
        verified_callsites=len(accepted),application_callsites=sum(not r['test_or_fixture'] for r in accepted),test_or_fixture_callsites=sum(r['test_or_fixture'] for r in accepted),
        matched_c_flow_records=sum(bool(sites) for sites in covered.values()),receiver_or_argument_boundaries=len(rejected),native_argument_bindings_per_gem=dict(sorted(collections.Counter(h['native_api']['gem'] for r in accepted for h in r['native_flows']).items())),
        definition='Static receiver-resolved Ruby call sites with a definitely supplied argument connected to a saved native memory-operand witness. C witnesses retain their checkpoint-snapshot status. Gem Ruby wrappers are followed by formal/actual argument bindings.')
    (a.out/'summary.json').write_text(json.dumps(summary,indent=2,sort_keys=True)+'\n');print(json.dumps(summary,indent=2,sort_keys=True),flush=True)

if __name__=='__main__':main()

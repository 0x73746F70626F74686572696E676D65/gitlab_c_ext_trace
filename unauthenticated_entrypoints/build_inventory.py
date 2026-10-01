#!/usr/bin/env python3
"""Source-only HTTP registration and anonymous-access inventory; never boots GitLab."""
import argparse, collections, copy, functools, gzip, hashlib, json, pickle, re, subprocess, sys
from pathlib import Path
import inflection, yaml
from tree_sitter import Language, Parser
import tree_sitter_ruby
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'frontend_gem_api_map'))
from map_frontend import Mapper, args, block_body, conditional, fld, git, literal, location, method_name, options, positional, symbols, txt, walk

HTTP = {'get','post','put','patch','delete','head','options','match','root','route'}
FILTERS = {'before_action','prepend_before_action','append_before_action','skip_before_action','before_filter','skip_before_filter','around_action','prepend_around_action','skip_around_action'}
AUTH = {'authenticate_user!','authenticate_admin!','authenticate!','require_admin!','require_authenticated_user!','authenticate_runner!','authenticated_as_admin!','authenticated_with_can_read_all_resources!'}
OPTIONAL = {'authenticate_sessionless_user!','authenticate_with_http_token','authenticate_with_http_basic','current_user','find_current_user!','find_user_from_sources'}
CREDENTIAL = re.compile(r'(?:authenticate_by_|verify_.*(?:token|signature|secret)|require_gitlab_workhorse|verify_workhorse|authorize_workhorse|require_verification_user|require_.*(?:token|certificate)|authenticate_.*(?:token|runner|job)|valid_.*(?:token|signature))')
GUEST_SAFE = {('ApplicationController','ldap_security_check'),('Gitlab::GonHelper','add_gon_variables'),('Impersonation','check_impersonation_availability')}
DYNAMIC = {'send','public_send','__send__','method_missing','define_method','class_eval','module_eval','instance_eval','eval'}


def digest(data): return hashlib.sha256(data).hexdigest()
def stable_id(value): return 'ep_' + digest(json.dumps(value,sort_keys=True).encode())[:24]
def camel(s): return inflection.camelize(s, False)
def join(*parts): return '/' + '/'.join(str(p).strip('/') for p in parts if p is not None and str(p).strip('/'))
def load_lines(p):
    with (gzip.open(p,'rt') if p.suffix=='.gz' else p.open()) as f: return [json.loads(l) for l in f]
def dedup(rows): return list({json.dumps(x,sort_keys=True):x for x in rows}.values())


class Index:
    def __init__(self, source, cache, baseline, engine_source=Path('/workspace/auth-route-engine-sources')):
        self.source=source; self.sha=git(source,'rev-parse','HEAD'); self.parser=Parser(Language(tree_sitter_ruby.language()))
        self.trees={}; self.nodes={}; self.files={}; self.gaps=[];self.external_paths={};self.engine_sources={}
        self.m=object.__new__(Mapper); self.m.source=source; self.m.sha=self.sha; self.m.parser=self.parser
        if cache and cache.exists():
            state=pickle.loads(cache.read_bytes())
            if state['sha']!=self.sha: raise ValueError('Cached Ruby index revision differs from checkout; rebuild instead of reusing it')
            for k in ['classes','units','method_index','aliases','files','global_helpers']: setattr(self.m,k,state[k])
            self.reuse='existing source index (no API matching or memory tracing)'
        else:
            self.m.classes=collections.defaultdict(lambda:{'parents':[],'mixins':[],'macros':[],'files':[]})
            self.m.units={}; self.m.method_index=collections.defaultdict(list); self.m.aliases={}; self.m.files=[]
            self.m.global_helpers=[]; self.m.entries=[]; self.m.routes=[]; self.m.registrations=[]
            self.m.gaps=collections.defaultdict(list); self.m.declared_fields=[]; self.m.mounted_mutations=[]
            self.m.apis=[]; self.m.api_by_name={}; self.m.parse()
            self.reuse='rebuilt source-only Ruby index; no gem inventory read'
        self.classes=self.m.classes; self.units=self.m.units
        self.original=[]
        bp=baseline/'entrypoints.jsonl.gz'
        if bp.exists():
            self.original=load_lines(bp)
            if any(e['gitlab_commit_sha']!=self.sha for e in self.original): raise ValueError('Baseline revision mismatch')
        if not self.original and hasattr(self.m,'entries'):self.original=list(self.m.entries)
        self.controller_map={inflection.underscore(c.removesuffix('Controller')).replace('::','/'):c for c in self.classes if c.endswith('Controller') and not c.startswith('EE::')}
        self.augment={}; self.callbacks={}; self.class_nodes={}; self.declarations=[]; self.mounts=[]
        self._class_facts_done=set()
        self.tracked=git(source,'ls-files','-z').split('\0')
        self.load_engines(engine_source)

    def load_engines(self,root):
        self.m.classes=collections.defaultdict(lambda:{'parents':[],'mixins':[],'macros':[],'files':[]},self.m.classes)
        self.m.method_index=collections.defaultdict(list,self.m.method_index);self.classes=self.m.classes
        for key,value in {'entries':[],'routes':[],'registrations':[],'declared_fields':[],'mounted_mutations':[],'gaps':collections.defaultdict(list)}.items():setattr(self.m,key,value)
        for gem,version in [('devise','4.9.4'),('doorkeeper','5.9.3'),('doorkeeper-openid_connect','1.10.5'),('doorkeeper-device_authorization_grant','1.0.3')]:
            path=root/(gem+'-'+version)
            if not path.exists():
                self.gap('external_engine_source_unavailable',{'file':'Gemfile.lock','line':1},gem=gem,version=version);continue
            metadata=json.loads((root/(gem+'-'+version+'.json')).read_text())
            for relative,expected in metadata['source_files'].items():
                if digest((path/relative).read_bytes())!=expected:raise ValueError('External engine source changed: '+relative)
            self.engine_sources[gem]={'version':version,'metadata':metadata}
            for p in sorted((path/'app/controllers').rglob('*.rb')):
                file='external/'+gem+'-'+version+'/'+str(p.relative_to(path));self.external_paths[file]=p
                self.m.visit(self.tree(file),file,'','public',[],[],None)
            if gem=='devise' and 'DeviseController' in self.classes:self.classes['DeviseController']['parents']=['ApplicationController']
            if gem=='doorkeeper' and 'Doorkeeper::ApplicationController' in self.classes:self.classes['Doorkeeper::ApplicationController']['parents']=['Gitlab::BaseDoorkeeperController']
            for relative in (['lib/devise/rails/routes.rb','lib/devise/controllers/helpers.rb'] if gem=='devise' else ['lib/doorkeeper/rails/routes.rb'] if gem=='doorkeeper' else [str(p.relative_to(path)) for p in (path/'lib').rglob('*routes*.rb')]):
                p=path/relative;file='external/'+gem+'-'+version+'/'+relative;self.external_paths[file]=p;self.tree(file)

    def tree(self,file):
        if file not in self.trees:
            data=(self.external_paths.get(file) or self.source/file).read_bytes(); tree=self.parser.parse(data)
            self.trees[file]=tree.root_node
            self.files[file]={'file':file,'sha256':digest(data),'bytes':len(data),'parse_errors':sum(n.type=='ERROR' or n.is_missing for n in walk(tree.root_node))}
        return self.trees[file]

    def at(self,file,line,column=None,types=None):
        key=(file,line,column,tuple(types or ()))
        if key not in self.nodes:
            self.nodes[key]=next((n for n in walk(self.tree(file)) if n.start_point.row+1==line and (column is None or n.start_point.column+1==column) and (types is None or n.type in types)),None)
        return self.nodes[key]

    def unit_node(self,uid):
        u=self.units[uid]; _,line,col,_=uid.rsplit(':',3)
        return self.at(u['file'],int(line),int(col),['method','singleton_method','call'])

    def facts(self,owner):
        if owner in self._class_facts_done:return
        self._class_facts_done.add(owner)
        for file in set(self.classes.get(owner,{}).get('files',[])):
            self.scan_classes(file)

    def scan_classes(self,file):
        if file in self._class_facts_done:return
        self._class_facts_done.add(file)
        def visit(n,owner=''):
            if n is None:return
            if n.type in {'class','module'}:
                name=txt(fld(n,'name'));own=self.m.qualify(name,owner)
                self.class_nodes.setdefault(own,[]).append((file,n));visit(fld(n,'body'),own);return
            if n.type in {'method','singleton_method'}:return
            if n.type=='call':
                name=method_name(n);opts=options(n);pos=positional(n)
                if name in FILTERS:
                    inherited={};p=n.parent
                    while p and p.type not in {'class','module'}:
                        if p.type=='call' and method_name(p)=='with_options':inherited={**options(p),**inherited}
                        p=p.parent
                    opts={**inherited,**opts}
                    self.callbacks.setdefault(owner,[]).append({'name':name,'names':[literal(a) for a in pos if literal(a)],'only':symbols(opts.get('only')),'except':symbols(opts.get('except')),'only_specified':'only' in opts,'if':opts.get('if'),'unless':opts.get('unless'),'node':n,'owner':owner,'source':location(file,n),'conditional':conditional(n)})
                if name in {'prepend_mod','prepend_mod_with','include_mod','include_mod_with'}:
                    target=txt(fld(n,'receiver')).lstrip(':') or owner
                    if pos and literal(pos[0]):target=literal(pos[0])
                    if 'EE::'+target in self.classes:self.augment.setdefault(target,[]).append('EE::'+target)
                if name in {'field','mount_mutation','mount_aliased_mutation','type','authorize','graphql_name','implements','possible_types','include','prepend','helpers','authentication'}:
                    self.declarations.append({'owner':owner,'file':file,'node':n,'name':name})
                if name=='mount':self.mounts.append({'owner':owner,'file':file,'node':n})
            for child in n.named_children:visit(child,owner)
        visit(self.tree(file))

    @functools.lru_cache(None)
    def ancestors(self,owner,edition):
        result=[];seen=set()
        def descend(c):
            if c in seen:return
            seen.add(c);self.facts(c)
            if edition=='ee':
                for a in self.augment.get(c,[]):descend(a)
            result.append(c)
            cls=self.classes.get(c,{})
            for mix in reversed(cls.get('mixins',[])):
                m=self.m.resolve_constant(mix,c)
                descend(m)
            for p in cls.get('parents',[]):descend(self.m.resolve_constant(p,c.rsplit('::',1)[0] if '::' in c else ''))
        descend(owner);return tuple(result)

    def lookup(self,owner,name,edition='ce',kind='instance'):
        for c in self.ancestors(owner,edition):
            alias=self.classes.get(c,{}).get('method_aliases',{}).get(name,name)
            u=[i for i in self.m.method_index.get((c,alias,kind),[]) if edition=='ee' or not self.units[i]['file'].startswith('ee/')]
            if u:return u
        if kind=='instance' and owner.startswith('API::'):
            for helper in reversed(self.m.global_helpers):
                if helper==owner:continue
                for c in self.ancestors(helper,edition):
                    hits=self.m.method_index.get((c,name,kind),[])
                    if hits:return hits
        return []

    def controller(self,path):
        return self.controller_map.get(path.lstrip('/')) or '::'.join(inflection.camelize(p) for p in path.lstrip('/').split('/'))+'Controller'

    def gap(self,kind,source,**kw):self.gaps.append({'kind':kind,**source,**kw})


class Routes:
    def __init__(self,idx):
        self.i=idx;self.records=[];self.concerns={};self.methods={};self.drawn=set();self.visited=[]

    def value(self,node,env):
        if node is None:return None
        if node.type in {'identifier','instance_variable'} and txt(node) in env:return env[txt(node)]
        lit=literal(node)
        if lit is not None:return lit
        if node.type=='hash':
            return {literal(fld(p,'key')):self.value(fld(p,'value'),env) for p in node.named_children if p.type=='pair'}
        if node.type=='string' and any(c.type=='interpolation' for c in node.named_children):
            parts=[]
            for c in node.named_children:
                if c.type=='string_content':parts.append(txt(c))
                elif c.type=='interpolation':
                    v=self.value(c.named_children[0],env) if c.named_children else None
                    if v is None:return None
                    parts.append(str(v))
            return ''.join(parts)
        if node.type in {'true','false','nil'}:return {'true':True,'false':False,'nil':None}[node.type]
        if node.type in {'array','symbol_array','string_array'}:
            return [self.value(n,env) for n in node.named_children if n.type not in {'string_content'}] if node.type=='array' else [txt(n).lstrip(':') for n in node.named_children]
        return None

    def context(self,edition):return {'path':'/','module':'','controller':None,'resource':None,'conditions':[],'auth_scopes':[],'edition':edition,'organization':False,'env':{},'draw_chain':[]}

    def emit(self,ctx,node,file,verb,path,target=None,controller=None,action=None,kind='rails_action',**extra):
        if target and '#' in target:controller,action=target.split('#',1)
        if controller and not controller.startswith('/') and ctx['module']:controller=ctx['module'].strip('/')+'/'+controller
        controller=controller.lstrip('/') if controller else None
        rec={'type':kind,'edition':ctx['edition'],'http_methods':verb,'path':path,'controller':self.i.controller(controller) if controller else None,'controller_path':controller,'action':action,'registration':location(file,node),'registration_status':'static_route','conditions':ctx['conditions'][:],'route_auth_scopes':ctx['auth_scopes'][:],'draw_chain':ctx['draw_chain'][:],'target':target,**extra}
        rec['id']=stable_id([ctx['edition'],kind,verb,path,controller,action,rec['registration']['file'],rec['registration']['line'],extra.get('target')])
        self.records.append(rec)

    def read(self,file,ctx):
        if file in ctx['draw_chain']:
            self.i.gap('route_draw_cycle',{'file':file,'line':1});return
        self.drawn.add(file);self.visited.append({'file':file,'edition':ctx['edition'],'prefix':ctx['path']})
        ctx=copy.copy(ctx);ctx['draw_chain']=ctx['draw_chain']+[file]
        self.visit(self.i.tree(file),file,ctx)

    def visit(self,n,file,ctx):
        if n is None:return
        if n.type in {'program','body_statement','block_body','then','else','begin','do_block','block'}:
            for c in n.named_children:self.visit(c,file,ctx)
            return
        if n.type in {'method','singleton_method'}:
            name=txt(fld(n,'name'))
            if file.startswith(('config/routes','ee/config/routes')):self.methods[name]=(file,fld(n,'body'))
            return
        if n.type=='assignment':
            v=self.value(fld(n,'right'),ctx['env']);ctx['env'][txt(fld(n,'left'))]=v
            if txt(fld(n,'left'))=='@organization_scoped_routes':ctx['organization']=bool(v)
            return
        if n.type=='identifier':
            name=txt(n)
            if name in self.methods:
                ff,body=self.methods[name];self.visit(body,ff,copy.deepcopy(ctx))
            return
        if n.type in {'if','unless','if_modifier','unless_modifier'}:
            cond=fld(n,'condition');condtext=txt(cond)
            known=None
            if '@organization_scoped_routes'==condtext:known=ctx['organization']
            if ctx['edition']=='ce' and re.search(r'(?:::)?Gitlab\.ee\?',condtext) and '&&' in condtext:known=False
            if n.type.startswith('unless') and known is not None:known=not known
            body=fld(n,'consequence') or fld(n,'body')
            alt=fld(n,'alternative')
            if known is True:self.visit(body,file,ctx)
            elif known is False:self.visit(alt,file,ctx)
            else:
                cc=copy.deepcopy(ctx);cc['conditions'].append({'kind':'registration_condition','expression':condtext,'negated':n.type.startswith('unless'),**location(file,n)})
                self.visit(body,file,cc)
                if alt:
                    cc=copy.deepcopy(ctx);cc['conditions'].append({'kind':'registration_condition','expression':condtext,'negated':not n.type.startswith('unless'),**location(file,n)});self.visit(alt,file,cc)
            return
        if n.type!='call':
            for c in n.named_children:self.visit(c,file,ctx)
            return
        name=method_name(n);pos=positional(n);opts=options(n);body=block_body(n)
        val=lambda node:self.value(node,ctx['env'])
        if name in self.methods:
            ff,bb=self.methods[name];self.visit(bb,ff,copy.deepcopy(ctx));return
        if name=='ee' and txt(fld(n,'receiver'))=='Gitlab':
            if ctx['edition']=='ee':self.visit(body,file,ctx)
            return
        if name=='concern' and pos:
            self.concerns[val(pos[0])]=(file,body);return
        if name=='concerns':
            values=[val(a) for a in pos];values=[x for v in values for x in (v if isinstance(v,list) else [v])]
            for v in values:
                if v in self.concerns:ff,bb=self.concerns[v];self.visit(bb,ff,copy.deepcopy(ctx))
                else:self.i.gap('unresolved_route_concern',location(file,n),name=v)
            return
        if name in {'draw','draw_all'}:
            if not pos and body:
                self.visit(body,file,ctx);return
            v=val(pos[0]) if pos else None
            files=[f'config/routes/{v}.rb']
            if name=='draw_all' and ctx['edition']=='ee':files.append(f'ee/config/routes/{v}.rb')
            elif v and (self.i.source/f'ee/config/routes/{v}.rb').exists() and not (self.i.source/files[0]).exists():files=[f'ee/config/routes/{v}.rb']
            for f in files:
                if (self.i.source/f).exists():self.read(f,copy.deepcopy(ctx))
                elif name=='draw':self.i.gap('missing_route_draw',location(file,n),target=f)
            return
        if name in {'scope','namespace','constraints','authenticate','authenticated','unauthenticated','controller'} and body:
            cc=copy.deepcopy(ctx);v=val(pos[0]) if pos else None
            if name=='namespace':
                if v is None:self.i.gap('dynamic_route_namespace',location(file,n))
                else:
                    cc['path']=join(ctx['path'],val(opts['path']) if 'path' in opts else v)
                    cc['module']='/'.join(p for p in [ctx['module'],val(opts['module']) if 'module' in opts else v] if p)
            elif name=='scope':
                path=val(opts['path']) if 'path' in opts else v
                if path is not None:cc['path']=join(ctx['path'],path)
                if 'module' in opts:cc['module']='/'.join(p for p in [ctx['module'],val(opts['module'])] if p)
                if 'controller' in opts:cc['controller']=val(opts['controller'])
            elif name=='controller':cc['controller']=v
            elif name in {'authenticate','authenticated','unauthenticated'}:
                cc['auth_scopes'].append({'name':name,'expression':txt(n).split('\n')[0],**location(file,n)})
            else:
                cc['conditions'].append({'kind':'route_constraint','expression':txt(n).split('\n')[0],**location(file,n)})
            if 'constraints' in opts:
                cc['conditions'].append({'kind':'route_constraint','expression':txt(opts['constraints']),**location(file,n)})
            self.visit(body,file,cc);return
        if name in {'resources','resource'}:
            names=[val(a) for a in pos];names=[v for v in names if isinstance(v,str)]
            if not names:self.i.gap('dynamic_resource_name',location(file,n));return
            for v in names:
                plural=name=='resources';path=val(opts['path']) if 'path' in opts else v
                collection=join(ctx['path'],path);param=val(opts.get('param')) or 'id'
                controller=val(opts.get('controller')) or (v if plural else inflection.pluralize(v))
                mod=ctx['module'];module=val(opts.get('module'))
                if module:mod='/'.join(p for p in [mod,module] if p)
                member=join(collection,':'+param) if plural else collection
                nested=join(collection,':'+inflection.singularize(v)+'_'+param) if plural else collection
                only=val(opts.get('only'));exc=val(opts.get('except')) or []
                if isinstance(only,str):only=[only]
                if isinstance(exc,str):exc=[exc]
                cc=copy.deepcopy(ctx);cc['module']=mod
                if 'constraints' in opts:cc['conditions'].append({'kind':'route_constraint','expression':txt(opts['constraints']),**location(file,n)})
                actions={'index':(['GET'],collection),'create':(['POST'],collection),'new':(['GET'],join(collection,'new')),'show':(['GET'],member),'edit':(['GET'],join(member,'edit')),'update':(['PATCH','PUT'],member),'destroy':(['DELETE'],member)}
                for a,(verbs,p) in actions.items():
                    if (not plural and a=='index') or (only is not None and a not in only) or a in exc:continue
                    self.emit(cc,n,file,verbs,p,controller=controller,action=a)
                res={'controller':controller,'collection':collection,'member':member,'nested':nested,'name':v}
                cc['resource']=res;cc['path']=nested;cc['controller']=controller
                if 'concerns' in opts:
                    concerns=val(opts['concerns']) or []
                    if isinstance(concerns,str):concerns=[concerns]
                    for concern in concerns:
                        if concern in self.concerns:ff,bb=self.concerns[concern];self.visit(bb,ff,copy.deepcopy(cc))
                self.visit(body,file,cc)
            return
        if name in {'member','collection','new'} and ctx['resource']:
            cc=copy.deepcopy(ctx);res=ctx['resource'];cc['path']=res['member'] if name=='member' else res['collection'] if name=='collection' else join(res['collection'],'new');self.visit(body,file,cc);return
        if name in HTTP:
            routepath=val(pos[0]) if pos else '';target=val(opts.get('to'));controller=val(opts.get('controller')) or ctx['controller'];action=val(opts.get('action'))
            for a in args(n):
                if a.type=='pair' and fld(a,'key').type=='string':routepath=val(fld(a,'key'));target=val(fld(a,'value'))
            if name=='root':routepath=''
            if isinstance(routepath,list):paths=routepath
            else:paths=[routepath]
            if name=='match':verbs=val(opts.get('via'));verbs=verbs if isinstance(verbs,list) else [verbs] if verbs else ['ANY']
            else:verbs=['GET'] if name=='root' else [name.upper()]
            verbs=[str(v).upper() for v in verbs]
            cc=copy.deepcopy(ctx)
            if opts.get('on') is not None and ctx['resource']:
                on=val(opts['on']);cc['path']=ctx['resource'].get(on,ctx['path'])
            if action is None and controller and isinstance(routepath,str):action=routepath.strip('/')
            targetnode=opts.get('to')
            if targetnode is not None and targetnode.type=='call' and method_name(targetnode)=='action':
                klass=txt(fld(targetnode,'receiver')).lstrip(':');aa=positional(targetnode)
                if klass in self.i.classes and aa:
                    controller='/'+inflection.underscore(klass.removesuffix('Controller')).replace('::','/');action=literal(aa[0])
            for p in paths:
                if p is None:self.i.gap('dynamic_route_path',location(file,n),declaration=txt(n).split('\n')[0]);p='<unresolved>'
                kind='rails_action';extra={}
                if not target and not controller:
                    kind='http_registration';extra['handler_target']=txt(targetnode) or str(p);extra['declaration']=txt(n).split('\n')[0]
                    extra['handler_kind']='redirect' if targetnode is not None and (method_name(targetnode)=='redirect' or txt(targetnode).endswith('_redirect')) else 'inline' if targetnode is not None and ('proc' in txt(targetnode) or targetnode.type=='lambda') else 'unresolved'
                self.emit(cc,n,file,verbs,join(cc['path'],p),target=target or extra.get('handler_target'),controller=controller,action=action,kind=kind,**extra)
            return
        if name in {'mount','devise_for','use_doorkeeper','use_doorkeeper_openid_connect','use_doorkeeper_device_authorization_grant'}:
            target=txt(pos[0]) if pos else name;path=val(opts.get('at'))
            for a in args(n):
                if a.type=='pair' and fld(a,'key').type not in {'hash_key_symbol','simple_symbol'}:target=txt(fld(a,'key'));path=val(fld(a,'value'))
            self.emit(ctx,n,file,['ANY'],join(ctx['path'],path or ''),kind='http_registration',target=target,registration_macro=name,declaration=txt(n).split('\n')[0],path_exact=path is not None)
            if name=='use_doorkeeper':self.doorkeeper(n,file,ctx)
            if name in {'use_doorkeeper_openid_connect','use_doorkeeper_device_authorization_grant'}:self.oauth_extension(n,file,ctx,name)
            if name=='devise_for':self.devise(n,file,ctx)
            return
        if name=='each' and body:
            rec=fld(n,'receiver');values=val(rec)
            params=fld(fld(n,'block'),'parameters');param=txt(params.named_children[0]) if params and params.named_children else None
            if isinstance(values,list) and param:
                for v in values:
                    cc=copy.deepcopy(ctx);cc['env'][param]=v;self.visit(body,file,cc)
            else:
                self.i.gap('dynamic_route_loop',location(file,n),expression=txt(n).split('\n')[0]);self.visit(body,file,ctx)
            return
        if name in {'direct','get_gitlab_portal','redirect','as','format'}:return
        if body:self.visit(body,file,ctx)

    def doorkeeper(self,n,file,ctx):
        classes={}
        for x in walk(block_body(n)):
            if x.type=='pair':classes[literal(fld(x,'key'))]=literal(fld(x,'value'))
        scope=self.value(options(n).get('scope'),ctx['env']) or 'oauth'
        rows=[(['GET'],'authorize','authorizations','new'),(['GET'],'authorize/native','authorizations','show'),(['POST'],'authorize','authorizations','create'),(['DELETE'],'authorize','authorizations','destroy'),(['POST'],'token','tokens','create'),(['POST'],'revoke','tokens','revoke'),(['POST'],'introspect','tokens','introspect'),(['GET'],'token/info','token_info','show'),(['GET'],'authorized_applications','authorized_applications','index'),(['DELETE'],'authorized_applications/:id','authorized_applications','destroy')]
        rows += [(verbs,path,'applications',action) for verbs,path,action in [(['GET'],'applications','index'),(['GET'],'applications/new','new'),(['POST'],'applications','create'),(['GET'],'applications/:id','show'),(['GET'],'applications/:id/edit','edit'),(['PUT','PATCH'],'applications/:id','update'),(['DELETE'],'applications/:id','destroy')]]
        for verbs,path,controller,action in rows:
            self.emit(ctx,n,file,verbs,join(ctx['path'],scope,path),controller=classes.get(controller,'doorkeeper/'+controller),action=action,engine_expansion='Doorkeeper 5.9.3 source route macro',engine_verified='doorkeeper' in self.i.engine_sources,engine_source={'file':'external/doorkeeper-5.9.3/lib/doorkeeper/rails/routes.rb','line':34})

    def oauth_extension(self,n,file,ctx,name):
        classes={literal(fld(x,'key')):literal(fld(x,'value')) for x in walk(block_body(n)) if x.type=='pair'}
        scope=self.value(options(n).get('scope'),ctx['env']) or 'oauth'
        if name=='use_doorkeeper_openid_connect':
            gem,version='doorkeeper-openid_connect','1.10.5'
            rows=[(['GET','POST'],join(scope,'userinfo'),'userinfo','show'),(['GET'],join(scope,'discovery/keys'),'discovery','keys'),(['GET'],'/.well-known/openid-configuration','discovery','provider'),(['GET'],'/.well-known/oauth-authorization-server','discovery','provider'),(['GET'],'/.well-known/webfinger','discovery','webfinger')]
            self.i.gap('openid_optional_dynamic_registration',location(file,n),note='Framework dynamic_client_registration setting is not statically enabled; separate in-repo /oauth/register is inventoried')
        else:
            gem,version='doorkeeper-device_authorization_grant','1.0.3'
            rows=[(['GET'],join(scope,'device'),'device_authorizations','index'),(['POST'],join(scope,'device'),'device_authorizations','authorize'),(['POST'],join(scope,'authorize_device'),'device_codes','create')]
        for verbs,path,group,action in rows:
            controller=classes.get(group,'doorkeeper/'+('openid_connect/' if gem=='doorkeeper-openid_connect' else 'device_authorization_grant/')+group)
            self.emit(ctx,n,file,verbs,join(ctx['path'],path),controller=controller,action=action,engine_expansion=gem+' '+version+' source route macro',engine_verified=gem in self.i.engine_sources)

    def devise(self,n,file,ctx):
        opts=options(n);pos=positional(n);env=ctx['env'];v=lambda node:self.value(node,env)
        cs=opts.get('controllers');mapping=v(cs) if cs is not None else {}
        mapping=mapping if isinstance(mapping,dict) else {}
        for resource in [v(a) for a in pos if isinstance(v(a),str)]:
            base=v(opts.get('path')) or resource
            only=v(opts.get('only'));skip=v(opts.get('skip')) or []
            if isinstance(only,str):only=[only]
            if isinstance(skip,str):skip=[skip]
            path_names=v(opts.get('path_names')) or {}
            configs={'sessions':[(['GET'],'sign_in','new'),(['POST'],'sign_in','create'),(['POST'],'sign_out','destroy')],'registrations':[(['GET'],'sign_up','new'),(['GET'],'edit','edit'),(['POST'],'','create'),(['PUT','PATCH'],'','update'),(['DELETE'],'','destroy'),(['GET'],'cancel','cancel')],'passwords':[(['GET'],'password/new','new'),(['GET'],'password/edit','edit'),(['POST'],'password','create'),(['PUT','PATCH'],'password','update')],'confirmations':[(['GET'],'confirmation/new','new'),(['GET'],'confirmation','show'),(['POST'],'confirmation','create')],'unlocks':[(['GET'],'unlock/new','new'),(['GET'],'unlock','show'),(['POST'],'unlock','create')]}
            for group,routes in configs.items():
                if group in skip or (only is not None and group not in only):continue
                controller=mapping.get(group,'devise/'+group)
                model='app/models/'+inflection.singularize(resource)+'.rb'
                if (self.i.source/model).exists():
                    modeltext=(self.i.source/model).read_text();self.i.tree(model)
                    necessary={'registrations':'registerable','passwords':'recoverable','confirmations':'confirmable','unlocks':'lockable'}.get(group)
                    if necessary and ':'+necessary not in modeltext:continue
                for verbs,path,action in routes:
                    if path in path_names:path=path_names[path]
                    self.emit(ctx,n,file,verbs,join(ctx['path'],base,path),controller=controller,action=action,engine_expansion='Devise 4.9.4 static route macro',engine_verified='devise' in self.i.engine_sources,engine_route_group=group,engine_resource=resource)
        self.i.gap('external_engine_route_expansion',location(file,n),engine='Devise',note='Conventional route superset; enabled modules, path_names and OmniAuth provider expansion need engine resolution')

    def run(self):
        for edition in ['ce','ee']:
            self.methods={};self.concerns={};self.read('config/routes.rb',self.context(edition))
        # Keep unused declarations explicit instead of silently treating them as registered.
        for f in self.i.tracked:
            if f.startswith(('config/routes/','ee/config/routes/')) and f.endswith('.rb') and f not in self.drawn:
                self.i.gap('route_file_not_drawn',{'file':f,'line':1})
        return self.records

class AuthCheck:
    def __init__(self,idx):
        self.i=idx;self.memo={};self.policy={};self.policy_sources={}
        file='config/authz/roles/public_anonymous.yml';role=yaml.safe_load((idx.source/file).read_text());idx.tree('app/policies/global_policy.rb')
        self.public=set()
        for scope in ['project','group','organization']:
            for a in role.get(scope,{}).get('raw_permissions',[]):
                self.public.add(a);self.policy_sources[a]={'file':file,'line':next((j for j,l in enumerate((idx.source/file).read_text().splitlines(),1) if l.strip()=='- '+a),1),'resource_scope':scope}
        self.public.update({'access_api','access_git','read_project','read_group','read_users_list','read_cross_project','read_build','read_pipeline','read_pipeline_schedule','read_ci_cd_analytics'})
        for a in self.public:self.policy_sources.setdefault(a,{'file':'app/policies/global_policy.rb','line':64,'note':'Global default or derived public permissions; resource/settings conditions retained'})

    def predicate(self,n,owner,edition,verb):
        if n is None:return None
        s=txt(n).strip();s=re.sub(r'^:\s*','',s)
        if s.startswith('->'):s=s[s.find('{')+1:s.rfind('}')].strip()
        if s in {'current_user','@current_user','current_admin'}:return False
        if s in {'true','false'}:return s=='true'
        if s in {'current_user.nil?','current_user.blank?','!current_user','current_user == nil','nil == current_user'}:return True
        if s in {'request_authenticator.authentication_token_present?','authentication_token_present?'}:return False
        if s in {'current_user.present?','!!current_user','current_user != nil','current_user.is_a?(User)','sessionless_user?','user_signed_in?','signed_in?'}:return False
        if s=='devise_controller?':return any('Devise' in c for c in self.i.ancestors(owner,edition))
        if s in {'request.get?','request.head?','request.post?','request.put?','request.patch?','request.delete?','request.options?'}:return verb==s.split('.')[1][:-1].upper()
        if s=='Gitlab.ee?':return edition=='ee'
        if s=='user_onboarding?' and 'Onboarding::Redirect' in self.i.ancestors(owner,edition):
            self.i.tree('ee/app/models/onboarding.rb')
            return False # Onboarding.user_onboarding_in_progress?(nil) returns false at line 19.
        if '&&' in s:
            parts=s.split('&&');vals=[self.predicate_text(p,owner,edition,verb) for p in parts]
            if False in vals:return False
            if all(v is True for v in vals):return True
        if '||' in s:
            vals=[self.predicate_text(p,owner,edition,verb) for p in s.split('||')]
            if True in vals:return True
            if all(v is False for v in vals):return False
        return None

    def predicate_text(self,s,owner,edition,verb):
        return self.predicate(self.i.parser.parse(s.strip().encode()).root_node.named_children[0],owner,edition,verb) if s.strip() else None

    def reachability(self,n,boundary,owner,edition,verb):
        uncertain=False;p=n.parent
        while p is not None and p!=boundary:
            if p.type in {'if','unless','if_modifier','unless_modifier'}:
                val=self.predicate(fld(p,'condition'),owner,edition,verb)
                if p.type.startswith('unless') and val is not None:val=not val
                alternative=fld(p,'alternative')
                in_alt=alternative is not None and alternative.start_byte<=n.start_byte<alternative.end_byte
                if val is not None and (bool(val)==bool(in_alt)):return False
                if val is None:uncertain=True
            p=p.parent
        return None if uncertain else True

    def permissions(self,ability,source):
        if ability in {'access_api','access_git'}:
            return self.result(evidence={'kind':'global_default_anonymous_permission','ability':ability,'file':'app/policies/global_policy.rb','line':64})
        if ability in self.public:
            return {'classification':'conditional_anonymous','evidence':[{'kind':'anonymous_permission','ability':ability,**source},{'kind':'public_policy_role',**self.policy_sources[ability]}],'conditions':[{'kind':'public_resource_policy','ability':ability,'requirement':'Public resource and applicable policy/feature/settings permit anonymous access'}],'gaps':[]}
        if ability in {'execute_graphql_mutation','admin_all_resources','access_admin_area','create_group','create_organization','read_instance_metadata'} or ability.startswith(('admin_','update_','destroy_','create_','delete_','push_','manage_')):
            return {'classification':'authenticated','evidence':[{'kind':'permission_requires_authenticated_role','ability':ability,**source}],'conditions':[],'gaps':[]}
        return {'classification':'unknown','evidence':[{'kind':'unresolved_permission','ability':ability,**source}],'conditions':[],'gaps':[{'kind':'anonymous_policy_unresolved','ability':ability,**source}]}

    def combine(self,results):
        classes=[r['classification'] for r in results]
        cls='authenticated' if 'authenticated' in classes else 'unknown' if 'unknown' in classes else 'conditional_anonymous' if 'conditional_anonymous' in classes else 'unauthenticated'
        return {'classification':cls,'evidence':dedup([e for r in results for e in r.get('evidence',[])]),'conditions':dedup([e for r in results for e in r.get('conditions',[])]),'gaps':dedup([e for r in results for e in r.get('gaps',[])])}

    def result(self,classification='unauthenticated',evidence=None,condition=None,gap=None):
        return {'classification':classification,'evidence':[evidence] if evidence else [],'conditions':[condition] if condition else [],'gaps':[gap] if gap else []}

    def analyze(self,owner,name,edition,verb,depth=0,trail=(),forced_uid=None):
        key=(owner,name,edition,verb,depth,forced_uid)
        if key in self.memo:return self.memo[key]
        if name=='authenticate_non_get!':
            return self.result('unauthenticated' if verb in {'GET','HEAD'} else 'authenticated',{'kind':'verb_dependent_auth','method':name,'verb':verb,'file':'lib/api/helpers.rb','line':397})
        if name=='authenticate_resource_owner!' and any(c.startswith('Doorkeeper::') for c in self.i.ancestors(owner,edition)):
            self.i.tree('config/initializers/doorkeeper.rb')
            return self.result('authenticated',{'kind':'configured_oauth_resource_owner_login','file':'config/initializers/doorkeeper.rb','line':13})
        if name=='authenticate_user!' and any(c.startswith('Devise::') for c in self.i.ancestors(owner,edition)):
            return self.result(evidence={'kind':'devise_authenticate_user_without_force_is_optional','file':'external/devise-4.9.4/lib/devise/controllers/helpers.rb','line':120})
        if name in {'require_no_authentication','require_no_authentication_without_flash'} and any(c.startswith('Devise::') for c in self.i.ancestors(owner,edition)):
            return self.result(evidence={'kind':'devise_guest_admission','method':name,'file':'external/devise-4.9.4/app/controllers/devise_controller.rb','line':1})
        if name in OPTIONAL:return self.result(evidence={'kind':'optional_authentication','method':name})
        if name in {'project','group','user_project','user_group','find_project!','find_group!','find_routable!'}:
            # Only this source-owned public-resource lookup contract is accepted.
            units=self.i.lookup(owner,name,edition)
            if units and self.i.units[units[0]]['owner'] in {'Projects::ApplicationController','Groups::ApplicationController','API::Helpers','RoutableActions'}:
                source={k:self.i.units[units[0]][k] for k in ['file','line']}
                ability='read_group' if 'group' in name else 'read_project'
                return self.permissions(ability,source)
        hits=[forced_uid] if forced_uid else self.i.lookup(owner,name,edition)
        if name in AUTH and (not hits or all(self.i.units[u]['owner'] in {'API::Helpers','EnforcesAdminAuthentication'} for u in hits)):
            return self.result('authenticated',{'kind':'mandatory_authentication','method':name,**({k:self.i.units[hits[0]][k] for k in ['file','line']} if hits else {'framework':'Devise/Rails'})})
        if not hits:
            if CREDENTIAL.search(name):return self.result('authenticated',{'kind':'mandatory_request_credential','method':name})
            if name.startswith('authorize_') and name.endswith('!'):
                permission=name[len('authorize_'):-1];p=self.permissions(permission,{'owner':owner,'method':name})
                p['evidence'].append({'kind':'dynamic_authorizer_convention','file':'app/controllers/projects/application_controller.rb','line':74})
                return p
            if name.startswith(('authenticate','authorize','require_','verify_','ensure_')):
                return self.result('unknown',gap={'kind':'auth_helper_definition_unresolved','owner':owner,'method':name})
            return self.result()
        if len(hits)>1:return self.result('unknown',gap={'kind':'auth_method_multiple_definitions','owner':owner,'method':name,'definitions':hits})
        uid=hits[0]
        if (self.i.units[uid]['owner'],name) in GUEST_SAFE:
            return self.result(evidence={'kind':'reused_guest_compatible_callback_review','owner':self.i.units[uid]['owner'],'method':name,**{k:self.i.units[uid][k] for k in ['file','line']},'prior_review':'frontend_gem_api_map/unauth_review/review_candidates.py'})
        if uid in trail:return self.result('unknown',gap={'kind':'auth_helper_cycle','unit':uid})
        if depth>=6:return self.result('unknown',gap={'kind':'auth_helper_depth_limit','unit':uid,'limit':6})
        node=self.i.unit_node(uid);body=fld(node,'body');u=self.i.units[uid]
        result=self.analyze_body(body,u['file'],owner,edition,verb,depth,trail+(uid,))
        if body and any(n.type in {'super','super_call'} and self.reachability(n,body,owner,edition,verb) is not False for n in walk(body)):
            chain=list(self.i.ancestors(owner,edition));position=chain.index(u['owner']) if u['owner'] in chain else len(chain)
            parent=next((c for c in chain[position+1:] if self.i.m.method_index.get((c,name,'instance'))),None)
            parent_uid=self.i.m.method_index[(parent,name,'instance')][0] if parent else None
            inherited=self.analyze(owner,name,edition,verb,depth+1,trail+(uid,),forced_uid=parent_uid) if parent else self.result('unknown',gap={'kind':'super_method_source_unresolved','owner':u['owner'],'method':name,'file':u['file'],'line':u['line']})
            result=self.combine([result,inherited])
        result['evidence'].insert(0,{'kind':'auth_method_reviewed','owner':u['owner'],'method':name,'file':u['file'],'line':u['line']})
        self.memo[key]=result;return result

    def analyze_body(self,body,file,owner,edition,verb,depth=0,trail=()):
        if body is None:return self.result('unknown',gap={'kind':'missing_auth_body','owner':owner,'file':file})
        results=[];nodes=list(walk(body,('method','singleton_method','class','module')))
        # A leading user-presence guard prevents subsequent callbacks from imposing a guest login.
        for child in body.named_children[:3]:
            if child.type in {'if_modifier','unless_modifier'}:
                cc=fld(child,'body');val=self.predicate(fld(child,'condition'),owner,edition,verb)
                if child.type=='unless_modifier' and val is not None:val=not val
                if cc is not None and cc.type=='return' and val is True:
                    return self.result(evidence={'kind':'anonymous_early_return','expression':txt(child),**location(file,child)})
        for n in nodes:
            if n.type not in {'call','identifier'}:continue
            name=method_name(n) if n.type=='call' else txt(n)
            if n.type=='identifier':
                p=n.parent
                if p and p.type in {'call','assignment','pair','method_parameters','optional_parameter','block_parameters','scope_resolution'}:continue
            reachable=self.reachability(n,body,owner,edition,verb)
            if reachable is False:continue
            rec=txt(fld(n,'receiver'));source=location(file,n)
            if name in DYNAMIC:
                results.append(self.result('unknown',gap={'kind':'dynamic_auth_control_dispatch','expression':txt(n).split('\n')[0],**source}))
                continue
            relevant=name in AUTH or name=='authenticate_non_get!' or CREDENTIAL.search(name) or name in OPTIONAL or name in {'user_project','user_group','find_source','find_source!','find_project!','find_group!'} or name.startswith(('authorize_','authenticate_','require_','verify_'))
            if name in {'can?','authorize!','authorize','authorize_action!','authorized_find!'}:
                vals=[literal(a) for a in positional(n)];abilities=[a for a in vals if a and a not in {'current_user','global'}]
                if abilities:rr=self.permissions(abilities[0],source)
                elif name in {'authorize!','authorize_action!','authorized_find!'}:rr=self.result('unknown',gap={'kind':'dynamic_auth_permission','expression':txt(n).split('\n')[0],**source})
                else:continue
                # can? may only select presentation/filtering; it is not itself a gate.
                if name=='can?':
                    parent=n.parent
                    if not parent or parent.type not in {'argument_list','unless_modifier','if_modifier','unless','if','unary'}:continue
                    if rr['classification']=='authenticated':rr=self.result('unknown',gap={'kind':'permission_predicate_usage','expression':txt(n).split('\n')[0],**source})
            elif relevant:
                if name=='authenticate_user!' and txt(options(n).get('force'))=='true':
                    rr=self.result('authenticated',{'kind':'forced_authentication',**source});results.append(rr);continue
                if rec not in {'','self'} and name not in AUTH and not CREDENTIAL.search(name):continue
                rr=self.analyze(owner,name,edition,verb,depth+1,trail)
            elif name in {'unauthorized!','access_denied!','authenticate_user!'}:
                rr=self.result('authenticated',{'kind':'authentication_denial',**source})
            elif name in {'redirect_to','render','head','raise','error!','forbidden!'} and re.search(r'\b(?:current_user|user_signed_in\?)\b',txt(n.parent)) and reachable is True:
                # Only explicit nil-user credential denials are decisive, ordinary 404s are not.
                parent=n.parent;s=txt(parent)
                if re.search(r'(?:unauthorized|sign_in|new_user_session|not_authenticated)',s):rr=self.result('authenticated',{'kind':'anonymous_denied','expression':s.split('\n')[0],**source})
                else:continue
            elif n.type=='call' and rec in {'current_user','@current_user'} and name not in {'nil?','blank?','present?','try','try!','is_a?','to_s','&'} and '&.' not in txt(n):
                rr=self.result('unknown',gap={'kind':'anonymous_user_dereference','expression':txt(n).split('\n')[0],**source})
            else:continue
            if reachable is None and rr['classification']=='authenticated':rr=self.result('unknown',gap={'kind':'conditional_credential_gate','expression':txt(n).split('\n')[0],**source})
            results.append(rr)
        return self.combine(results)

    def callbacks_for(self,owner,action,edition,verb):
        active={};results=[]
        for c in reversed(self.i.ancestors(owner,edition)):
            for cb in self.i.callbacks.get(c,[]):
                if cb['only_specified'] and action not in cb['only']:continue
                if action in cb['except']:continue
                val=True
                if cb['if'] is not None:
                    expression=txt(cb['if'])
                    expression=re.sub(r'action_name\s*==\s*[\"\']([^\"\']+)[\"\']',lambda m:'true' if action==m.group(1) else 'false',expression)
                    val=self.predicate_text(expression,owner,edition,verb)
                if cb['unless'] is not None:
                    v=self.predicate(cb['unless'],owner,edition,verb);val=not v if v is not None else None
                names=cb['names'] or [f"@block:{cb['source']['file']}:{cb['source']['line']}"]
                for name in names:
                    if cb['name'].startswith('skip'):
                        if val is True:active.pop(name,None)
                        elif val is None and name in active:active[name]=(active[name][0],None)
                    elif val is not False:active[name]=(cb,val)
        for name,(cb,val) in active.items():
            if name.startswith('@block:'):rr=self.analyze_body(block_body(cb['node']),cb['source']['file'],owner,edition,verb)
            else:rr=self.analyze(owner,name,edition,verb)
            if val is None and rr['classification']=='authenticated':
                if name=='authenticate_user!' and owner=='HelpController':rr=self.result('conditional_anonymous',{'kind':'public_visibility_setting_controls_login','file':'app/controllers/help_controller.rb','line':4},condition={'kind':'public_visibility_setting','requirement':'PUBLIC visibility is not restricted'})
                else:rr=self.result('unknown',gap={'kind':'conditional_auth_callback','callback':name,**cb['source']})
            rr['evidence'].append({'kind':'active_callback','callback':name,'conditional':val is None,**cb['source']});results.append(rr)
        return self.combine(results),[{'name':name,'owner':cb['owner'],'source':cb['source'],'conditional':val is None} for name,(cb,val) in active.items()]

    def rails(self,r):
        edition=r['edition'];owner=r.get('controller');action=r.get('action');verbs=r['http_methods']
        if any(s['name'] in {'authenticate','authenticated'} for s in r['route_auth_scopes']):return self.result('authenticated',{'kind':'route_authentication_scope','source':r['registration']})
        if r.get('engine_expansion') and not r.get('engine_verified'):return self.result('unknown',gap={'kind':'unverified_external_engine_expansion','engine':r['engine_expansion'],'source':r['registration']})
        if not owner:
            if r.get('handler_kind')=='redirect':return self.result(evidence={'kind':'route_redirect_no_auth_scope','source':r['registration']})
            if r.get('handler_kind')=='inline':
                n=self.i.at(r['registration']['file'],r['registration']['line'],types=['call'])
                target=options(n).get('to');body=block_body(target)
                if body is not None:
                    literal_response=re.search(r'\[\s*(\d{3})\s*,',txt(body))
                    if literal_response:
                        r['response_kind']='error_only' if int(literal_response.group(1))>=400 else 'inline_response'
                        return self.analyze_body(body,r['registration']['file'],'',edition,verbs[0])
            return self.result('unknown',gap={'kind':'http_registration_auth_unresolved','source':r['registration'],'target':r.get('target')})
        if owner not in self.i.classes:return self.result('unknown',gap={'kind':'controller_source_missing','controller':owner,'source':r['registration']})
        hits=self.i.lookup(owner,action or '',edition)
        if not hits:return self.result('unknown',gap={'kind':'registered_action_body_missing','controller':owner,'action':action,'source':r['registration']})
        if all(self.i.units[u].get('visibility') in {'private','protected'} for u in hits):return self.result('unknown',gap={'kind':'route_targets_nonpublic_method','controller':owner,'action':action,'source':r['registration']})
        output=[];callback_lists=[]
        for verb in verbs:
            cb,active=self.callbacks_for(owner,action,edition,verb);callback_lists.extend(active)
            # The whole action is checked for credential gates; normal service calls are not traced.
            act=self.analyze(owner,action,edition,verb)
            output.append(self.combine([cb,act]))
        result=self.combine(output);r['active_callbacks']=dedup(callback_lists);r['action_sources']=[{k:self.i.units[u][k] for k in ['file','line','end_line','owner']} for u in hits]
        if result['classification'] in {'unauthenticated','conditional_anonymous'}:
            result['evidence'].append({'kind':'registered_action_and_callbacks_reviewed','controller':owner,'action':action})
        return result

class GrapeInventory:
    def __init__(self,idx,auth,rails):self.i=idx;self.auth=auth;self.rails=rails;self.constant_values={};self.seen=set()

    def scalar(self,n,owner,file):
        v=literal(n)
        if n is None:return ''
        if n.type in {'constant','scope_resolution'}:
            for a in walk(self.i.tree(file)):
                if a.type=='assignment' and txt(fld(a,'left')).split('::')[-1]==txt(n).split('::')[-1]:
                    r=literal(fld(a,'right'))
                    if r is not None:return r
            return '<'+txt(n)+'>'
        return v if v is not None else '<'+txt(n)+'>'

    def scopes(self,node,file,owner):
        path=[];version=None;conditions=[];p=node.parent
        while p and p.type not in {'class','module'}:
            if p.type=='call':
                name=method_name(p);pos=positional(p)
                if name in {'namespace','resource','resources','group','segment','route_param'} and pos:
                    part=self.scalar(pos[0],owner,file)
                    path.insert(0,':'+part if name=='route_param' and not part.startswith(':') else part)
                elif name=='version' and pos:version=self.scalar(pos[0],owner,file)
            if p.type in {'if','unless','if_modifier','unless_modifier'}:conditions.append({'kind':'registration_condition','expression':txt(fld(p,'condition')),**location(file,p)})
            p=p.parent
        return path,version,conditions

    def loop_paths(self,path,node,file):
        variants=[(path,{})];p=node.parent
        while p and p.type not in {'class','module'}:
            if p.type=='call' and method_name(p)=='each':
                receiver=fld(p,'receiver');values=Routes(self.i).value(receiver,{})
                params=fld(fld(p,'block'),'parameters');parameter=txt(params.named_children[0]) if params and params.named_children else None
                if isinstance(values,list) and parameter:
                    out=[]
                    for template,env in variants:
                        for value in values:
                            if not isinstance(value,str):continue
                            transformed=template
                            for suffix,result in [('.pluralize',inflection.pluralize(value)),('.underscore',inflection.underscore(value)),('',value)]:
                                transformed=transformed.replace('<'+parameter+suffix+'>',result).replace('#{'+parameter+suffix+'}',result)
                            if transformed.startswith('/<"'):transformed=transformed.replace('<"','').replace('">','')
                            out.append((transformed,{**env,parameter:value}))
                    variants=out
                else:self.i.gap('dynamic_grape_registration_loop',location(file,p),expression=txt(p).split('\n')[0])
            p=p.parent
        return variants

    def config(self,owner,edition):
        prefix=None;version=None
        for c in reversed(self.i.ancestors(owner,edition)):
            self.i.facts(c)
            for file,node in self.i.class_nodes.get(c,[]):
                for n in walk(fld(node,'body'),('method','singleton_method','class','module')):
                    if n.type=='call' and method_name(n) in {'prefix','version'} and not block_body(n):
                        pos=positional(n)
                        if pos:
                            value=self.scalar(pos[0],c,file)
                            if method_name(n)=='prefix':prefix=value
                            else:version=value
        return prefix,version

    def hooks(self,owner,edition,site_file=None,site_node=None):
        found=[]
        for c in self.i.ancestors(owner,edition):
            self.i.facts(c)
            for file,node in self.i.class_nodes.get(c,[]):
                for n in walk(fld(node,'body'),('method','singleton_method','class','module')):
                    if n.type!='call' or method_name(n) not in {'before','before_validation','after_validation'} or not block_body(n):continue
                    path,version,conds=self.scopes(n,file,c)
                    scope_nodes=[];p=n.parent
                    while p and p!=node:
                        if p.type=='call' and method_name(p) in {'namespace','resource','resources','group','segment','route_param','version'}:scope_nodes.append(p)
                        p=p.parent
                    if scope_nodes and (file!=site_file or site_node is None or not all(s.start_byte<=site_node.start_byte<s.end_byte for s in scope_nodes)):continue
                    found.append((file,n,c))
        return found

    def run(self):
        records=[]
        root_mounts=[r for r in self.rails if r['type']=='http_registration' and r.get('target','').lstrip(':')=='API::API']
        for rm in root_mounts:
            edition=rm['edition'];queue=collections.deque([('API::API',rm['path'],[],rm['conditions'],[],None,False)])
            visited=set()
            while queue:
                owner,prefix,parent_hooks,conditions,mount_chain,inherited_version,version_consumed=queue.popleft();key=(owner,prefix)
                if key in visited:continue
                visited.add(key);self.i.facts(owner)
                config_prefix,config_version=self.config(owner,edition)
                config_version=config_version or inherited_version
                baseprefix=join(prefix,config_prefix or '')
                hooks=parent_hooks+self.hooks(owner,edition)
                owners=set(self.i.ancestors(owner,edition))
                # Include endpoint blocks from explicitly included endpoint concerns.
                entries=[e for e in self.i.original if e['type']=='grape_endpoint' and e['class_or_field'] in owners and (edition=='ee' or not e['source']['file'].startswith('ee/'))]
                for e in entries:
                    if not e['roots']:continue
                    n=self.i.unit_node(e['roots'][0]);file=e['source']['file'];path,version,localconds=self.scopes(n,file,e['class_or_field'])
                    version=version or config_version;pos=positional(n);verb=method_name(n).upper()
                    if verb=='ROUTE':
                        verb=(literal(pos[0]) or 'ANY').upper();pos=pos[1:]
                    suffix=self.scalar(pos[0],owner,file) if pos else ''
                    if suffix.startswith('<') or any(p.startswith('<') for p in path):self.i.gap('dynamic_grape_path',e['source'],owner=owner,path=path+[suffix])
                    finalpath=join(baseprefix,(version or '') if not version_consumed else '',*path,suffix)
                    if version_consumed and version!=inherited_version:self.i.gap('grape_version_override_not_expanded',e['source'],version=version,inherited_version=inherited_version)
                    rs=[]
                    # Local hooks matched against this endpoint's lexical scopes, plus mounted-parent hooks.
                    for f,b,c in dedup_hooks(parent_hooks+self.hooks(owner,edition,file,n)):
                        rs.append(self.auth.analyze_body(block_body(b),f,owner,edition,verb))
                    rs.append(self.auth.analyze_body(block_body(n),file,owner,edition,verb))
                    r={'type':'grape_endpoint','edition':edition,'http_methods':[verb],'path':finalpath,'class':owner,'action':verb,'registration':e['source'],'registration_status':'mounted_grape_endpoint','conditions':conditions+localconds,'mount_chain':mount_chain,'baseline_ids':[e['id']],'auth':self.auth.combine(rs),'response_kind':'error_only' if '*path' in suffix and 'error!' in txt(block_body(n)) else 'application'}
                    for concrete,bindings in self.loop_paths(finalpath,n,file):
                        rr=copy.deepcopy(r);rr['path']=concrete;rr['registration_bindings']=bindings
                        rr['id']=stable_id([edition,'grape',owner,concrete,verb,file,e['source']['line']]);records.append(rr)
                for mt in self.i.mounts:
                    if mt['owner'] not in owners:continue
                    file=mt['file'];n=mt['node'];pos=positional(n)
                    if not pos:continue
                    target=txt(pos[0]).lstrip(':')
                    if target not in self.i.classes:
                        self.i.gap('unresolved_grape_mount',location(file,n),target=target);continue
                    path,version,localconds=self.scopes(n,file,mt['owner'])
                    # Versions/prefixes inherited once; child config should not append the parent's version again.
                    child_prefix=join(baseprefix,(version or config_version or '') if not version_consumed else '',*path)
                    mh=parent_hooks+self.hooks(owner,edition,file,n)
                    queue.append((target,child_prefix,mh,conditions+localconds,mount_chain+[{'class':target,**location(file,n)}],version or config_version,True))
        return dedup(records)


def dedup_hooks(hooks):return list({(f,n.start_byte,c):(f,n,c) for f,n,c in hooks}.values())


class GraphqlInventory:
    def __init__(self,idx,auth):self.i=idx;self.auth=auth;self.fields={};self.types={};self.decl_by_owner={};self.type_names={}

    def load(self):
        for file in self.i.tracked:
            if file.endswith('.rb') and (file.startswith('app/graphql/') or file.startswith('ee/app/graphql/')):self.i.scan_classes(file)
        for d in self.i.declarations:
            owner=d['owner'];self.decl_by_owner.setdefault(owner,[]).append(d)
            if d['name']=='graphql_name' and positional(d['node']):self.type_names[owner]=literal(positional(d['node'])[0])

    def refs(self,n):
        if n is None:return []
        return list(dict.fromkeys(txt(c).lstrip(':') for c in walk(n) if c.type in {'scope_resolution','constant'} and (c.parent is None or c.parent.type!='scope_resolution') and (txt(c).lstrip(':').startswith(('Types::','Mutations::','GraphQL::Types::')))))

    def declarations(self,owner,edition,name):
        out=[]
        for c in self.i.ancestors(owner,edition):
            for d in self.decl_by_owner.get(c,[]):
                if d['name']==name and (edition=='ee' or not d['file'].startswith('ee/')):out.append(d)
        return out

    def field_declarations(self,owner,edition,seen=None):
        seen=set() if seen is None else seen
        if owner in seen:return []
        seen.add(owner);out=self.declarations(owner,edition,'field')
        for d in self.declarations(owner,edition,'implements'):
            for interface in self.refs(d['node']):out+=self.field_declarations(interface,edition,seen)
        return out

    def fields_for(self,owner,edition):
        found={}
        # Ruby lookup precedence: nearer declarations override inherited same-name fields.
        for d in self.field_declarations(owner,edition):
            n=d['node'];pos=positional(n);opts=options(n)
            if not pos:continue
            name=literal(pos[0])
            if not name:self.i.gap('dynamic_graphql_field',location(d['file'],n),owner=owner);continue
            actual=name if txt(opts.get('camelize'))=='false' else camel(name)
            if actual in found:continue
            resolver=txt(opts.get('resolver'));resolverclass=(self.refs(opts.get('resolver')) or [resolver.split('.')[0].lstrip(':')])[0]
            fieldtype=pos[1] if len(pos)>1 else opts.get('type');refs=self.refs(fieldtype)
            type_expression=txt(fieldtype)
            if not refs and resolverclass:
                typeds=self.declarations(resolverclass,edition,'type')
                if typeds:
                    typenode=positional(typeds[0]['node'])[0];refs=self.refs(typenode);type_expression=txt(typenode)
            refs=[r for r in refs if r in self.i.classes and r.startswith(('Types::','Mutations::'))]
            found[actual]={'name':actual,'ruby_name':name,'owner':owner,'declaration_owner':d['owner'],'resolver':resolverclass or owner,'resolver_expression':resolver,'method':literal(opts.get('resolver_method')) or literal(opts.get('method')) or name,'types':refs,'type_expression':type_expression,'result_steps':['nodes'] if '.connection_type' in type_expression else ['node'] if '.edge_type' in type_expression else [],'source':location(d['file'],n),'authorize':symbols(opts.get('authorize')),'node':n,'file':d['file']}
        for macro in ['mount_mutation','mount_aliased_mutation']:
            for d in self.declarations(owner,edition,macro):
                pos=positional(d['node']);cls=txt(pos[1] if macro=='mount_aliased_mutation' and len(pos)>1 else pos[0]).lstrip(':') if pos else None
                if not cls:continue
                explicit=literal(pos[0]) if macro=='mount_aliased_mutation' else self.type_names.get(cls)
                name=camel(inflection.underscore(explicit or cls.split('::')[-1]))
                if name not in found:found[name]={'name':name,'ruby_name':inflection.underscore(name),'owner':owner,'declaration_owner':d['owner'],'resolver':cls,'resolver_expression':cls,'method':'resolve','types':[cls],'source':location(d['file'],d['node']),'authorize':[],'mutation':True,'node':d['node'],'file':d['file']}
        return list(found.values())

    def authorize(self,f,edition,root_kind):
        results=[];owner=f['owner'];resolver=f['resolver']
        if f.get('mutation') or 'Mutations::BaseMutation' in self.i.ancestors(resolver,edition):
            gates=self.i.lookup(resolver,'authorized?',edition,'singleton')
            if not gates or all(self.i.units[u]['owner']=='Mutations::BaseMutation' for u in gates):
                return self.auth.result('authenticated',{'kind':'mutation_anonymous_policy_denial','file':'app/policies/global_policy.rb','line':61})
            return self.auth.result('unknown',gap={'kind':'graphql_mutation_authorized_override','resolver':resolver,'definitions':gates})
        for c in {owner,resolver}:
            permissions=[]
            for d in self.declarations(c,edition,'authorize'):
                permissions.extend(symbols(d['node']))
            for a in permissions+f['authorize']:results.append(self.auth.permissions(a,f['source']))
            if c==resolver and resolver!=owner:
                # Custom authorization/ready? gates are reviewed as authentication declarations.
                for method,kind in [('authorized?','singleton'),('ready?','instance'),('resolve','instance')]:
                    us=self.i.lookup(c,method,edition,kind)
                    for uid in us:
                        u=self.i.units[uid]
                        if u['owner'] in {'Resolvers::BaseResolver','LooksAhead','Types::BaseObject'}:continue
                        n=self.i.unit_node(uid);results.append(self.auth.analyze_body(fld(n,'body'),u['file'],c,edition,'POST'))
        if resolver==owner:
            units=self.i.lookup(owner,f['method'],edition)
            for uid in units:
                u=self.i.units[uid];results.append(self.auth.analyze_body(fld(self.i.unit_node(uid),'body'),u['file'],owner,edition,'POST'))
            if not units and not f['types']:
                results.append(self.auth.result('unknown',gap={'kind':'graphql_default_property_resolver','field':f['name'],'owner':owner,**f['source']}))
        return self.auth.combine(results)

    def run(self):
        self.load();records=[];used_declarations=set()
        for edition in ['ce','ee']:
            for kind,root in [('query','Types::QueryType'),('mutation','Types::MutationType'),('subscription','Types::SubscriptionType')]:
                queue=collections.deque([(root,[],self.auth.result(),0)]);visited={}
                while queue:
                    owner,path,parent_auth,depth=queue.popleft()
                    prev=visited.get(owner)
                    # Preserve one shortest field path for each owner/classification; never enumerate recursive query strings.
                    visitkey=(owner,parent_auth['classification'])
                    if visitkey in visited:continue
                    visited[visitkey]=True
                    for d in self.declarations(owner,edition,'possible_types'):
                        for typ in self.refs(d['node']):
                            if typ in self.i.classes:queue.append((typ,path+['... on '+(self.type_names.get(typ) or typ.split('::')[-1])],parent_auth,depth+1))
                    fields=self.fields_for(owner,edition)
                    for f in fields:
                        ownauth=self.authorize(f,edition,kind);fullauth=self.auth.combine([parent_auth,ownauth]);fieldpath=path+[f['name']]
                        response_kind='application'
                        if depth==0 and f['ruby_name']=='current_user':response_kind='nullable_identity'
                        r={'type':'graphql_'+kind if depth==0 else 'graphql_field','edition':edition,'http_methods':['GET','POST'] if kind=='query' else ['POST'],'path':'/api/graphql','graphql':{'operation':kind,'type':self.type_names.get(owner) or owner.split('::')[-1],'field':f['name'],'ruby_field':f['ruby_name'],'schema_path':fieldpath,'resolver_class':f['resolver'],'resolver_method':f['method'],'result_types':f['types'],'result_type_expression':f.get('type_expression'),'generated_result_steps':f.get('result_steps',[]),'resolver_expression':f['resolver_expression']},'registration':f['source'],'registration_status':'root_schema_registration' if depth==0 else 'static_result_type_path','conditions':[],'auth':fullauth,'response_kind':response_kind}
                        r['id']=stable_id([edition,kind,owner,f['name'],f['source']['file'],f['source']['line'],parent_auth['classification']]);records.append(r)
                        used_declarations.add((f['source']['file'],f['source']['line']))
                        for typ in f['types']:
                            pa=fullauth
                            if depth==0 and f['ruby_name']=='current_user':pa=self.auth.result('authenticated',{'kind':'anonymous_parent_result_is_nil','field':'currentUser','file':'app/graphql/types/base_object.rb','line':57})
                            if depth>=32:
                                self.i.gap('graphql_type_graph_limit',f['source'],type=typ,limit=32);continue
                            steps=f.get('result_steps',[])
                            if steps:self.i.gap('graphql_generated_wrapper_fields',f['source'],type=typ,note='Conventional nodes/node witness path; generated edges, cursor, pageInfo and custom connection fields require framework expansion')
                            queue.append((typ,fieldpath+steps,pa,depth+1))
                if kind=='subscription':
                    for r in records:
                        if r['edition']==edition and r['graphql']['operation']=='subscription':
                            r['auth']=self.auth.result('unknown',gap={'kind':'subscription_transport_authorization_unresolved','source':r['registration']})
        for d in self.i.declarations:
            if d['name'] in {'field','mount_mutation','mount_aliased_mutation'} and (d['file'],d['node'].start_point.row+1) not in used_declarations:
                self.i.gap('graphql_declaration_no_static_schema_path',location(d['file'],d['node']),owner=d['owner'])
        return records

def other_registrations(idx,auth):
    records=[]
    # Preserve existing Rack registrations; middleware 'use' is not itself an HTTP entrypoint.
    for e in idx.original:
        if e['type']!='http_registration' or e['action'] not in {'map','run','mount'} or e['source']['file'].startswith(('config/routes','ee/config/routes','lib/api','ee/lib/api')):continue
        if e['action']!='map':
            idx.gap('rack_registration_without_concrete_path',e['source'],baseline_id=e['id'],target=e.get('target'));continue
        paths=[r.get('path') for r in e['routes'] if r.get('path')]
        if not paths:
            m=re.search(r'map\s+[\'\"]([^\'\"]+)',e.get('declaration',''))
            if m:paths=[m.group(1)]
        if not paths:idx.gap('rack_map_path_unresolved',e['source'],baseline_id=e['id']);continue
        for edition in ['ce','ee']:
            if edition=='ce' and e['source']['file'].startswith('ee/'):continue
            for path in paths:
                r={'type':'rack_registration','edition':edition,'path':path,'http_methods':['ANY'],'registration':e['source'],'registration_status':'rack_map','target':e.get('target'),'conditions':[],'auth':auth.result('unknown',gap={'kind':'rack_handler_auth_unresolved','source':e['source']}),'baseline_ids':[e['id']]};r['id']=stable_id([edition,'rack',path,e['source']]);records.append(r)
    # Explicit non-Rails health registration, source-confirmed network allowlist condition.
    for edition in ['ce','ee']:
        r={'type':'middleware_endpoint','edition':edition,'path':'/-/health','http_methods':['ANY'],'registration':{'file':'lib/gitlab/middleware/basic_health_check.rb','line':17},'registration_status':'literal_middleware_path','class':'Gitlab::Middleware::BasicHealthCheck','conditions':[{'kind':'client_ip_allowlist','setting':'Settings.monitoring.ip_whitelist'}],'auth':auth.result('conditional_anonymous',{'kind':'network_allowlist_without_login','file':'lib/gitlab/middleware/basic_health_check.rb','line':35},condition={'kind':'client_ip_allowlist','setting':'Settings.monitoring.ip_whitelist'}),'response_kind':'application'};r['id']=stable_id([edition,'middleware','/-/health']);records.append(r);idx.tree(r['registration']['file'])
    for edition in ['ce','ee']:
        for path in ['/readiness','/liveness']:
            r={'type':'health_listener_endpoint','edition':edition,'path':path,'http_methods':['ANY'],'registration':{'file':'lib/gitlab/health_checks/middleware.rb','line':13 if path=='/readiness' else 14},'registration_status':'dedicated_health_listener','listener':'Gitlab::HealthChecks::Server (separate listener, not a main Rails URL)','conditions':[{'kind':'dedicated_listener','requirement':'Health-check listener enabled and network-reachable'}],'auth':auth.result('conditional_anonymous',{'kind':'health_listener_no_identity_gate','file':'lib/gitlab/health_checks/middleware.rb','line':11}),'response_kind':'application'};r['id']=stable_id([edition,'health_listener',path]);records.append(r)
    idx.tree('lib/gitlab/health_checks/middleware.rb');idx.tree('lib/gitlab/health_checks/server.rb')
    for edition in ['ce','ee']:
        r={'type':'websocket_registration','edition':edition,'path':'/-/cable','http_methods':['GET'],'registration':{'file':'config/initializers/action_cable.rb','line':6},'registration_status':'configured_action_cable_mount','class':'ApplicationCable::Connection','action':'connect','conditions':[{'kind':'websocket_handshake','requirement':'Enabled transport, allowed origin and normal handshake'}],'auth':auth.result('unauthenticated',{'kind':'anonymous_websocket_connection_admitted','file':'app/channels/application_cable/connection.rb','line':15}),'response_kind':'websocket_transport'};r['id']=stable_id([edition,'cable','/-/cable']);records.append(r)
    for file in ['config/initializers/action_cable.rb','app/channels/application_cable/connection.rb','app/channels/application_cable/channel.rb','app/channels/graphql_channel.rb']:idx.tree(file)
    idx.gap('websocket_channel_authorization_separate',{'file':'app/channels/application_cable/channel.rb','line':9},note='Anonymous connection admission does not prove admission to every channel/subscription; channel policy and token callbacks remain separate')
    # Workhorse dispatch rules are proxy registrations, not independently proven public routes.
    file='workhorse/internal/upstream/routes.go';data=(idx.source/file).read_text();idx.files[file]={'file':file,'sha256':digest(data.encode()),'bytes':len(data.encode()),'parse_errors':None,'parser':'literal Go route registration extraction'}
    for m in re.finditer(r'newRoute\(\s*([^,\n]+)\s*,\s*"([^"]+)"\s*,\s*(\w+)\s*\)',data):
        expression=m.group(1).strip();literal_regex=re.fullmatch(r'("(?:[^"\\]|\\.)*"|`[^`]*`)',expression)
        path=expression[1:-1] if literal_regex else None;line=data[:m.start()].count('\n')+1
        if path is None:idx.gap('dynamic_workhorse_regex',{'file':file,'line':line},expression=expression)
        r={'type':'workhorse_dispatch_registration','edition':'shared','path_regex':path,'path_expression':expression,'path':None,'http_methods':['UNKNOWN'],'registration':{'file':file,'line':line},'registration_status':'proxy_dispatch_rule','target':m.group(2),'backend':m.group(3),'conditions':[],'auth':auth.result('unknown',gap={'kind':'proxy_dispatch_auth_delegates_to_handler_backend','file':file,'line':line}),'response_kind':'proxy'};r['id']=stable_id(['workhorse',line,expression]);records.append(r)
    return records


def routing_snapshot(idx,auth,records):
    file='config/routing/gitlab_routes.json';p=idx.source/file
    if not p.exists():return [],{'available':False}
    data=p.read_bytes();snapshot=json.loads(data);idx.files[file]={'file':file,'sha256':digest(data),'bytes':len(data),'parse_errors':0,'parser':'committed JSON route snapshot (not regenerated)'}
    normalize=lambda path:re.sub(r'\(\.:format\)|\.:format','',path).rstrip('/').replace('/api/:version/','/api/v4/') or '/'
    by_path=collections.defaultdict(list)
    for r in records:
        if r.get('path') and not r['type'].startswith('graphql'):by_path[normalize(r['path'])].append(r['id'])
    registrations=list(re.finditer(r'"template"\s*:\s*("(?:[^"\\]|\\.)*")',data.decode()))
    comparison=[];supplement=[]
    for row,match in zip(snapshot,registrations):
        path=row['template'];ids=by_path.get(normalize(path),[]);matched=bool(ids);line=data[:match.start()].count(b'\n')+1
        if not ids:
            r={'type':'snapshot_http_registration','edition':'ee','path':path,'http_methods':['UNKNOWN'],'registration':{'file':file,'line':line},'registration_status':'committed_routing_snapshot','conditions':[{'kind':'snapshot_configuration','requirement':'EE CI/test route snapshot with example configuration; method/handler/configuration not stored'}],'auth':auth.result('unknown',gap={'kind':'snapshot_path_handler_and_auth_unresolved','file':file,'line':line}),'response_kind':'unknown'};r['id']=stable_id(['snapshot',path]);supplement.append(r);ids=[r['id']]
        comparison.append({'template':path,'entrypoint_ids':ids,'matched_source_registration':matched})
    return supplement,{'available':True,'file':file,'sha256':digest(data),'template_count':len(snapshot),'source_matched_templates':len(snapshot)-len(supplement),'supplemental_unknown_templates':len(supplement),'normalization':'Strip optional format suffix, trailing slash; compare Grape /api/:version with explicitly declared /api/v4. This does not admit arbitrary versions.','configuration_source':{'file':'lib/tasks/gitlab/cells/routes.rake','line':42},'templates':comparison}


def build(args):
    source=Path(args.source);baseline=Path(args.baseline);output=Path(args.output);output.mkdir(exist_ok=True,parents=True)
    if git(source,'status','--porcelain','--untracked-files=no'):raise ValueError('GitLab tracked source must be clean; cached source facts cannot describe a dirty tree')
    idx=Index(source,Path(args.cache) if args.cache else None,baseline,Path(args.engine_source));auth=AuthCheck(idx)
    route_builder=Routes(idx);rails=route_builder.run();print('Expanded',len(rails),'Rails registrations',flush=True)
    for j,r in enumerate(rails):
        r['auth']=auth.rails(r)
        if j and j%1500==0:print('Reviewed',j,'Rails registrations',flush=True)
    grapes=GrapeInventory(idx,auth,rails).run();print('Expanded and reviewed',len(grapes),'mounted Grape endpoints',flush=True)
    graphql=GraphqlInventory(idx,auth).run();print('Mapped',len(graphql),'GraphQL schema fields',flush=True)
    for r in graphql:
        transport=[x for x in rails if x['edition']==r['edition'] and x.get('controller')=='GraphqlController' and x.get('action')=='execute' and x.get('path')==r['path']]
        if not transport:r['auth']=auth.combine([r['auth'],auth.result('unknown',gap={'kind':'graphql_http_transport_not_resolved'})])
        else:
            field_auth=r['auth'];transport_auth=auth.combine([x['auth'] for x in transport]);combined=auth.combine([field_auth,transport_auth])
            combined['evidence']=field_auth['evidence']+[{'kind':'graphql_http_transport_auth','entrypoint_ids':[x['id'] for x in transport]}]
            combined['gaps']=field_auth['gaps']+([{'kind':'graphql_http_transport_auth_unresolved','entrypoint_ids':[x['id'] for x in transport]}] if transport_auth['classification']=='unknown' else [])
            r['auth']=combined
            r['transport_entrypoint_ids']=[x['id'] for x in transport]
    all_records=rails+grapes+graphql+other_registrations(idx,auth)
    supplemental,snapshot_comparison=routing_snapshot(idx,auth,all_records);all_records+=supplemental
    # Registration/context predicates constrain availability independently of login requirements.
    for r in all_records:
        r['conditions']=dedup(r.get('conditions',[])+r['auth'].pop('conditions',[]))
        r['auth']['runtime_verified']=False
        r['auth']['confidence']='source_supported' if r['auth']['classification'] in {'unauthenticated','conditional_anonymous'} else 'source_inferred' if r['auth']['classification']=='authenticated' else 'unresolved'
        r['gitlab_commit_sha']=idx.sha
        r['anonymous_access']=r['auth']['classification'] in {'unauthenticated','conditional_anonymous'} and r.get('response_kind')!='error_only'
        if (r.get('engine_expansion') and not r.get('engine_verified')) or '<' in (r.get('path') or '') or '<unresolved>' in (r.get('path') or ''):
            r['registration_status']='unresolved_registration'
            r['auth']['classification']='unknown';r['anonymous_access']=False
        r['evidence_scope']='source declarations and bounded auth-control review; not deployed reachability proof'
        r['conditions'].append({'kind':'deployment','requirement':'Ordinary routing, enabled features, valid request and deployed edition/configuration'})
        r['conditions'].append({'kind':'url_prefix','setting':'Gitlab.config.gitlab.relative_url_root','requirement':'Prepend the configured installation URL prefix to main-listener paths'})
        if r['auth']['classification']=='unauthenticated' and any(c['kind'] in {'registration_condition','route_constraint','client_ip_allowlist','public_resource_policy'} for c in r['conditions']):
            r['auth']['classification']='conditional_anonymous'
        r['auth']['confidence']='source_supported' if r['auth']['classification'] in {'unauthenticated','conditional_anonymous'} else 'source_inferred' if r['auth']['classification']=='authenticated' else 'unresolved'
    all_records=list({r['id']:r for r in all_records}.values());all_records.sort(key=lambda r:(r['edition'],r['type'],r.get('path') or '',r.get('graphql',{}).get('schema_path',[]),r['id']))
    for r in all_records:
        for gap in r['auth'].get('gaps',[]):idx.gaps.append({'entrypoint_id':r['id'],**gap})
    old_by_source=collections.defaultdict(list)
    for e in idx.original:old_by_source[(e['source']['file'],e['source']['line'])].append(e['id'])
    used_old=set()
    for r in all_records:
        existing=set(r.get('baseline_ids',[]));existing.update(old_by_source.get((r['registration']['file'],r['registration']['line']),[]));r['baseline_ids']=sorted(existing);used_old.update(existing)
    omitted=[]
    for e in idx.original:
        if e['id'] not in used_old:
            omitted.append({'baseline_id':e['id'],'type':e['type'],'source':e['source'],'identifier':e['class_or_field'],'action':e['action'],'reason':'public Ruby method or standalone resolver is not a registration' if e['discovery'].startswith(('public controller','resolver body')) else 'no reconstructed static registration/schema path; retained for coverage review'})
    evidence_table={};callback_table={};gap_table={}
    for r in all_records:
        evidence=r['auth'].pop('evidence',[])
        keys=[]
        for e in evidence:
            key='ev_'+stable_id(e)[3:];evidence_table[key]=e;keys.append(key)
        r['auth']['evidence_ids']=keys
        gapkeys=[]
        for g in r['auth'].pop('gaps',[]):
            key='gap_'+stable_id(g)[3:];gap_table[key]=g;gapkeys.append(key)
        r['auth']['gap_ids']=gapkeys
        if 'active_callbacks' in r:
            callbacks=r.pop('active_callbacks');key='cb_'+stable_id(callbacks)[3:];callback_table[key]=callbacks;r['auth']['callback_pipeline_id']=key
    meta={'schema_version':1,'gitlab_commit_sha':idx.sha,'definition':'Unauthenticated means no authenticated user session or request credential required; public-resource/feature/network predicates are separate conditions. Null/empty GraphQL responses are distinguished where known.','method':'static_source_review','runtime_verified':False,'complete':False,'source_index_reuse':idx.reuse,'bounds':{'auth_helper_depth':6,'graphql_type_path_depth':32,'graphql_paths':'one shortest witness per type/auth classification; cycles collapsed'},'external_engine_sources':idx.engine_sources,'baseline_file':str(baseline/'entrypoints.jsonl.gz') if (baseline/'entrypoints.jsonl.gz').exists() else None,'baseline_sha256':digest((baseline/'entrypoints.jsonl.gz').read_bytes()) if (baseline/'entrypoints.jsonl.gz').exists() else None,'baseline_entrypoints':len(idx.original),'counts':{'registered_entrypoint_records':len(all_records),'anonymous_access_records':sum(r['anonymous_access'] for r in all_records),'anonymous_http_records':sum(r['anonymous_access'] and not r['type'].startswith('graphql') for r in all_records),'anonymous_graphql_records':sum(r['anonymous_access'] and r['type'].startswith('graphql') for r in all_records),'by_auth':dict(collections.Counter(r['auth']['classification'] for r in all_records)),'by_type':dict(collections.Counter(r['type'] for r in all_records)),'by_edition':dict(collections.Counter(r['edition'] for r in all_records)),'route_files_examined':len(route_builder.drawn),'source_files_examined':len(idx.files),'discovery_source_files':len(idx.m.files),'committed_snapshot_templates':snapshot_comparison.get('template_count',0),'source_matched_snapshot_templates':snapshot_comparison.get('source_matched_templates',0),'gap_categories':dict(collections.Counter(g['kind'] for g in idx.gaps))},'limitations':['Static source support does not prove a running deployment returns an admitted application response.','Dynamic Ruby, policy outcomes, custom engines, URL shadowing, runtime autoload and configuration remain unresolved where recorded.','Unknown records must not be treated as either private or public.','CE and EE are separate profiles; organization aliases are separate route registrations. GraphQL fields are not separate HTTP paths.','Framework-generated GraphQL connection/edge/interface/introspection members and runtime-resolved types are not fully expanded.','The committed EE routing snapshot is reused as a path universe; unresolved handler/method entries remain unknown.','Implicit HTTP HEAD, framework OPTIONS, assets, reverse-proxy configuration and environment-dependent engines are not fully enumerated.']}
    def write(name,obj):(output/name).write_text(json.dumps(obj,sort_keys=True,separators=(',',':'))+'\n')
    write('evidence.json',{'metadata':{'gitlab_commit_sha':idx.sha,'schema_version':1},'evidence':evidence_table,'callback_pipelines':callback_table,'gaps':gap_table})
    write('entrypoints.json',{'metadata':meta,'entrypoints':all_records})
    write('unauthenticated.json',{'metadata':meta,'count':sum(r['anonymous_access'] for r in all_records),'entrypoints':[r for r in all_records if r['anonymous_access']]})
    for name,graphql_only in [('http_unauthenticated.json',False),('graphql_unauthenticated.json',True)]:
        rows=[r for r in all_records if r['anonymous_access'] and r['type'].startswith('graphql')==graphql_only];write(name,{'metadata':meta,'count':len(rows),'entrypoints':rows})
    for name,classification in [('unconditional.json','unauthenticated'),('conditional_anonymous.json','conditional_anonymous'),('authenticated.json','authenticated'),('unknown.json','unknown')]:
        rows=[r for r in all_records if r['auth']['classification']==classification];write(name,{'metadata':meta,'count':len(rows),'entrypoints':rows})
    indexed_files={r['file'] for r in idx.m.files}
    skipped=[{'file':f,'reason':'Outside the reused production Ruby/Rack source index; test, documentation, vendor, migration or tooling scope'} for f in idx.tracked if f.endswith(('.rb','.ru')) and f not in indexed_files]
    signature_groups=collections.defaultdict(list)
    for r in all_records:
        if r.get('path') and not r['type'].startswith('graphql') and r['type']!='snapshot_http_registration':
            for verb in r['http_methods']:signature_groups[(r['edition'],verb,r['path'])].append(r)
    collisions=[{'edition':edition,'method':verb,'path':path,'entrypoint_ids':[r['id'] for r in records],'auth_classifications':sorted({r['auth']['classification'] for r in records}),'reason':'Same declared path/verb; constraints, formats, settings and route precedence require review'} for (edition,verb,path),records in signature_groups.items() if len(records)>1]
    write('coverage.json',{'metadata':meta,'gaps':dedup(idx.gaps),'route_signature_collisions':collisions,'baseline_records_without_reconstructed_registration':omitted,'source_files':sorted(idx.files.values(),key=lambda r:r['file']),'discovery_source_files':idx.m.files,'skipped_ruby_rack_files':skipped,'route_file_expansions':dedup(route_builder.visited),'committed_routing_snapshot_comparison':snapshot_comparison})
    write('summary.json',meta)
    print(json.dumps(meta['counts'],indent=2),flush=True)


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--source',default='/workspace/gitlab-frontend-source');p.add_argument('--baseline',default='frontend_gem_api_map');p.add_argument('--output',default='unauthenticated_entrypoints');p.add_argument('--cache',default='/workspace/scratch/unauth-review-source.pickle');p.add_argument('--engine-source',default='/workspace/auth-route-engine-sources');build(p.parse_args())

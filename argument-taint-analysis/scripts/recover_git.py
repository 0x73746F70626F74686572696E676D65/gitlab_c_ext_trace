#!/usr/bin/env python3
"""Reclone recorded native repositories at exact commits, including gitlinks.

Only Git object reads and native source extraction occur. No checkout, hook,
gemspec, build script or extension is executed.
"""
import argparse, concurrent.futures, hashlib, io, json, os, re, subprocess, tarfile, threading, urllib.parse
from pathlib import Path, PurePosixPath
from recover import NATIVE

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--native-data',type=Path,required=True)
    ap.add_argument('--cache',type=Path,required=True); ap.add_argument('--out',type=Path,required=True)
    a=ap.parse_args(); base=a.cache/'git-repositories'; sources=a.cache/'git-sources'
    base.mkdir(parents=True,exist_ok=True); sources.mkdir(parents=True,exist_ok=True)
    gems=[json.loads(l) for l in (a.native_data/'gems.jsonl').open()]
    regs={json.loads(l)['gem_id'] for l in (a.native_data/'c_registrations.jsonl').open()}
    anchors={}
    for r in gems:
        if not (r.get('native_file_count',0)>0 or r['gem_id'] in regs): continue
        p=r.get('source_provenance') or r.get('provenance') or {}
        if p.get('url') and p.get('commit'):
            key=(r['name'],r['version'],p['url'],p['commit'])
            anchor=anchors.setdefault(key,dict(gem=r['name'],version=r['version'],url=p['url'],commit=p['commit'],tag=p.get('tag'),gem_ids=[],vendors=r.get('vendored_acquisitions',[])))
            anchor['gem_ids'].append(r['gem_id'])
    env=dict(os.environ,GIT_TERMINAL_PROMPT='0'); locks={}; lock_guard=threading.Lock()
    def git(repo,*args,input_=None):
        return subprocess.run(['git','-c','core.hooksPath=/dev/null','-c','protocol.file.allow=never','-C',str(repo),*args],
            input=input_,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,check=True).stdout
    def safe_url(url,parent=None):
        if url.startswith('../') or url.startswith('./'):
            url=urllib.parse.urljoin(parent.rstrip('/')+'/',url)
        url=re.sub(r'^git@github\.com:', 'https://github.com/',url)
        url=url.replace('git://github.com/','https://github.com/')
        if not re.fullmatch(r'https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/?',url):
            raise ValueError('Unsupported recorded repository URL: '+url)
        return url.rstrip('/')
    def obtain(url,commit):
        url=safe_url(url); assert re.fullmatch(r'[0-9a-f]{40}',commit)
        key=hashlib.sha256(url.encode()).hexdigest()[:20]; repo=base/key
        with lock_guard: lock=locks.setdefault(key,threading.Lock())
        with lock:
            if not (repo/'HEAD').exists():
                repo.mkdir(exist_ok=True); subprocess.run(['git','-c','core.hooksPath=/dev/null','init','--bare',str(repo)],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,check=True,env=env)
            available=subprocess.run(['git','-C',str(repo),'cat-file','-e',commit+'^{commit}'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0
            if not available: git(repo,'fetch','--depth=1','--no-tags',url,commit)
            assert git(repo,'rev-parse',commit+'^{commit}').decode().strip()==commit
        return repo,url
    def extract(url,commit,directory,prefix='',ancestry=()):
        if (url,commit) in ancestry: raise ValueError('cyclic gitlink source graph')
        repo,url=obtain(url,commit); records=[]; children=[]; metadata=[]
        entries=[]
        for item in git(repo,'ls-tree','-rz','--full-tree',commit).split(b'\0'):
            if not item: continue
            left,path=item.split(b'\t',1); mode,kind,oid=left.decode().split(); name=path.decode('utf8')
            rel=PurePosixPath(name)
            if rel.is_absolute() or '..' in rel.parts: raise ValueError('unsafe Git source path')
            entries.append((mode,kind,oid,name))
        modules={}
        module=next((x for x in entries if x[3]=='.gitmodules'),None)
        if module:
            content=git(repo,'cat-file','blob',module[2]).decode('utf8')
            for section in re.split(r'^\s*\[submodule[^\n]*\]\s*$',content,flags=re.M)[1:]:
                path=re.search(r'^\s*path\s*=\s*(.+)$',section,re.M); remote=re.search(r'^\s*url\s*=\s*(.+)$',section,re.M)
                if path and remote: modules[path[1].strip()]=safe_url(remote[1].strip(),url)
        archive_name=lambda name:name.endswith(('.tar.gz','.tar.bz2','.tar.xz','.tgz','.tbz2'))
        selected=[x for x in entries if x[1]=='blob' and x[0]!='120000' and (Path(x[3]).suffix in NATIVE or Path(x[3]).name=='extconf.rb' or archive_name(x[3]))]
        proc=subprocess.Popen(['git','-C',str(repo),'cat-file','--batch'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env)
        for mode,kind,oid,name in selected:
            proc.stdin.write((oid+'\n').encode()); proc.stdin.flush()
            header=proc.stdout.readline().decode().split(); assert header[1]=='blob'
            n=int(header[2]); chunks=[]; remaining=n
            while remaining:
                b=proc.stdout.read(min(remaining,65536)); assert b; chunks.append(b); remaining-=len(b)
            assert proc.stdout.read(1)==b'\n'; data=b''.join(chunks)
            path=directory/prefix/name; path.parent.mkdir(parents=True,exist_ok=True); path.write_bytes(data)
            rel=str(PurePosixPath(prefix)/name)
            if Path(name).suffix in NATIVE: records.append(dict(file=rel,sha256=hashlib.sha256(data).hexdigest(),bytes=n,git_blob=oid,git_commit=commit,git_url=url))
            elif archive_name(name):
                try:
                    with tarfile.open(fileobj=io.BytesIO(data),mode='r:*') as archive:
                        for member in archive:
                            if not member.isfile() or Path(member.name).suffix not in NATIVE: continue
                            part=PurePosixPath(member.name.removeprefix('./'))
                            if part.is_absolute() or '..' in part.parts: raise ValueError('unsafe native archive member')
                            contents=archive.extractfile(member).read(); target=directory/(rel+'.extracted')/part
                            target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(contents)
                            records.append(dict(file=str(PurePosixPath(rel+'.extracted')/part),sha256=hashlib.sha256(contents).hexdigest(),bytes=len(contents),
                                git_blob=oid,git_commit=commit,git_url=url,archive_member=str(part)))
                except tarfile.ReadError: pass
            else: metadata.append(rel)
        proc.stdin.close(); assert proc.wait()==0
        for mode,kind,oid,name in entries:
            if kind!='commit': continue
            if name not in modules: raise ValueError('unresolved gitlink URL: '+name)
            subprefix=str(PurePosixPath(prefix)/name)
            subrecords,subchildren,submeta=extract(modules[name],oid,directory,subprefix,ancestry+((url,commit),))
            records.extend(subrecords); metadata.extend(submeta)
            children.append(dict(path=subprefix,url=modules[name],commit=oid)); children.extend(subchildren)
        return records,children,metadata
    def restore(item):
        key,r=item; directory=sources/(r['gem']+'-'+r['version']+'-'+r['commit'][:12])
        cached=directory/'source-record.json'
        if cached.exists():
            old=json.loads(cached.read_text())
            if old.get('native_suffixes')==sorted(NATIVE) and old.get('recovery_format')==2: return old
        records,children,metadata=extract(r['url'],r['commit'],directory)
        vendors=[]
        for vendor in r['vendors']:
            if not vendor.get('commit') or not vendor.get('url'): continue
            relative='vendor/'+vendor['dependency']
            extra,subchildren,submeta=extract(vendor['url'],vendor['commit'],directory,relative)
            records.extend(extra);children.extend(subchildren);metadata.extend(submeta)
            vendors.append(dict(path=relative,url=vendor['url'],commit=vendor['commit']))
        record=dict(gem=r['gem'],version=r['version'],locked_version=r['version'],directory=str(directory),
            source_url=r['url'],source_variant='git:'+r['commit'],git_commit=r['commit'],git_tag=r['tag'],
            gem_ids=sorted(r['gem_ids']),gitlinks=children,hash_basis='recorded_git_commit',verified_catalogue_files=0,
            source_files=sorted(records,key=lambda s:s['file']),extension_metadata=sorted(metadata),native_suffixes=sorted(NATIVE),recovery_format=2,vendored_sources=vendors)
        directory.mkdir(parents=True,exist_ok=True); cached.write_text(json.dumps(record,indent=2,sort_keys=True)+'\n')
        print(r['gem'],r['version'],r['commit'][:12],len(records),'sources;',len(children),'gitlinks',flush=True)
        return record
    recovered=[]; failures=[]
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        futures={pool.submit(restore,item):item for item in sorted(anchors.items())}
        for future in concurrent.futures.as_completed(futures):
            key,r=futures[future]
            try: recovered.append(future.result())
            except Exception as e:
                message=e.stderr.decode('utf8',errors='replace')[-1200:] if isinstance(e,subprocess.CalledProcessError) else str(e)
                failures.append(dict(**r,error=message)); print('SOURCE FAILURE',r['gem'],r['version'],message[:160],flush=True)
    a.out.mkdir(parents=True,exist_ok=True)
    (a.out/'git-source-manifest.json').write_text(json.dumps(sorted(recovered,key=lambda r:(r['gem'],r['version'],r['git_commit'])),indent=2,sort_keys=True)+'\n')
    report=dict(requested=len(anchors),restored=len(recovered),failures=sorted(failures,key=lambda r:(r['gem'],r['version'])))
    (a.out/'git-source-recovery.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    print(json.dumps(dict(requested=len(anchors),restored=len(recovered),failures=len(failures)),sort_keys=True))
    if failures: raise SystemExit(1)

if __name__=='__main__': main()

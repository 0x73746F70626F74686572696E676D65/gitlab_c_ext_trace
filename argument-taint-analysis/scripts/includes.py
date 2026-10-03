#!/usr/bin/env python3
"""Literal C include visibility, retaining conditional include alternatives."""
import collections,json,re
from pathlib import Path

INCLUDE=re.compile(rb'^\s*#\s*include\s*([<"])([^>"\r\n]+)[>"]',re.M)


def include_graph(manifest, package_key):
    graph={};boundaries=[]
    for package in manifest:
        key=package_key(package);files={r['file'] for r in package['source_files']}
        suffixes=collections.defaultdict(set)
        for file in sorted(files):
            parts=file.split('/')
            for start in range(len(parts)):suffixes['/'.join(parts[start:])].add(file)
        for file in sorted(files):
            b=(Path(package['directory'])/file).read_bytes();targets=set()
            for match in INCLUDE.finditer(b):
                name=match[2].decode('utf8',errors='replace')
                local=Path(file).parent/name
                normalized=[]
                for part in local.parts:
                    if part=='..':
                        if normalized:normalized.pop()
                    elif part!='.':normalized.append(part)
                local='/'.join(normalized)
                candidates={local} if match[1]==b'"' and local in files else suffixes.get(name,set())
                if not candidates and name+'.in' in suffixes:candidates=suffixes[name+'.in']
                if candidates:
                    def proximity(candidate):
                        common=0
                        for a,c in zip(file.split('/')[:-1],candidate.split('/')[:-1]):
                            if a!=c:break
                            common+=1
                        return common
                    nearest=max(proximity(c) for c in candidates)
                    selected={c for c in candidates if proximity(c)==nearest};targets.update(selected)
                    if len(selected)>1:boundaries.append(dict(package=key,file=file,line=b[:match.start()].count(b'\n')+1,include=name,candidates=sorted(selected),reason='multiple equally close include files'))
                else:boundaries.append(dict(package=key,file=file,line=b[:match.start()].count(b'\n')+1,include=name,candidates=[],reason='include outside restored source files'))
            graph[(key,file)]=frozenset(targets)
    return graph,boundaries


def visible_headers(graph, package, file, cache):
    key=(package,file)
    if key not in cache:
        seen=set();pending=[file]
        while pending:
            current=pending.pop()
            if current in seen:continue
            seen.add(current);pending.extend(graph.get((package,current),()))
        cache[key]=frozenset(seen)
    return cache[key]

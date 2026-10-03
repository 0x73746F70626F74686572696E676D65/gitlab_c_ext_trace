#!/usr/bin/env python3
"""Atomic, inert JSON checkpoints for the analyzer's finite worklist state."""
import collections, hashlib, json, os, shutil, time
from pathlib import Path


def digest(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda:stream.read(4*1024*1024),b''):h.update(block)
    return h.hexdigest()


def identity(paths, roots):
    return dict(files={str(p):digest(p) for p in paths},
                roots_sha256=hashlib.sha256(json.dumps(roots,sort_keys=True).encode()).hexdigest())


def tuple_tree(value):
    return tuple(tuple_tree(x) for x in value) if isinstance(value,list) else value


def encode_value(value):
    return dict(deps=list(value.deps.items()),refs=sorted(value.refs,key=str),
                funcs=sorted(value.funcs),const=value.const)


def decode_value(row, value_type):
    return value_type({tuple_tree(atom):tuple(path) for atom,path in row['deps']},
                      frozenset(tuple_tree(ref) for ref in row['refs']),
                      frozenset(row['funcs']),row['const'])


class Checkpoints:
    def __init__(self, directory, key, interval=600):
        self.directory=Path(directory);self.key=key;self.interval=interval;self.last=time.monotonic()
        self.directory.mkdir(parents=True,exist_ok=True)

    def due(self):return time.monotonic()-self.last>=self.interval

    def save(self, solver, queue, priority):
        generation=self.directory/('state-'+str(solver.analyses))
        temporary=self.directory/('writing-'+str(os.getpid()))
        if temporary.exists():shutil.rmtree(temporary)
        temporary.mkdir()
        metadata=dict(identity=self.key,analyses=solver.analyses,changes=solver.changes,
                      change_counts=dict(solver.change_counts),priority=priority,
                      queue=sorted(queue),reachable=sorted(solver.reachable))
        metadata['abi_boundaries']=list(solver.abi_boundaries.values())
        (temporary/'metadata.json').write_text(json.dumps(metadata,sort_keys=True)+'\n')
        with (temporary/'events.jsonl').open('w') as stream:
            for eid,event in sorted(solver.index.events.items()):
                stream.write(json.dumps(dict(id=eid,**event),sort_keys=True)+'\n')
        pointer_inputs=collections.defaultdict(list);table_inputs=collections.defaultdict(list)
        for (fid,i),targets in sorted(solver.pointer_inputs.items()):
            if targets:pointer_inputs[fid].append([i,sorted(targets)])
        for (fid,i),targets in sorted(solver.table_inputs.items()):
            if targets:table_inputs[fid].append([i,sorted(targets,key=str)])
        with (temporary/'functions.jsonl').open('w') as stream:
            for fid in sorted(solver.reachable):
                summary=solver.summaries[fid]
                row=dict(function=fid,result=encode_value(summary.result),
                         outputs=[[key,encode_value(value)] for key,value in sorted(summary.outputs.items(),key=lambda x:str(x[0]))],
                         sinks=sorted(summary.sinks.items(),key=lambda x:str(x[0])),
                         edges=sorted(solver.edges[fid]),
                         pointer_inputs=pointer_inputs[fid],table_inputs=table_inputs[fid])
                stream.write(json.dumps(row,sort_keys=True)+'\n')
        if generation.exists():shutil.rmtree(generation)
        temporary.replace(generation)
        pointer=self.directory/'CURRENT.tmp';pointer.write_text(generation.name+'\n');pointer.replace(self.directory/'CURRENT')
        for old in self.directory.glob('state-*'):
            if old!=generation:shutil.rmtree(old)
        self.last=time.monotonic()
        print('Checkpoint saved:',solver.analyses,'evaluations;',len(queue),'queued',flush=True)

    def load(self,solver,value_type,summary_type):
        pointer=self.directory/'CURRENT'
        if not pointer.exists():return None
        generation=self.directory/pointer.read_text().strip()
        metadata=json.loads((generation/'metadata.json').read_text())
        if metadata['identity']!=self.key:raise ValueError('Checkpoint source/harness identity differs')
        for line in (generation/'events.jsonl').open():
            event=json.loads(line);eid=event.pop('id');solver.index.events[eid]=event
            core=['function','line','kind','expression'];extra={k:v for k,v in event.items() if k not in core}
            prefix=tuple(event[k] for k in core)
            solver.index.event_keys[prefix+(json.dumps(extra or None,sort_keys=True),)]=eid
        solver.reachable=set(metadata['reachable'])
        for fid in sorted(solver.reachable):solver.dependencies(fid)
        for line in (generation/'functions.jsonl').open():
            row=json.loads(line);fid=row['function']
            solver.summaries[fid]=summary_type(decode_value(row['result'],value_type),
                {tuple_tree(key):decode_value(value,value_type) for key,value in row['outputs']},
                {tuple_tree(key):tuple(path) for key,path in row['sinks']})
            solver.edges[fid]=set(row['edges'])
            for target in row['edges']:solver.reverse[target].add(fid)
            for i,targets in row['pointer_inputs']:solver.pointer_inputs[(fid,i)]=set(targets)
            for i,targets in row['table_inputs']:solver.table_inputs[(fid,i)]=set(tuple_tree(t) for t in targets)
        solver.analyses=metadata['analyses'];solver.changes=metadata['changes']
        solver.change_counts=collections.Counter(metadata['change_counts'])
        solver.abi_boundaries={(r['function'],r['event'],r['target'],r['actual_arguments']):r for r in metadata.get('abi_boundaries',[])}
        self.last=time.monotonic()
        print('Checkpoint resumed:',solver.analyses,'evaluations',flush=True)
        return [tuple(entry) for entry in metadata['queue']],metadata['priority']

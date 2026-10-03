"""Incrementally read our inert JSON index without a corpus-sized text buffer."""
import json
import sys


def compact_offsets(offsets):
    result=[]
    for offset,line in offsets:
        if not result or line!=result[-1][1]: result.append((offset,line))
    return result


class Stream:
    def __init__(self,file,chunk_size=1024*1024):
        self.file=file;self.chunk_size=chunk_size;self.buffer='';self.pos=0;self.eof=False
        self.decoder=json.JSONDecoder()

    def fill(self):
        chunk=self.file.read(self.chunk_size)
        self.buffer=self.buffer[self.pos:]+chunk;self.pos=0
        if not chunk:self.eof=True

    def peek(self):
        while True:
            while self.pos<len(self.buffer) and self.buffer[self.pos].isspace():self.pos+=1
            if self.pos<len(self.buffer):return self.buffer[self.pos]
            if self.eof:raise ValueError('truncated index cache')
            self.fill()

    def take(self,char):
        actual=self.peek()
        if actual!=char:raise ValueError(f'index cache: expected {char!r}, got {actual!r}')
        self.pos+=1

    def value(self):
        self.peek()
        while True:
            try:value,end=self.decoder.raw_decode(self.buffer,self.pos)
            except json.JSONDecodeError:
                if self.eof:raise
                self.fill();continue
            if end==len(self.buffer) and not self.eof:
                self.fill();continue
            self.pos=end;return value


def load_index(path,chunk_size=1024*1024):
    result={};functions={}
    with path.open() as file:
        stream=Stream(file,chunk_size);stream.take('{')
        while stream.peek()!='}':
            key=stream.value();stream.take(':')
            if key=='functions':
                stream.take('{')
                while stream.peek()!='}':
                    fid=stream.value();stream.take(':');fn=stream.value()
                    fn['offsets']=compact_offsets(fn['offsets'])
                    for name in ('package','gem','version','locked_version','file','path','source_sha256','parser','name'):
                        fn[name]=sys.intern(fn[name])
                    fn['parameters']=[sys.intern(p) for p in fn['parameters']]
                    functions[fid]=fn
                    if len(functions)%100000==0:print('Loaded index functions:',len(functions),flush=True)
                    if stream.peek()=='}':break
                    stream.take(',')
                stream.take('}');result[key]=functions
            else:result[key]=stream.value()
            if stream.peek()=='}':break
            stream.take(',')
        stream.take('}')
        if stream.buffer[stream.pos:].strip() or file.read().strip():raise ValueError('trailing index data')
    return result

"""Bounded ZIP views without filesystem extraction. Member paths are never executed."""
import copy
import hashlib
import io
import stat
import time
import zipfile
import zlib
from pathlib import PurePosixPath

MAX_MEMBER=8*1024*1024
MAX_TOTAL=64*1024*1024
MAX_ENTRIES=5000
MAX_ARCHIVES=32
MAX_DEPTH=2
EXTENSIONS={'.zip','.jar','.apk','.ipa','.aar'}

def validate(infos):
    if len(infos)>MAX_ENTRIES:raise ValueError('nested_entry_count_limit')
    names=set();canonical=set();total=0
    for item in infos:
        name=item.filename;parts=name.rstrip('/').split('/')
        if name!=item.orig_filename or not name or len(name)>4096 or name.startswith(('/','\\')) or '\\' in name or ':' in name or any(p in ('','.','..') for p in parts) or any(ord(c)<32 or ord(c)==127 for c in name):raise ValueError('nested_unsafe_path')
        if name in names or name.rstrip('/') in canonical:raise ValueError('nested_duplicate_entry')
        names.add(name);canonical.add(name.rstrip('/'))
        if stat.S_IFMT(item.external_attr>>16) not in (0,stat.S_IFREG,stat.S_IFDIR):raise ValueError('nested_special_entry')
        if item.flag_bits&1 or item.compress_type not in (0,8):raise ValueError('nested_encryption_or_compression_unsupported')
        if item.file_size>MAX_MEMBER or item.file_size/max(1,item.compress_size)>200:raise ValueError('nested_member_size_or_ratio_limit')
        total+=item.file_size
        if total>MAX_TOTAL:raise ValueError('nested_expanded_budget')
    files={item.filename for item in infos if not item.is_dir()}
    if any('/'.join(n.rstrip('/').split('/')[:i]) in files for n in names for i in range(1,len(n.rstrip('/').split('/')))):raise ValueError('nested_file_directory_conflict')

def read_bounded(z,info):
    with z.open(info) as stream:data=stream.read(MAX_MEMBER+1)
    if len(data)>MAX_MEMBER or len(data)!=info.file_size:raise ValueError('nested_actual_size_limit')
    return data

class NestedArchiveView:
    def __init__(self,root,expected,deadline):
        self.root=root;self.expected=expected;self.deadline=min(deadline,time.monotonic()+10)
        self.metadata={};self.labels={};self.prefixes={};self.container_keys=set();self.entries=list(root.infolist())
        self.sources={i.filename:(root,i) for i in self.entries};self.children=[];self.counter=0
        self.stats={'status':'partial','discovery_truncated':False,'archives_checked':0,'archives_blocked':0,'nested_entries':0,'bytes_read':0,'failures':[], 'failures_truncated':False,'depth_limit':MAX_DEPTH,'member_bytes_limit':MAX_MEMBER,'total_bytes_limit':MAX_TOTAL,'entry_limit':MAX_ENTRIES,'archive_limit':MAX_ARCHIVES}
        try:
            for entry in list(self.entries):self.expand(root,entry,entry.filename,[],0)
        except Exception:
            self.close();raise
        if not self.stats['archives_checked'] and not self.stats['archives_blocked'] and not self.stats['discovery_truncated']:self.stats['status']='not_applicable'
    def blocked(self,label,reason):
        self.stats['archives_blocked']+=1
        if len(self.stats['failures'])<100:self.stats['failures'].append({'path':label,'reason':reason})
        else:self.stats['failures_truncated']=True
    def expand(self,parent,info,key,chain,depth):
        if info.is_dir():return
        label=self.labels.get(key,key)
        known=PurePosixPath(info.filename).suffix.lower() in EXTENSIONS
        try:
            if not known:
                if time.monotonic()>self.deadline:self.stats['discovery_truncated']=True;return
                with parent.open(info) as stream:known=stream.read(4) in (b'PK\x03\x04',b'PK\x05\x06')
            if not known:return
            self.container_keys.add(key)
            if depth>=MAX_DEPTH:raise ValueError('nested_depth_limit')
            if self.counter>=MAX_ARCHIVES:raise ValueError('nested_archive_count_limit')
            if info.file_size>MAX_MEMBER or self.stats['bytes_read']+info.file_size>MAX_TOTAL:raise ValueError('nested_input_budget')
            if time.monotonic()>self.deadline:raise ValueError('nested_discovery_timeout')
            self.counter+=1
            blob=read_bounded(parent,info);self.stats['bytes_read']+=len(blob)
            digest=hashlib.sha256(blob).hexdigest()
            if digest!=self.expected[key]['sha256']:raise ValueError('member_digest_mismatch')
            child=zipfile.ZipFile(io.BytesIO(blob));self.children.append(child)
            infos=child.infolist();validate(infos)
            if self.stats['nested_entries']+len(infos)>MAX_ENTRIES:raise ValueError('nested_total_entry_limit')
            pending=[];parent_chain=chain+[{'path':info.filename,'sha256':digest}]
            for item in infos:
                if time.monotonic()>self.deadline:raise ValueError('nested_discovery_timeout')
                if self.stats['bytes_read']+item.file_size>MAX_TOTAL:raise ValueError('nested_expanded_budget')
                data=read_bounded(child,item);self.stats['bytes_read']+=len(data)
                virtual='nested:'+str(self.counter)+'/'+item.filename
                # A colon cannot occur in imported root paths, so namespaces cannot collide.
                alias=copy.copy(item);alias.filename=virtual
                pending.append((alias,item,hashlib.sha256(data).hexdigest()))
            self.prefixes['nested:'+str(self.counter)+'/']=label+'!/'
            self.stats['archives_checked']+=1;self.stats['nested_entries']+=len(pending)
            for alias,item,digest in pending:
                self.entries.append(alias);self.sources[alias.filename]=(child,item)
                self.labels[alias.filename]=label+'!/'+item.filename
                self.metadata[alias.filename]={'archive_chain':parent_chain,'member_path':item.filename}
                self.expected[alias.filename]={'sha256':digest}
            for alias,item,digest in pending:self.expand(child,item,alias.filename,parent_chain,depth+1)
        except ValueError as error:
            if str(error)=='member_digest_mismatch':raise
            if str(error)=='nested_discovery_timeout':self.stats['discovery_truncated']=True
            self.blocked(label,str(error))
        except (zipfile.BadZipFile,RuntimeError,NotImplementedError,EOFError,OSError,zlib.error):self.blocked(label,'nested_invalid_zip_or_crc')
    def infolist(self):return self.entries
    def open(self,item):
        key=item if isinstance(item,str) else item.filename
        archive,original=self.sources[key];return archive.open(original)
    def read(self,item):
        with self.open(item) as stream:return stream.read()
    def close(self):
        for child in reversed(self.children):child.close()
    def __enter__(self):return self
    def __exit__(self,*args):self.close()

# Re-materialize an identity-bound member for the independent native verifier.
def read_chained_member(root,chain,member,max_member):
    if not isinstance(chain,list) or len(chain)>MAX_DEPTH:raise ValueError('nested_depth_limit')
    current=root;opened=[]
    try:
        for parent in chain:
            name=parent.get('path');digest=parent.get('sha256')
            info=current.getinfo(name)
            blob=read_bounded(current,info)
            if hashlib.sha256(blob).hexdigest()!=digest:raise ValueError('nested_digest_mismatch')
            child=zipfile.ZipFile(io.BytesIO(blob));opened.append(child);validate(child.infolist());current=child
        info=current.getinfo(member)
        if info.file_size>min(max_member,MAX_MEMBER if chain else max_member):raise ValueError('nested_member_size_limit')
        with current.open(info) as stream:data=stream.read(min(max_member,MAX_MEMBER if chain else max_member)+1)
        if len(data)!=info.file_size:raise ValueError('nested_actual_size_limit')
        return data
    finally:
        for child in reversed(opened):child.close()

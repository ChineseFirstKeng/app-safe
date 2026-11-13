"""Materialize exactly one verified, unencrypted Mach-O slice for an isolated REA session."""
import sys,json,hashlib,zipfile,os
from pathlib import Path
from nested_archives import read_chained_member
from ios_macho import slices,parse_slice,MAX_NATIVE_FILE

def run(req):
    folder=Path(req['storage_root'])/req['artifact_id'];package=folder/'package.bin'
    if folder.is_symlink() or package.is_symlink():raise ValueError('artifact_symlink')
    with package.open('rb') as f:
        digest=hashlib.sha256()
        for b in iter(lambda:f.read(1024*1024),b''):digest.update(b)
        if digest.hexdigest()!=req['artifact_sha256']:raise ValueError('artifact_digest_mismatch')
        f.seek(0)
        with zipfile.ZipFile(f) as z:
            data=read_chained_member(z,req.get('archive_chain',[]),req['member'],MAX_NATIVE_FILE)
    if hashlib.sha256(data).hexdigest()!=req['member_sha256']:raise ValueError('member_digest_mismatch')
    layout=slices(data);index=req['slice_index']
    if not isinstance(index,int) or not 0<=index<len(layout):raise ValueError('macho_slice_invalid')
    base,size,cpu,sub=layout[index];meta=parse_slice(data,base,size,cpu,sub)
    if meta['encrypted']:raise ValueError('encrypted_macho_slice')
    blob=data[base:base+size];digest=hashlib.sha256(blob).hexdigest()
    if digest!=req['slice_sha256']:raise ValueError('macho_slice_digest_mismatch')
    fd=os.open(req['output'],os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    with os.fdopen(fd,'wb') as f:f.write(blob)
    return {'sha256':digest,'bytes':len(blob)}
try:print(json.dumps({'ok':True,'result':run(json.load(sys.stdin))}))
except Exception as e:
    code=str(e)
    print(json.dumps({'ok':False,'error':code if code in ('nested_digest_mismatch','nested_depth_limit','nested_member_size_limit','artifact_symlink','artifact_digest_mismatch','macho_input_limit','member_digest_mismatch','macho_slice_invalid','encrypted_macho_slice','macho_slice_digest_mismatch') else 'macho_extract_failed'}))

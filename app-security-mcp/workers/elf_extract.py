"""Extract one identity-checked ELF member; never load/execute it."""
import sys,json,hashlib,zipfile,os
from pathlib import Path
from nested_archives import read_chained_member
from android_elf import parse,MAX_ELF

def run(req):
 folder=Path(req['storage_root'])/req['artifact_id'];package=folder/'package.bin'
 if folder.is_symlink() or package.is_symlink():raise ValueError('artifact_symlink')
 with package.open('rb') as f:
  h=hashlib.sha256()
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
  if h.hexdigest()!=req['artifact_sha256']:raise ValueError('artifact_digest_mismatch')
  f.seek(0)
  with zipfile.ZipFile(f) as z:
   data=read_chained_member(z,req.get('archive_chain',[]),req['member'],MAX_ELF)
 digest=hashlib.sha256(data).hexdigest()
 if digest!=req['member_sha256']:raise ValueError('member_digest_mismatch')
 parse(data)
 fd=os.open(req['output'],os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 with os.fdopen(fd,'wb') as f:f.write(data)
 return {'sha256':digest,'bytes':len(data)}
try:print(json.dumps({'ok':True,'result':run(json.load(sys.stdin))}))
except Exception as e:
 code=str(e)
 print(json.dumps({'ok':False,'error':code if code in ('nested_digest_mismatch','nested_depth_limit','nested_member_size_limit','artifact_symlink','artifact_digest_mismatch','member_digest_mismatch','elf_input_limit') else 'elf_extract_failed'}))

"""Private local evidence, separate from MCP results and ordinary redacted reports."""
import json
import os
import re
from pathlib import Path

class PrivateEvidence:
    def __init__(self,request):
        self.request=request;self.values={};self.bytes=0;self.truncated=False
    def add(self,ident,value,encoding='utf-8'):
        if value is None:return
        if isinstance(value,bytes):value=value.hex();encoding='hex'
        if not isinstance(value,str):value=json.dumps(value,ensure_ascii=True);encoding='json'
        size=len(value.encode('utf8','surrogatepass'))
        if size>256*1024 or self.bytes+size>4*1024*1024:self.truncated=True;return
        self.values[ident]={'encoding':encoding,'value':value};self.bytes+=size
    def save(self):
        scan_id=self.request.get('scan_id')
        if not isinstance(scan_id,str) or not re.fullmatch('[a-f0-9]{32}',scan_id):return {'available':False,'reason':'scan_identity_missing'}
        root=Path(self.request['storage_root'])/'_scans'
        if root.is_symlink():raise ValueError('invalid_private_storage')
        path=root/(scan_id+'.sensitive.json')
        data={'schema_version':'0.1','scan_id':scan_id,'artifact_id':self.request['artifact_id'],'artifact_sha256':self.request['artifact_sha256'],'values':self.values}
        fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'w') as out:json.dump(data,out,ensure_ascii=True)
        return {'available':True,'item_count':len(self.values),'values_truncated':self.truncated}

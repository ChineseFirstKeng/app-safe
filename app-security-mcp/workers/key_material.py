"""Bounded builtin Node/OpenSSL key format parsing; never retain key values."""
import base64
import json
import re
import subprocess
import time
from pathlib import Path

ENVELOPES=re.compile(r'-----BEGIN ((?:RSA |EC |ENCRYPTED |OPENSSH )?PRIVATE KEY)-----[\s\S]{1,131072}?-----END \1-----')
class KeyValidator:
    def __init__(self,node,deadline):
        self.node=node
        self.deadline=deadline
        self.stats={'engine':'node_crypto_openssl','attempt_limit':32,'attempts':0,'parsed':0,'public_material':0,'invalid_or_unsupported':0,'unresolved':0,'budget_skipped':0}
    def validate(self,data,format):
        if len(data)>131072 or self.stats['attempts']>=32 or time.monotonic()>=self.deadline:
            self.stats['budget_skipped']+=1
            return {'status':'key_parse_budget_or_size_limit'}
        if not isinstance(self.node,str) or not self.node:
            self.stats['unresolved']+=1
            return {'status':'key_parser_unavailable'}
        self.stats['attempts']+=1
        try:
            request={'format':format,'data':base64.b64encode(data).decode('ascii') if format=='der' else data}
            r=subprocess.run([self.node,str(Path(__file__).with_name('key_validate.mjs'))],input=json.dumps(request).encode('utf8'),stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=min(3,max(.01,self.deadline-time.monotonic())))
            if r.returncode!=0 or len(r.stdout)>2048:raise ValueError()
            value=json.loads(r.stdout)
            if not isinstance(value,dict):raise ValueError()
            if value.get('status') not in ('parsed_private_key','public_key','public_certificate','invalid_or_unsupported','encrypted_or_unsupported_envelope','encrypted_container_requires_passphrase'):raise ValueError()
            if value['status']=='parsed_private_key':
                self.stats['parsed']+=1
                return {k:v for k,v in value.items() if k in ('status','algorithm','modulus_bits')}
            if value['status'] in ('public_key','public_certificate'):self.stats['public_material']+=1
            elif value['status']=='invalid_or_unsupported':self.stats['invalid_or_unsupported']+=1
            else:self.stats['unresolved']+=1
            return {'status':value['status']}
        except (OSError,ValueError,subprocess.TimeoutExpired):
            self.stats['unresolved']+=1
            return {'status':'key_parser_unavailable_or_timeout'}

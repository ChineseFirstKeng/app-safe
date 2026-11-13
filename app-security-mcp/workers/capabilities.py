"""Dependency discovery using the same resolvers as scanning; no target execution."""
import json,sys
from android_resources import find_aapt2
from android_dex import find_dexdump

def describe(path):
    return {'status':'located_not_executed' if path else 'missing',
            'version':None,'execution_verified':False,
            'reason':'executable_located_only' if path else 'executable_not_found'}

if __name__=='__main__':
    print(json.dumps({'python':{'status':'available','version':'.'.join(map(str,sys.version_info[:3])),'execution_verified':True},
                      'aapt2':describe(find_aapt2()),'dexdump':describe(find_dexdump())}))

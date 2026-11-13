"""Compile controlled, unsigned IPA-like fixtures. No target is executed."""
import pathlib,subprocess,sys,plistlib,zipfile,struct,base64
p=pathlib.Path(sys.argv[1]);p.mkdir(parents=True,exist_ok=True)
source=p/'sample.c'
source.write_text('''__attribute__((used,noinline)) const char *fixture_secret(void){return "password=fixture-ios-secret-123";}
__attribute__((used,noinline)) const char *fixture_public(void){return "client_id=public-ios-client-456";}
__attribute__((used,noinline)) const char *fixture_base64(void){return "base64:%s";}
__attribute__((used,noinline)) const char *fixture_hex(void){return "hex:%s";}
int entry(void){return fixture_secret()[0];}
'''%(base64.b64encode(b'access_token=fixture-ios-encoded-token').decode(),b'client_secret=fixture-ios-hex-secret'.hex()))
def run(args):subprocess.run(args,check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
run(['xcrun','--sdk','iphoneos','clang','-target','arm64-apple-ios13.0','-nostartfiles','-Wl,-e,_entry',str(source),'-o',str(p/'App-arm64')])
run(['xcrun','--sdk','iphonesimulator','clang','-target','x86_64-apple-ios13.0-simulator','-nostartfiles','-Wl,-e,_entry',str(source),'-o',str(p/'App-x86_64')])
run(['xcrun','lipo','-create',str(p/'App-arm64'),str(p/'App-x86_64'),'-output',str(p/'App')])
run(['xcrun','--sdk','iphoneos','clang','-target','arm64-apple-ios13.0','-dynamiclib',str(source),'-o',str(p/'Kit')])
enc=bytearray((p/'App-arm64').read_bytes());pos=32;patched=False
for _ in range(struct.unpack_from('<I',enc,16)[0]):
 cmd,size=struct.unpack_from('<II',enc,pos)
 if cmd==0x2c:struct.pack_into('<I',enc,pos+16,1);patched=True
 pos+=size
assert patched
(p/'Encrypted').write_bytes(enc)
with zipfile.ZipFile(p/'fixture.ipa','w') as z:
 for root,exe,blob in [('Payload/Test.app','App',(p/'App').read_bytes()),('Payload/Test.app/Frameworks/Kit.framework','Kit',(p/'Kit').read_bytes()),('Payload/Test.app/PlugIns/Share.appex','Share',enc)]:
  z.writestr(root+'/Info.plist',plistlib.dumps({'CFBundleIdentifier':'example.fixture','CFBundleExecutable':exe},fmt=plistlib.FMT_BINARY))
  z.writestr(root+'/'+exe,blob)
 z.writestr('Payload/Test.app/Bad.dylib',b'\xcf\xfa\xed\xfebroken')
 z.writestr('Payload/Test.app/config.json','{"client_id":"public-ios-client-456"}')

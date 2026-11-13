import os,pathlib,subprocess,zipfile,sys,base64
p=pathlib.Path(sys.argv[1]);p.mkdir(parents=True,exist_ok=True)
ndk=os.environ.get('TEST_NDK_BIN','/Users/h1610/Library/Android/sdk/ndk/28.2.13676358/toolchains/llvm/prebuilt/darwin-x86_64/bin')
encoded=base64.b64encode(b'password=fixture-encoded-elf-123').decode();hexed=b'client_secret=fixture-hex-elf-456'.hex()
(p/'sample.c').write_text('''__attribute__((used,noinline)) const char *Java_example_Native_secret(void *a,void *b){return "password=fixture-native-elf-789";}
__attribute__((used,noinline)) const char *encoded(void){return "base64:%s";}
__attribute__((used,noinline)) const char *hexed(void){return "hex:%s";}
__attribute__((used,noinline)) const char *public_id(void){return "client_id=public-client-123";}
int JNI_OnLoad(void *a,void *b){return 0x10006;}
'''%(encoded,hexed))
with zipfile.ZipFile(p/'fixture.apk','w') as z:
 z.writestr('AndroidManifest.xml',b'fixture')
 for abi,target in [('arm64-v8a','aarch64-linux-android21'),('armeabi-v7a','armv7a-linux-androideabi21'),('x86','i686-linux-android21'),('x86_64','x86_64-linux-android21')]:
  out=p/(abi+'.so')
  subprocess.run([ndk+'/clang','--target='+target,'-shared','-fPIC','-nostdlib',str(p/'sample.c'),'-o',str(out)],check=True,capture_output=True)
  z.writestr('lib/'+abi+'/libfixture.so',out.read_bytes())
 z.writestr('lib/arm64-v8a/broken.so',b'\x7fELFbroken')

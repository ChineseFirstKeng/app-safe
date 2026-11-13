"""Offline DEX constants and conservative straight-line usage. Never executes app code."""
import os,re,struct,subprocess,selectors,tempfile,time,hashlib,zlib
from pathlib import Path
from android_auth import inspect_guard
from dex_base64 import decode_literal
from dex_array_copy import copy_bytes
from dex_utf8_string import restore_utf8
from dex_method_summary import summarize, resolve_summaries
from android_resources import find_aapt2

MAX_DEX=32*1024*1024
MAX_OUTPUT=192*1024*1024
MAX_LINE=128*1024
MAX_METHOD=20000

def find_dexdump():
    import shutil
    explicit=os.environ.get('APP_SECURITY_DEXDUMP')
    if explicit is not None:return explicit if os.path.isabs(explicit) and os.path.isfile(explicit) and os.access(explicit,os.X_OK) else None
    tool=shutil.which('dexdump')
    if tool:return tool
    aapt=find_aapt2()
    if aapt:
        p=Path(aapt).with_name('dexdump')
        if p.is_file() and os.access(p,os.X_OK):return str(p)
    return None

def strings(data):
    # Standard standalone little-endian DEX only. Verify identity before parsing offsets.
    if len(data)<112 or data[:4]!=b'dex\n' or data[4:8] not in (b'035\0',b'037\0',b'038\0',b'039\0',b'040\0'):raise ValueError('dex_format_unsupported')
    u32=lambda off:struct.unpack_from('<I',data,off)[0]
    if u32(32)!=len(data) or u32(36)!=112 or u32(40)!=0x12345678:raise ValueError('dex_header_invalid')
    if hashlib.sha1(data[32:]).digest()!=data[12:32] or zlib.adler32(data[12:])&0xffffffff!=u32(8):raise ValueError('dex_checksum_invalid')
    count,offset=u32(56),u32(60)
    if count>1000000 or offset+count*4>len(data):raise ValueError('dex_string_bounds')
    result=[]
    for i in range(count):
        pos=u32(offset+i*4);n=0
        for shift in range(0,35,7):
            if pos>=len(data):raise ValueError('dex_string_bounds')
            b=data[pos];pos+=1;n|=(b&127)<<shift
            if b<128:break
        else:raise ValueError('dex_string_bounds')
        end=data.find(b'\0',pos,min(len(data),pos+MAX_LINE))
        if end<0:raise ValueError('dex_string_limit')
        try:
            # MUTF-8 represents NUL as C0 80 and supplementary chars as surrogate pairs.
            value=data[pos:end].replace(b'\xc0\x80',b'\0').decode('utf8','surrogatepass')
            value=value.encode('utf-16-le','surrogatepass').decode('utf-16-le','surrogatepass')
            if len(value.encode('utf-16-le','surrogatepass'))//2!=n:raise ValueError('dex_string_length')
        except UnicodeError:raise ValueError('dex_string_encoding')
        result.append((value,pos))
    return result

def dump_lines(tool,path,deadline,stats):
    if not tool:raise ValueError('dex_decoder_unavailable')
    end=min(deadline,time.monotonic()+25);pending=b''
    try:
        with subprocess.Popen([tool,'-d',str(path)],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL) as proc:
            try:
                with selectors.DefaultSelector() as selector:
                    selector.register(proc.stdout,selectors.EVENT_READ)
                    while True:
                        if time.monotonic()>=end:raise ValueError('dex_decode_timeout')
                        if not selector.select(.05):continue
                        b=os.read(proc.stdout.fileno(),65536)
                        if not b:break
                        stats['output_bytes']+=len(b)
                        if stats['output_bytes']>MAX_OUTPUT:raise ValueError('dex_output_limit')
                        parts=(pending+b).split(b'\n');pending=parts.pop()
                        if len(pending)>MAX_LINE:raise ValueError('dex_line_limit')
                        for line in parts:
                            if len(line)>MAX_LINE:raise ValueError('dex_line_limit')
                            yield line.decode('utf8','replace')
                if proc.wait(timeout=max(.01,end-time.monotonic())):raise ValueError('dex_decode_failed')
                if pending:yield pending.decode('utf8','replace')
            finally:
                if proc.poll() is None:proc.kill();proc.wait()
    except (OSError,subprocess.TimeoutExpired):raise ValueError('dex_decode_failed')

def scan(data,tool,deadline,emit,stats):
    pool=strings(data);stats['strings_checked']+=len(pool)
    # Emit every string for syntax-based rules, even if there is no recovered use.
    for index,(value,offset) in enumerate(pool):emit(value,None,{'string_index':index,'file_offset':offset,'usage':'string_pool_only'})
    summaries={}
    with tempfile.TemporaryDirectory(prefix='app-security-dex-') as directory:
        path=Path(directory)/'input.dex';path.write_bytes(data);path.chmod(0o600)
        dump_path=Path(directory)/'dump.txt'
        with dump_path.open('w') as output_file:
            for line in dump_lines(tool,path,deadline,stats):output_file.write(line+'\n')
        for pass_index in range(2):
            if pass_index==1:
                summaries,unresolved=resolve_summaries(summaries)
                stats['constant_method_summaries_unresolved']=stats.get('constant_method_summaries_unresolved',0)+unresolved
            method=[];klass=None;name=None;proto=None;section=None;field=None;skipping=False;register_count=None;input_count=None;is_static=False
            def flush():
                if method:
                    if pass_index==0:
                        summary=summarize(method,pool,klass,name,proto,is_static)
                        if summary:
                            key,item=summary
                            if key in summaries:summaries[key]=None
                            elif len(summaries)<10000:summaries[key]=item
                            else:stats['method_summaries_truncated']=True
                    else:
                        analyze(method,data,pool,klass,name,proto,emit,stats,range(register_count-input_count,register_count) if isinstance(register_count,int) and isinstance(input_count,int) and 0<=input_count<=register_count<=65535 else (),summaries)
                    method.clear()
            with dump_path.open() as dump_file:
                for line in dump_file:
                    if time.monotonic()>deadline:raise ValueError('dex_decode_timeout')
                    m=re.match(r"\s*Class descriptor\s*: '([^']+)'",line)
                    if m:flush();klass=m.group(1);stats['classes_checked']+=int(pass_index==1)
                    if re.match(r'\s*(Static fields|Instance fields|Direct methods|Virtual methods)\s*-',line):
                        flush();section=line.strip().split('  ')[0].rstrip(' -');skipping=False
                    if re.match(r'\s*#\d+\s*:',line):flush();name=None;proto=None;field=None;skipping=False;register_count=None;input_count=None;is_static=False
                    if re.match(r'\s*access\s*:',line):is_static=bool(re.search(r'\bSTATIC\b',line))
                    m=re.match(r'\s*registers\s*: (\d+)',line)
                    if m:register_count=int(m[1])
                    m=re.match(r'\s*ins\s*: (\d+)',line)
                    if m:input_count=int(m[1])
                    m=re.match(r"\s*name\s*: '([^']+)'",line)
                    if m:
                        if section=='Static fields':field=m.group(1)
                        else:name=m.group(1)
                    m=re.match(r"\s*type\s*: '([^']+)'",line)
                    if m:proto=m.group(1)
                    m=re.match(r'\s*value\s*: "(.*)"$',line)
                    if m and section=='Static fields' and pass_index==1:emit(m.group(1),field,{'class_descriptor':klass,'field':field,'usage':'static_field_value'})
                    m=re.match(r'^([0-9a-f]+):.*?\|([0-9a-f]+): ([^\n]+)$',line)
                    if m and not skipping:
                        method.append((int(m.group(1),16),int(m.group(2),16),m.group(3)))
                        if len(method)>MAX_METHOD:method.clear();skipping=True;stats['methods_skipped_limit']+=int(pass_index==1)
                flush()
    stats['constant_method_summaries']=stats.get('constant_method_summaries',0)+sum(v is not None for v in summaries.values())

def analyze(instructions,data,pool,klass,name,proto,emit,stats,parameter_registers=(),method_summaries=None):
    stats['methods_checked']+=1
    base={'class_descriptor':klass,'method':name,'prototype':proto}
    inspect_guard(instructions,pool,base,parameter_registers,emit)
    flow=not any(re.match(r'(if-|goto|packed-switch|sparse-switch|move-exception)',op) for _,_,op in instructions)
    if not flow:stats['methods_without_flow']+=1
    regs={};pending=None
    def value(v):
        return v.get('value') if isinstance(v,dict) else v
    def evidence(off,pc,usage):return {**base,'file_offset':off,'dex_code_unit_offset':pc,'usage':usage}
    def output(v,key,off,pc,usage,rule=None):
        context=evidence(off,pc,usage)
        if isinstance(v,dict):context.update(v.get('provenance',{}))
        v=value(v)
        if isinstance(v,bytes):
            if rule:context['material_encoding']='hex';emit(v.hex(),key,context,rule)
            else:
                try:emit(v.decode('utf8'),key,context)
                except UnicodeError:pass
        elif isinstance(v,str):emit(v,key,context,rule)
    for off,pc,op in instructions:
        opcode=op.split(' ',1)[0];operands=op[len(opcode):].strip();old_pending=pending;pending=None
        m=re.match(r'v(\d+), .* // string@([0-9a-f]+)$',operands)
        if opcode in ('const-string','const-string/jumbo') and m:
            reg,index=int(m.group(1)),int(m.group(2),16)
            if index>=len(pool):raise ValueError('dex_string_index_invalid')
            v=pool[index][0];output(v,None,off,pc,'const_string')
            if flow:regs[reg]=v
            continue
        if not flow:continue
        rr=[int(x) for x in re.findall(r'\bv(\d+)\b',operands.split(' // ',1)[0])]
        if opcode.startswith('move-result'):
            if rr:regs[rr[0]]=old_pending
        elif opcode.startswith('move') and len(rr)>=2:regs[rr[0]]=regs.get(rr[1])
        elif opcode.startswith('const'):
            m=re.search(r'#(?:int|long) (-?\d+)',operands)
            number=int(m.group(1)) if m else None
            # dexdump renders const's raw 32-bit bits as #float; consume the
            # signed integer instruction encoding, not its display interpretation.
            if opcode in ('const','const/high16'):
                width=4 if opcode=='const' else 2
                if off<0 or off+2+width>len(data) or data[off]!=(0x14 if opcode=='const' else 0x15):raise ValueError('dex_const_bounds')
                number=struct.unpack_from('<i' if width==4 else '<h',data,off+2)[0]
                if opcode=='const/high16':number<<=16
            if rr:regs[rr[0]]=number
        elif opcode=='new-instance' and rr:
            regs[rr[0]]={'kind':'builder','value':''} if 'Ljava/lang/StringBuilder;' in operands else {'kind':'string_object','value':None} if operands.split(', ',1)[-1].split(' // ',1)[0]=='Ljava/lang/String;' else None
        elif opcode=='new-array' and len(rr)>=2:
            size=regs.get(rr[1]);regs[rr[0]]={'kind':'array','value':bytes(size)} if isinstance(size,int) and 0<=size<=8192 and ', [B' in operands else None
            if regs[rr[0]] is not None:regs[rr[0]]['size']=size
        elif opcode=='aput-byte' and len(rr)==3:
            v,array,index=regs.get(rr[0]),regs.get(rr[1]),regs.get(rr[2])
            if isinstance(v,int) and isinstance(array,dict) and array.get('kind')=='array' and isinstance(index,int) and 0<=index<array['size']:
                content=bytearray(array['value']);content[index]=v&255;array['value']=bytes(content)
            else:regs.clear()
        elif opcode=='fill-array-data' and rr:
            m=re.match(r'v\d+, ([0-9a-f]+)',operands)
            array=regs.get(rr[0])
            if m and isinstance(array,dict) and array.get('kind')=='array':
                target=off-2*pc+2*int(m.group(1),16)
                if target<0 or target+8>len(data):raise ValueError('dex_array_bounds')
                magic,width,count=struct.unpack_from('<HHI',data,target)
                if magic==0x300 and width==1 and count==array['size'] and target+8+count<=len(data):
                    array['value']=data[target+8:target+8+count];output(array,None,off,pc,'constant_byte_array')
                else:regs.clear()
        elif opcode=='sget-object' and rr:
            field=operands.split(' // ',1)[0].split(', ',1)[-1]
            if field=='Ljava/nio/charset/StandardCharsets;.UTF_8:Ljava/nio/charset/Charset;':regs[rr[0]]={'kind':'charset_utf8'}
            else:regs.clear()
        elif opcode.startswith('sput-object') and rr:
            m=re.search(r';\.([^:]+):',operands)
            if m:output(regs.get(rr[0]),m.group(1),off,pc,'constant_field_assignment')
        elif opcode.startswith('invoke-'):
            m=re.match(r'\{([^}]*)\}, (.+?) // method@',operands)
            if not m:regs.clear();continue
            rr=[int(x) for x in re.findall(r'v(\d+)',m.group(1))]
            if '..' in m.group(1) and len(rr)==2:rr=list(range(rr[0],rr[1]+1)) if rr[1]-rr[0]<256 else []
            target=m.group(2);args=[regs.get(r) for r in rr]
            if opcode in ('invoke-static','invoke-static/range') and not args and (method_summaries or {}).get(target):
                item=method_summaries[target];pending={'kind':'method_return','value':item['value'],'provenance':{**item['provenance'],'caller_invoke_file_offset':off,'caller_invoke_code_unit_offset':pc}}
                stats['constant_method_returns_propagated']=stats.get('constant_method_returns_propagated',0)+1
                # These known library markers are immutable; discard mutable aliases.
                regs={r:v for r,v in regs.items() if isinstance(v,dict) and v.get('kind') in ('base64_basic_decoder','charset_utf8')}
            elif target=='Ljava/lang/StringBuilder;.<init>:()V':pass
            elif target in ('Ljava/lang/StringBuilder;.append:(Ljava/lang/String;)Ljava/lang/StringBuilder;','Ljava/lang/StringBuilder;.append:(I)Ljava/lang/StringBuilder;') and len(args)==2:
                obj=args[0];v=value(args[1])
                if isinstance(obj,dict) and obj.get('kind')=='builder' and isinstance(v,(str,int)) and isinstance(obj['value'],str) and len(obj['value'])+len(str(v))<=8192:
                    obj['value']+=str(v);pending=obj
                else:regs.clear()
            elif target in ('Ljava/lang/String;.<init>:([BLjava/lang/String;)V','Ljava/lang/String;.<init>:([BLjava/nio/charset/Charset;)V','Ljava/lang/String;.<init>:([BIILjava/lang/String;)V','Ljava/lang/String;.<init>:([BIILjava/nio/charset/Charset;)V'):
                sliced='[BII' in target;expected=5 if sliced else 3
                if len(args)==expected and isinstance(args[0],dict) and args[0].get('kind')=='string_object':
                    obj=args[0];obj['value']=None;obj.pop('provenance',None)
                    source=value(args[1]);start=value(args[2]) if sliced else 0
                    length=value(args[3]) if sliced else len(source) if isinstance(source,bytes) else None
                    charset=args[-1];named=target.endswith('Ljava/lang/String;)V')
                    supported=(isinstance(charset,str) and charset.lower() in ('utf-8','utf8')) if named else (isinstance(charset,dict) and charset.get('kind')=='charset_utf8')
                    restored=restore_utf8(source,start,length) if supported else None
                    if restored is not None:
                        provenance=dict(args[1].get('provenance',{})) if isinstance(args[1],dict) else {}
                        provenance.update(string_constructor_file_offset=off,string_constructor_code_unit_offset=pc,string_byte_offset=start,string_byte_length=length,string_character_count=len(restored))
                        provenance.setdefault('transform','bytes_to_utf8_string')
                        obj.update(value=restored,provenance=provenance)
                        output(obj,None,off,pc,'constant_utf8_string_constructor')
                else:regs.clear()
            elif target=='Ljava/lang/StringBuilder;.toString:()Ljava/lang/String;' and len(args)==1:
                pending=value(args[0]);output(pending,None,off,pc,'constant_string_builder')
            elif target=='Ljava/lang/String;.concat:(Ljava/lang/String;)Ljava/lang/String;' and len(args)==2 and all(isinstance(x,str) for x in args):
                if len(args[0])+len(args[1])<=8192:pending=args[0]+args[1];output(pending,None,off,pc,'constant_concat')
            elif target in ('Ljava/util/Arrays;.copyOf:([BI)[B','Ljava/util/Arrays;.copyOfRange:([BII)[B'):
                ranged='copyOfRange:' in target
                if len(args)==(3 if ranged else 2):
                    source=value(args[0]);start=value(args[1]) if ranged else 0;end=value(args[2]) if ranged else value(args[1])
                    restored=copy_bytes(source,start,end)
                    provenance=dict(args[0].get('provenance',{})) if isinstance(args[0],dict) else {}
                    steps=list(provenance.get('array_copy_steps',[]))
                    if restored is not None and len(steps)<8:
                        copied,padding=restored
                        steps.append({'operation':'copyOfRange' if ranged else 'copyOf','file_offset':off,'dex_code_unit_offset':pc,'input_length':len(source),'from':start,'to':end,'output_length':len(copied),'zero_padding_length':padding})
                        provenance['array_copy_steps']=steps
                        provenance.setdefault('transform','constant_array_copy')
                        pending={'kind':'copied_bytes','value':copied,'provenance':provenance}
            elif target=='Ljava/util/Base64;.getDecoder:()Ljava/util/Base64$Decoder;' and not args:
                pending={'kind':'base64_basic_decoder'}
            elif target in ('Ljava/util/Base64$Decoder;.decode:(Ljava/lang/String;)[B','Landroid/util/Base64;.decode:(Ljava/lang/String;I)[B'):
                android=target.startswith('Landroid/')
                stats['constant_decode_attempts']=stats.get('constant_decode_attempts',0)+1
                supported=len(args)==2 and (isinstance(args[1],int) and args[1] in (0,2) if android else isinstance(args[0],dict) and args[0].get('kind')=='base64_basic_decoder')
                source=(args[0] if android else args[1]) if len(args)==2 else None
                provenance=dict(source.get('provenance',{})) if isinstance(source,dict) else {}
                decoded=decode_literal(value(source),android) if supported and 'decode_file_offset' not in provenance else None
                if decoded is not None:
                    stats['constant_decode_recovered']=stats.get('constant_decode_recovered',0)+1
                    pending={'kind':'decoded_bytes','value':decoded,'provenance':{**provenance,'transform':'base64_android_one_layer' if android else 'base64_java_basic_one_layer','decode_file_offset':off,'decode_code_unit_offset':pc,'decoded_length':len(decoded)}}
                    output(pending,None,off,pc,'constant_base64_decode')
                else:
                    stats['constant_decode_unresolved']=stats.get('constant_decode_unresolved',0)+1
                    regs.clear()
            elif target=='Ljava/nio/charset/Charset;.forName:(Ljava/lang/String;)Ljava/nio/charset/Charset;' and len(args)==1:
                pending={'kind':'charset_utf8'} if isinstance(args[0],str) and args[0].lower() in ('utf-8','utf8') else None
            elif target in ('Ljava/lang/String;.getBytes:(Ljava/lang/String;)[B','Ljava/lang/String;.getBytes:(Ljava/nio/charset/Charset;)[B'):
                named=target.endswith('(Ljava/lang/String;)[B')
                supported=len(args)==2 and isinstance(value(args[0]),str) and len(value(args[0]))<=8192
                if supported:
                    charset=args[1]
                    supported=(isinstance(charset,str) and charset.lower() in ('utf-8','utf8')) if named else (isinstance(charset,dict) and charset.get('kind')=='charset_utf8')
                if supported:
                    try:encoded=value(args[0]).encode('utf8')
                    except UnicodeError:encoded=None
                    if encoded is not None and len(encoded)<=8192:
                        provenance=dict(args[0].get('provenance',{})) if isinstance(args[0],dict) else {}
                        pending={'kind':'encoded_bytes','value':encoded,'provenance':{**provenance,'transform':'string_getbytes_utf8','encode_file_offset':off,'encode_code_unit_offset':pc,'encoded_length':len(encoded)}}
                # Unsupported charset or malformed text does not produce inferred bytes.
            elif target=='Ljava/lang/String;.getBytes:()[B' and len(args)==1 and isinstance(value(args[0]),str):
                try:encoded=value(args[0]).encode('utf8')
                except UnicodeError:encoded=None
                if encoded is not None and len(encoded)<=8192:pending={'kind':'encoded_bytes','value':encoded,'provenance':dict(args[0].get('provenance',{})) if isinstance(args[0],dict) else {}}
            elif target=='Ljava/lang/String;.toCharArray:()[C' and len(args)==1 and isinstance(args[0],str):pending=args[0]
            elif target in ('Ljavax/crypto/spec/SecretKeySpec;.<init>:([BLjava/lang/String;)V','Ljavax/crypto/spec/SecretKeySpec;.<init>:([BIILjava/lang/String;)V','Ljavax/crypto/spec/IvParameterSpec;.<init>:([B)V','Ljavax/crypto/spec/IvParameterSpec;.<init>:([BII)V'):
                is_key='SecretKeySpec;' in target
                sliced='[BII' in target
                expected=(5 if sliced else 3) if is_key else (4 if sliced else 2)
                if len(args)==expected:
                    material=value(args[1])
                    start=value(args[2]) if sliced else 0
                    length=value(args[3]) if sliced else len(material) if isinstance(material,bytes) else None
                    algorithm_known=not is_key or isinstance(value(args[-1]),str)
                    # Nonempty supported candidates only; this is not provider validity checking.
                    if isinstance(material,bytes) and type(start) is int and type(length) is int and start>=0 and length>0 and start+length<=len(material) and algorithm_known:
                        kind='SecretKeySpec' if is_key else 'IvParameterSpec'
                        context=evidence(off,pc,'constant_to_'+kind)
                        if isinstance(args[1],dict):context.update(args[1].get('provenance',{}))
                        context.update(sink='javax.crypto.spec.'+kind,source_array_length=len(material),source_array_offset=start,material_length=length,constructor_descriptor=target,provider_acceptance='unknown',runtime_use='unknown')
                        context['material_encoding']='hex'
                        emit(material[start:start+length].hex(),None,context,'HC-005' if is_key else 'HC-007')
                regs.clear()
            elif target in ('Ljavax/crypto/spec/GCMParameterSpec;.<init>:(I[B)V','Ljavax/crypto/spec/GCMParameterSpec;.<init>:(I[BII)V'):
                expected=5 if target.endswith('[BII)V') else 3
                if len(args)==expected:
                    nonce=value(args[2]);tag=value(args[1])
                    start=value(args[3]) if expected==5 else 0
                    length=value(args[4]) if expected==5 else len(nonce) if isinstance(nonce,bytes) else None
                    if isinstance(nonce,bytes) and type(tag) is int and tag>=0 and type(start) is int and type(length) is int and start>=0 and length>0 and start+length<=len(nonce):
                        context=evidence(off,pc,'constant_nonce_to_GCMParameterSpec')
                        if isinstance(args[2],dict):context.update(args[2].get('provenance',{}))
                        context.update(sink='javax.crypto.spec.GCMParameterSpec',nonce_length=length,source_array_length=len(nonce),source_array_offset=start,tag_length_bits=tag,constructor_descriptor=target, encryption_use='unknown',same_key_nonce_reuse='unknown')
                        context['material_encoding']='hex'
                        emit(nonce[start:start+length].hex(),None,context,'HC-007')
                regs.clear()
            elif target in ('Ljavax/crypto/spec/PBEKeySpec;.<init>:([C[BII)V','Ljavax/crypto/spec/PBEKeySpec;.<init>:([C[BI)V'):
                expected=5 if target.endswith('[C[BII)V') else 4
                if len(args)==expected:
                    salt=value(args[2]);iterations=value(args[3]);key_length=value(args[4]) if expected==5 else None
                    # Exact constructor signature, non-empty constant bytes and valid known
                    # numeric arguments. Unknown/branch-derived values are not inferred.
                    if isinstance(salt,bytes) and len(salt)>0 and isinstance(iterations,int) and iterations>0 and (expected==4 or isinstance(key_length,int) and key_length>0):
                        context=evidence(off,pc,'constant_salt_to_PBEKeySpec')
                        if isinstance(args[2],dict):context.update(args[2].get('provenance',{}))
                        context.update(sink='javax.crypto.spec.PBEKeySpec',salt_length=len(salt),iteration_count=iterations,key_length_bits=key_length)
                        context['material_encoding']='hex'
                        emit(salt.hex(),None,context,'HC-008')
                regs.clear()
            elif target=='Ljava/net/PasswordAuthentication;.<init>:(Ljava/lang/String;[C)V' and len(args)==3:
                output(args[2],'password',off,pc,'constant_to_PasswordAuthentication');regs.clear()
            else:
                # Known string key/value API signatures only. Merely adjacent strings are not evidence.
                signatures=('Lorg/json/JSONObject;.put:(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;', 'Landroid/os/Bundle;.putString:(Ljava/lang/String;Ljava/lang/String;)V')
                if target in signatures and len(args)==3 and isinstance(args[1],str):output(args[2],args[1],off,pc,'constant_key_value_argument')
                regs.clear()
        elif opcode in ('nop','return-void') or opcode.startswith(('return','sput','iput')):pass
        else:
            # Clear all aliases on unsupported instructions, rather than infer through them.
            regs.clear()

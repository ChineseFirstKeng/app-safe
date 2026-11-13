"""Bounded offline ELF literals and JNI symbol clues; never loads shared libraries."""
import struct,re,time,base64,binascii
MAX_ELF=64*1024*1024

def bound(off,size,total):
    if off<0 or size<0 or off>total or size>total-off:raise ValueError('elf_bounds_invalid')

def parse(data):
    if len(data)<16 or data[:4]!=b'\x7fELF':raise ValueError('elf_magic_invalid')
    cls,order,version=data[4:7]
    if cls not in (1,2) or order not in (1,2) or version!=1:raise ValueError('elf_format_unsupported')
    wide=cls==2;endian='<' if order==1 else '>';header=64 if wide else 52;bound(0,header,len(data))
    kind,machine,ver,entry,phoff,shoff,flags,ehsize,phsize,phnum,shsize,shnum,shnames=struct.unpack_from(endian+('HHIQQQIHHHHHH' if wide else 'HHIIIIIHHHHHH'),data,16)
    if ver!=1 or ehsize!=header or kind not in (1,2,3):raise ValueError('elf_header_unsupported')
    if phnum==0xffff or (shnum==0 and shoff) or shnames==0xffff:raise ValueError('elf_extended_numbering_unsupported')
    if phnum>4096 or shnum>8192:raise ValueError('elf_table_limit')
    if phnum and phsize!=(56 if wide else 32):raise ValueError('elf_program_entry_invalid')
    if shnum and shsize!=(64 if wide else 40):raise ValueError('elf_section_entry_invalid')
    bound(phoff,phsize*phnum,len(data));bound(shoff,shsize*shnum,len(data));segments=[];sections=[]
    for i in range(phnum):
        values=struct.unpack_from(endian+('IIQQQQQQ' if wide else 'IIIIIIII'),data,phoff+i*phsize)
        if wide:typ,flg,off,addr,paddr,sz,mem,align=values
        else:typ,off,addr,paddr,sz,mem,flg,align=values
        bound(off,sz,len(data))
        if typ==1:
            if sz>mem or (align>1 and (align&(align-1) or off%align!=addr%align)):raise ValueError('elf_segment_invalid')
            segments.append({'offset':off,'size':sz,'address':addr,'flags':flg})
    for i in range(shnum):
        name,typ,flg,addr,off,sz,link,info,align,entsize=struct.unpack_from(endian+('IIQQQQIIQQ' if wide else 'IIIIIIIIII'),data,shoff+i*shsize)
        if typ!=8:bound(off,sz,len(data))
        sections.append({'name_index':name,'type':typ,'flags':flg,'address':addr,'offset':off,'size':sz,'link':link,'entry_size':entsize})
    def string(table,index):
        if index>=table['size']:raise ValueError('elf_string_index_invalid')
        start=table['offset']+index;end=data.find(b'\0',start,min(table['offset']+table['size'],start+4096))
        if end<0:raise ValueError('elf_string_termination_invalid')
        try:return data[start:end].decode('utf8')
        except UnicodeError:raise ValueError('elf_symbol_encoding_invalid')
    if shnames:
        if shnames>=len(sections) or sections[shnames]['type']!=3:raise ValueError('elf_section_names_invalid')
        for s in sections:s['name']=string(sections[shnames],s['name_index'])
    else:
        for s in sections:s['name']=''
    architecture={3:'x86',62:'x86_64',40:'armeabi-v7a',183:'arm64-v8a',8:'mips',243:'riscv64' if wide else 'riscv32'}.get(machine,'unknown')
    jni=[];jni_total=0;flutter=False;symbols=0
    for s in sections:
        if s['type'] not in (2,11):continue
        if s['entry_size']!=(24 if wide else 16) or s['size']%s['entry_size'] or s['link']>=len(sections) or sections[s['link']]['type']!=3:raise ValueError('elf_symbol_table_invalid')
        count=s['size']//s['entry_size'];symbols+=count
        if symbols>500000:raise ValueError('elf_symbol_limit')
        for i in range(count):
            off=s['offset']+i*s['entry_size']
            if wide:name,info,other,index,value,size=struct.unpack_from(endian+'IBBHQQ',data,off)
            else:name,value,size,info,other,index=struct.unpack_from(endian+'IIIBBH',data,off)
            symbol=string(sections[s['link']],name)
            if symbol.startswith('_kDart') or symbol.startswith('kDart'):flutter=True
            # Externally visible defined functions, not a proof that Java resolves/calls them.
            if s['type']==11 and index!=0 and info&15==2 and info>>4 in (1,2) and other&3 in (0,3) and (symbol.startswith('Java_') or symbol=='JNI_OnLoad'):
                jni_total+=1
                if len(jni)<100:jni.append({'name':symbol[:256],'address':hex(value),'size':size})
    return {'architecture':architecture,'bits':64 if wide else 32,'endian':'little' if order==1 else 'big','file_type':kind,'sections':sections,'segments':segments,'symbols_examined':symbols,'jni_symbol_status':'table_examined' if any(s['type']==11 for s in sections) else 'not_run_no_dynamic_symbol_table','jni_exports':jni,'jni_export_count':jni_total,'jni_exports_truncated':jni_total>len(jni),'dart_snapshot_symbols':flutter}

def inspect(data,emit,deadline):
    result=parse(data);sections=result.pop('sections');segments=result.pop('segments')
    result.update(status='literal_pass_finished',strings_checked=0,bytes_examined=0,decode_attempts=0,decoded_literals=0,gaps=[],gap_count=0,jni_dynamic_registration='not_analyzed')
    def gap(reason):
        result['gap_count']+=1
        if len(result['gaps'])<32:result['gaps'].append(reason)
    regions=[]
    for i,s in enumerate(sections):
        # Allocated, non-executable program data only; never debug/symbol strings.
        if s['type']==1 and s['flags']&2 and not s['flags']&4 and s['size']:
            if s['flags']&0x800:gap('compressed_section_not_decoded');continue
            if result['file_type'] in (2,3) and not any(s['offset']>=p['offset'] and s['offset']+s['size']<=p['offset']+p['size'] and s['address']==p['address']+s['offset']-p['offset'] for p in segments):gap('section_load_mapping_unresolved');continue
            regions.append((s['offset'],s['size'],s['address'],s['name'][:128] or 'section:'+str(i)))
    if not sections:
        gap('section_table_absent_segment_fallback')
        regions=[(s['offset'],s['size'],s['address'],'PT_LOAD:'+str(i)) for i,s in enumerate(segments) if s['flags']&4 and not s['flags']&1 and s['size']]
    for off,size,addr,name in regions:
        if time.monotonic()>deadline:gap('elf_timeout');break
        if size>32*1024*1024 or result['bytes_examined']+size>48*1024*1024:gap('elf_literal_budget');continue
        result['bytes_examined']+=size;raw=data[off:off+size]
        for m in re.finditer(rb'[\x20-\x7e\t\r\n]{6,}',raw):
            if time.monotonic()>deadline:gap('elf_timeout');break
            if len(m[0])>65536:gap('elf_string_limit');continue
            if result['strings_checked']>=200000:gap('elf_string_count_limit');break
            result['strings_checked']+=1;text=m[0].decode('ascii')
            context={'usage':'elf_literal_only','architecture':result['architecture'],'region':name,'file_offset':off+m.start(),'virtual_address':hex(addr+m.start()),'address_model':'elf_link_time','transform':'none'}
            emit(text,context)
            # One strict decoding layer, bounded per image; no XOR guessing or target execution.
            candidate=text.strip();kind=None
            if candidate.startswith('base64:'):candidate=candidate[7:];kind='base64'
            elif candidate.startswith('hex:'):candidate=candidate[4:];kind='hex'
            elif 24<=len(candidate)<=8192 and re.fullmatch('[A-Za-z0-9+/]+={0,2}',candidate) and len(candidate)%4==0:kind='base64'
            if kind:
                if result['decode_attempts']>=2000:gap('elf_decode_budget');continue
                if not 16<=len(candidate)<=8192:continue
                result['decode_attempts']+=1
                try:
                    decoded=base64.b64decode(candidate,validate=True) if kind=='base64' else bytes.fromhex(candidate)
                    value=decoded.decode('utf8')
                    if not value.isprintable():continue
                    result['decoded_literals']+=1;emit(value,{**context,'transform':kind+'_one_layer','usage':'elf_decoded_literal_only'})
                except (ValueError,UnicodeError,binascii.Error):pass
    if not regions:gap('no_supported_literal_regions')
    if result['gap_count']:result['status']='partial'
    return result

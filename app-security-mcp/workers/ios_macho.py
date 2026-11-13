"""Bounded Mach-O structure and literal inspection; no loading, execution or decryption."""
import struct,hashlib,time,re
from ios_literal_decode import LiteralDecoder

THIN={b'\xce\xfa\xed\xfe':('<',32),b'\xcf\xfa\xed\xfe':('<',64),b'\xfe\xed\xfa\xce':('>',32),b'\xfe\xed\xfa\xcf':('>',64)}
FAT={b'\xca\xfe\xba\xbe':('>',32),b'\xbe\xba\xfe\xca':('<',32),b'\xca\xfe\xba\xbf':('>',64),b'\xbf\xba\xfe\xca':('<',64)}
MAX_NATIVE_FILE=64*1024*1024
MAX_NATIVE_TOTAL=256*1024*1024
MAX_SECTIONS=4096
MAX_LITERAL_BYTES=32*1024*1024
MAX_STRING=65536

def is_macho(magic):return magic in THIN or magic in FAT

def bounds(start,size,total,reason='macho_bounds_invalid'):
    if start<0 or size<0 or start>total or size>total-start:raise ValueError(reason)

def label(data):
    try:return data.split(b'\0',1)[0].decode('ascii')
    except UnicodeError:raise ValueError('macho_label_invalid')

def slices(data):
    magic=bytes(data[:4])
    if magic in THIN:return [(0,len(data),None,None)]
    if magic not in FAT:raise ValueError('macho_magic_invalid')
    endian,bits=FAT[magic];bounds(0,8,len(data))
    count=struct.unpack_from(endian+'I',data,4)[0];entry_size=20 if bits==32 else 32
    if not 1<=count<=16:raise ValueError('macho_slice_limit')
    header_end=8+count*entry_size;bounds(0,header_end,len(data))
    result=[]
    for i in range(count):
        values=struct.unpack_from(endian+('IIIII' if bits==32 else 'IIQQII'),data,8+i*entry_size)
        cpu,sub,offset,size,align=values[:5]
        bounds(offset,size,len(data))
        if offset<header_end or size<28 or align>30 or offset%(1<<align):raise ValueError('macho_slice_layout_invalid')
        if any(offset<o+s and o<offset+size for o,s,_,_ in result):raise ValueError('macho_slices_overlap')
        result.append((offset,size,cpu,sub))
    return result

def parse_slice(data,base,size,declared_cpu=None,declared_sub=None):
    magic=bytes(data[base:base+4])
    if magic not in THIN:raise ValueError('macho_slice_magic_invalid')
    endian,bits=THIN[magic];header=32 if bits==64 else 28;bounds(0,header,size)
    cpu,sub,filetype,ncmds,command_bytes,flags=struct.unpack_from(endian+'IIIIII',data,base+4)
    if declared_cpu is not None and (cpu!=declared_cpu or sub!=declared_sub):raise ValueError('macho_slice_cpu_mismatch')
    if ncmds>4096 or command_bytes>4*1024*1024:raise ValueError('macho_command_limit')
    bounds(header,command_bytes,size);end=header+command_bytes;pos=header;sections=[];encryption=[]
    for _ in range(ncmds):
        bounds(pos,8,end);cmd,length=struct.unpack_from(endian+'II',data,base+pos)
        if length<8 or length%4:raise ValueError('macho_command_size_invalid')
        bounds(pos,length,end)
        if cmd in (1,0x19):
            wide=cmd==0x19;seg_size=72 if wide else 56;section_size=80 if wide else 68
            if wide!=(bits==64) or length<seg_size:raise ValueError('macho_segment_invalid')
            segment=label(data[base+pos+8:base+pos+24]);fmt='QQQQIIII' if wide else 'IIIIIIII'
            vmaddr,vmsize,fileoff,filesize,maxprot,initprot,nsects,segflags=struct.unpack_from(endian+fmt,data,base+pos+24)
            bounds(fileoff,filesize,size)
            if nsects>MAX_SECTIONS or len(sections)+nsects>MAX_SECTIONS or seg_size+nsects*section_size>length:raise ValueError('macho_section_limit')
            for j in range(nsects):
                off=base+pos+seg_size+j*section_size
                name=label(data[off:off+16]);section_segment=label(data[off+16:off+32])
                vals=struct.unpack_from(endian+('QQIIIIIIII' if wide else 'IIIIIIIII'),data,off+32)
                addr,sz,offset,alignment,reloff,nreloc,sflags=vals[:7]
                zerofill=(sflags&255) in (1,0xc,0x12)
                if not zerofill and sz:
                    bounds(offset,sz,size)
                    if filetype!=1 and (offset<fileoff or offset+sz>fileoff+filesize):raise ValueError('macho_section_outside_segment')
                if addr<vmaddr or addr+sz>vmaddr+vmsize:raise ValueError('macho_section_vm_bounds')
                sections.append({'segment':section_segment,'section':name,'address':addr,'size':sz,'offset':offset,'flags':sflags,'file_backed':not zerofill})
        elif cmd in (0x21,0x2c):
            if length<(24 if cmd==0x2c else 20):raise ValueError('macho_encryption_command_invalid')
            cryptoff,cryptsize,cryptid=struct.unpack_from(endian+'III',data,base+pos+8);bounds(cryptoff,cryptsize,size)
            encryption.append({'file_offset':base+cryptoff,'size':cryptsize,'cryptid':cryptid})
        pos+=length
    if pos!=end:raise ValueError('macho_command_table_inconsistent')
    architecture={7:'x86',0x1000007:'x86_64',12:'arm',0x100000c:'arm64',18:'powerpc',0x1000012:'powerpc64'}.get(cpu,'unknown')
    if cpu==0x100000c and sub&0xffffff==2:architecture='arm64e'
    return {'architecture':architecture,'cpu_type':cpu,'cpu_subtype':sub,'bits':bits,'endian':endian,'file_type':filetype,'sections':sections,'encryption_commands':encryption,'encrypted':any(e['cryptid']!=0 for e in encryption)}

def inspect(data,emit,deadline,decode_attempt_limit=2000):
    layout=slices(data);results=[]
    for index,(base,size,cpu,sub) in enumerate(layout):
        if time.monotonic()>deadline:raise ValueError('macho_timeout')
        record={'slice_index':index,'slice_offset':base,'slice_size':size,'slice_sha256':hashlib.sha256(data[base:base+size]).hexdigest()}
        results.append(record)
        try:
            parsed=parse_slice(data,base,size,cpu,sub)
            record.update({k:v for k,v in parsed.items() if k!='sections'})
            record['section_count']=len(parsed['sections']);record['strings_checked']=0;record['sections_checked']=0;record['section_gaps']=[];record['section_gap_count']=0
            def gap(item):
                record['section_gap_count']+=1
                if len(record['section_gaps'])<32:record['section_gaps'].append(item)
            decoder=LiteralDecoder(decode_attempt_limit);record['literal_decoding']=decoder.stats
            if parsed['encrypted']:
                record.update(status='blocked',reason='encrypted_macho_slice');continue
            record['status']='literal_pass_finished';budget=0
            for section in parsed['sections']:
                if time.monotonic()>deadline:raise ValueError('macho_timeout')
                name=section['section'];flags=section['flags']
                if not section['file_backed'] or not section['size']:continue
                cstring=flags&255==2 or name in ('__cstring','__objc_methname','__objc_classname','__swift5_reflstr')
                utf16=name=='__ustring';opaque=name in ('__const','__data') and flags&255==0 and not flags&0x80000400
                if not (cstring or utf16 or opaque):continue
                amount=section['size'];offset=base+section['offset']
                if amount>8*1024*1024 or budget+amount>MAX_LITERAL_BYTES:
                    gap({'section':name,'reason':'macho_literal_budget'});continue
                budget+=amount;record['sections_checked']+=1;raw=data[offset:offset+amount]
                common={k:record[k] for k in ('slice_index','slice_offset','slice_size','slice_sha256','architecture','file_type')}
                common.update(segment=section['segment'],section=name,usage='native_literal_only')
                def output(value,rel,encoding):
                    record['strings_checked']+=1
                    if record['strings_checked']>100000:raise ValueError('macho_string_count_limit')
                    if time.monotonic()>deadline:raise ValueError('macho_timeout')
                    context={**common,'file_offset':offset+rel,'virtual_address':hex(section['address']+rel),'encoding':encoding,'transform':'none'}
                    emit(value,context)
                    decoded=decoder.decode(value)
                    if decoded:
                        text,transform=decoded
                        emit(text,{**context,'usage':'native_decoded_literal_only','transform':transform,'derivation':'heuristic_literal_decode_not_runtime_call'})
                if utf16:
                    if amount%2:gap({'section':name,'reason':'macho_utf16_odd_size'})
                    start=0
                    for p in range(0,len(raw)-1,2):
                        if raw[p:p+2]!=b'\0\0':continue
                        if 0<p-start<=MAX_STRING:
                            try:output(raw[start:p].decode('utf-16-le' if parsed['endian']=='<' else 'utf-16-be'),start,'utf16')
                            except UnicodeError:gap({'section':name,'reason':'macho_string_encoding'})
                        elif p-start>MAX_STRING:gap({'section':name,'reason':'macho_string_limit'})
                        start=p+2
                    if start<len(raw):gap({'section':name,'reason':'macho_unterminated_string'})
                elif cstring:
                    start=0
                    while start<len(raw):
                        end=raw.find(b'\0',start)
                        if end<0:gap({'section':name,'reason':'macho_unterminated_string'});break
                        if end-start>MAX_STRING:gap({'section':name,'reason':'macho_string_limit'})
                        elif end>start:
                            try:output(raw[start:end].decode('utf8'),start,'utf8')
                            except UnicodeError:gap({'section':name,'reason':'macho_string_encoding'})
                        start=end+1
                else:
                    # Conservative printable runs in data sections; no key/value pairing inferred.
                    for m in re.finditer(rb'[\x20-\x7e\r\n\t]{6,}',raw):
                        if len(m[0])>MAX_STRING:gap({'section':name,'reason':'macho_string_limit'});continue
                        output(m[0].decode('ascii'),m.start(),'ascii_run')
            if decoder.stats['skipped_budget']:gap({'section':'*','reason':'macho_decode_budget'})
            if decoder.stats['skipped_size']:gap({'section':'*','reason':'macho_decode_input_size'})
            if record['section_gaps']:record['status']='partial'
            # Bound diagnostics independently of the findings budget.
            record['section_gaps_truncated']=record['section_gap_count']>len(record['section_gaps'])
        except (ValueError,struct.error) as e:
            record.update(status='blocked',reason=str(e) if isinstance(e,ValueError) else 'macho_struct_invalid')
    return results

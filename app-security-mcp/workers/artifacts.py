"""Local-only package inventory. Never extracts or executes archive members."""
import os, sys, json, stat, hashlib, uuid, shutil, zipfile, time
from pathlib import Path

MAX_INPUT = 1024 * 1024 * 1024
MAX_TOTAL = 2 * 1024 * 1024 * 1024
MAX_MEMBER = 256 * 1024 * 1024
MAX_FILES = 30000
MAX_RATIO = 200
class Rejected(Exception): pass

def require(condition, reason):
    if not condition: raise Rejected(reason)

def root_dir(value):
    p = Path(value).absolute()
    require(not p.is_symlink(), 'storage_symlink')
    p.mkdir(parents=True, exist_ok=True, mode=0o700)
    require(p.is_dir() and p.stat().st_uid == os.getuid(), 'invalid_storage_owner')
    os.chmod(p, 0o700)
    return p

def target(root, ident):
    require(isinstance(ident,str) and len(ident)==32 and all(x in '0123456789abcdef' for x in ident), 'invalid_artifact_id')
    p=root/ident
    require(p.is_dir() and not p.is_symlink(), 'artifact_not_found')
    return p

def kind(name):
    n=name.lower()
    if n.endswith('/'): return 'directory'
    if n.endswith('.dex'): return 'dex'
    if n.endswith('.so'): return 'native_library'
    if n.endswith(('.zip','.apk','.ipa','.jar')): return 'nested_archive'
    if n.endswith(('.plist','.xml','.json','.yaml','.yml','.properties')): return 'configuration'
    if n.endswith(('.db','.sqlite','.sqlite3')): return 'database_candidate'
    if n.endswith(('.pem','.p12','.pfx','.key','.cer','.crt')): return 'crypto_material_candidate'
    if '/frameworks/' in n or '/plugins/' in n: return 'embedded_component_file'
    return 'resource_or_binary'

def inventory(path, expected):
    entries=[]; names=set(); canonical=set(); total=0; deadline=time.monotonic()+40
    with zipfile.ZipFile(path) as z:
        infos=z.infolist()
        require(0<len(infos)<=MAX_FILES,'entry_count_limit')
        for info in infos:
            name=info.filename
            require(name==info.orig_filename and len(name)<=4096,'invalid_entry_name')
            parts=name.rstrip('/').split('/')
            require(name and not name.startswith(('/', '\\')) and '\\' not in name and ':' not in name and not any(x in ('','.','..') for x in parts),'unsafe_entry_path')
            require(not any(ord(x)<32 or ord(x)==127 for x in name),'control_character_in_path')
            require(name not in names and name.rstrip('/') not in canonical,'duplicate_entry')
            mode=info.external_attr>>16
            require(stat.S_IFMT(mode) in (0,stat.S_IFREG,stat.S_IFDIR),'special_entry_not_supported')
            require(not info.flag_bits&1,'encrypted_zip_entry')
            require(info.compress_type in (zipfile.ZIP_STORED,zipfile.ZIP_DEFLATED),'unsupported_compression')
            require(info.file_size<=MAX_MEMBER,'member_size_limit')
            require(info.file_size/max(1,info.compress_size)<=MAX_RATIO,'compression_ratio_limit')
            total+=info.file_size
            require(total<=MAX_TOTAL,'expanded_size_limit')
            names.add(name); canonical.add(name.rstrip('/'))
        files={i.filename for i in infos if not i.is_dir()}
        for name in names:
            parts=name.rstrip('/').split('/')
            require(not any('/'.join(parts[:i]) in files for i in range(1,len(parts))),'file_directory_conflict')
        apps=sorted(n for n in files if n.startswith('Payload/') and n.endswith('.app/Info.plist') and n.count('/')==2)
        apk='AndroidManifest.xml' in files
        require(not (apk and apps),'ambiguous_package')
        detected='android' if apk else ('ios' if len(apps)==1 else None)
        require(detected is not None,'unrecognized_package_layout')
        require(expected in ('auto',detected),'platform_mismatch')
        actual_total=0
        for info in infos:
            h=hashlib.sha256(); count=0
            with z.open(info) as member:
                while True:
                    require(time.monotonic()<deadline,'inventory_timeout')
                    data=member.read(1024*1024)
                    if not data: break
                    count+=len(data); actual_total+=len(data)
                    require(count<=MAX_MEMBER and actual_total<=MAX_TOTAL,'actual_size_limit')
                    h.update(data)
            require(count==info.file_size,'size_mismatch')
            entries.append({'path':info.filename,'kind':kind(info.filename),'size':count,'compressed_size':info.compress_size,'sha256':h.hexdigest()})
    counts={}
    for e in entries: counts[e['kind']]=counts.get(e['kind'],0)+1
    return {'platform':detected,'format':'apk' if detected=='android' else 'ipa','format_confidence':'structural_candidate','entries':entries,'counts':counts,'expanded_bytes':actual_total,
      'coverage':{'zip_inventory':'complete','member_size_and_crc':'complete','platform_semantic_validation':'not_run','nested_archive_contents':'not_run','resource_decoding':'not_run','dex_analysis':'not_run' if detected=='android' else 'not_applicable','native_analysis':'not_run','hardcoding_detection':'not_run'},
      'limitations':['Only ZIP integrity and package layout were validated; installability, signatures and platform semantics are unverified.','Nested archives are inventoried but not recursively opened.','Mach-O encryption, packers and code contents have not been analyzed.','No hardcoding scan or app execution was performed.']}

def main(req):
    root=root_dir(req['storage_root']); op=req['operation']
    if op=='import':
        source=Path(req['path'])
        require(source.is_absolute(),'absolute_path_required')
        # Resolve parent aliases (macOS /var), but reject a symlink as the input file.
        require(not source.is_symlink(),'source_symlink')
        source=source.parent.resolve(strict=True)/source.name
        fd=os.open(source,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        ident=req.get('import_id') or uuid.uuid4().hex; staging=root/('.pending-'+ident); dest=root/ident
        try:
            before=os.fstat(fd)
            require(stat.S_ISREG(before.st_mode),'regular_file_required')
            require(0<before.st_size<=MAX_INPUT,'input_size_limit')
            staging.mkdir(mode=0o700)
            with os.fdopen(fd,'rb') as src:
                fd=-1; h=hashlib.sha256(); size=0
                with open(staging/'package.bin','xb') as out:
                    os.chmod(staging/'package.bin',0o600)
                    while True:
                        block=src.read(1024*1024)
                        if not block: break
                        size+=len(block); require(size<=MAX_INPUT,'input_size_limit'); h.update(block);out.write(block)
                after=os.fstat(src.fileno())
            require((before.st_size,before.st_mtime_ns,before.st_ctime_ns)==(after.st_size,after.st_mtime_ns,after.st_ctime_ns) and size==before.st_size,'source_changed')
            result=inventory(staging/'package.bin',req.get('expected_platform','auto'))
            result.update({'schema_version':'0.1','artifact_id':ident,'sha256':h.hexdigest(),'size':size,'entry_count':len(result['entries']),'imported_at':int(time.time())})
            with open(staging/'inventory.json','x') as out:
                os.chmod(staging/'inventory.json',0o600);json.dump(result,out,ensure_ascii=True)
            os.chmod(staging/'package.bin',0o400)
            staging.rename(dest)
            return {k:v for k,v in result.items() if k!='entries'}
        finally:
            if fd>=0: os.close(fd)
            if staging.exists(): shutil.rmtree(staging)
    p=target(root,req['artifact_id'])
    if op=='delete':
        shutil.rmtree(p);return {'artifact_id':req['artifact_id'],'deleted':True}
    require(op=='inspect','unsupported_operation')
    with open(p/'inventory.json') as f: result=json.load(f)
    offset=req.get('offset',0);limit=req.get('limit',100)
    require(isinstance(offset,int) and offset>=0 and isinstance(limit,int) and 1<=limit<=200,'invalid_pagination')
    entries=result.pop('entries');end=offset+limit
    return {**result,'entries':entries[offset:end],'next_offset':end if end<len(entries) else None,'source_complete':True}

try:
    print(json.dumps({'ok':True,'result':main(json.load(sys.stdin))},ensure_ascii=True))
except Rejected as e:
    print(json.dumps({'ok':False,'error':str(e)}))
except (zipfile.BadZipFile,NotImplementedError,RuntimeError,EOFError):
    print(json.dumps({'ok':False,'error':'invalid_or_unsupported_zip'}))
except Exception:
    print(json.dumps({'ok':False,'error':'artifact_io_or_parser_error'}))

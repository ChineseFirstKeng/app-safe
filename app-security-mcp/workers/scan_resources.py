"""Bounded offline resource, Android DEX and iOS literal candidate detection."""
import sys, json, os, stat, hashlib, zipfile, re, plistlib, base64, time
from pathlib import Path
from contextlib import ExitStack
from nested_archives import NestedArchiveView
from private_evidence import PrivateEvidence
from key_material import KeyValidator, ENVELOPES
from sqlite_resources import inspect as inspect_sqlite
from config_signals import debug_enabled, private_urls
from personal_records import contact_categories, NAME_KEYS, EMAIL_KEYS, PHONE_KEYS, normalized as contact_key
from client_identifiers import identifier_kind
from android_resources import find_aapt2, dump, table_rows, xml_fields
from android_dex import find_dexdump, scan as scan_dex, MAX_DEX
from android_elf import inspect as inspect_elf, MAX_ELF
from ios_macho import is_macho, inspect as inspect_macho, MAX_NATIVE_FILE, MAX_NATIVE_TOTAL

MAX_FILE=2*1024*1024
MAX_TOTAL=32*1024*1024
MAX_FINDINGS=300
TEXT_EXT={'.json','.plist','.xml','.txt','.conf','.config','.ini','.properties','.env','.yaml','.yml','.pem','.key','.crt','.cer','.csv','.log','.db','.sqlite','.sqlite3','.der','.p8','.pk8'}
RULES={
 'HC-009':('疑似认证相关方法中的固定字符串分支判断','核实该分支是否实际控制认证、授权或验证码校验；若为固定通用口令/验证码，移除该入口并由受信服务完成校验，检查旧发行版本及兼容流程。普通字符串比较不是后门，不能仅凭方法名确认漏洞。'),
 'HC-012':('客户端标识/API Key 权限复核清点','核对服务提供方、实际 API 用途、应用绑定、权限和配额；包内字段本身不证明泄密或误用。'),
 'HC-011':('包内疑似明文联系人记录','核实数据是否为真实个人信息及是否确需随包分发；移除误打包的真实记录，测试改用明确合成数据。业务必需数据应通过受认证接口按需获取并最小化本地保存，复查旧发行包和构建输入；单纯改名或混淆不等于消除暴露。'),
 'HC-010':('包内私网地址或开启调试的配置线索','核对发行环境、配置是否生效及业务必要性；清理误打包的测试配置，关闭生产环境不必要的调试入口。私网地址不等于秘密或漏洞，合法局域网业务应记录用途；只有发现真实凭证时才按凭证规则处理轮换。'),
 'HC-008':('疑似固定盐传入 PBEKeySpec','确认是否用于实际口令派生及是否跨用户/记录重复；盐无需保密，按用途为每条记录生成独立随机盐并随派生结果保存。结合实际 KDF、性能与当前安全要求选择参数；已有数据制定兼容迁移和复测方案，不能仅把固定盐换成另一个固定值。'),
 'HC-001':('疑似固定密码或 Basic 凭证','移除包内共享凭证；核实用途后撤销或轮换，改为用户认证或服务端持有。'),
 'HC-002':('疑似固定认证令牌','核实令牌用途和权限；有效凭证应撤销或轮换，改为登录后签发、短有效期和可撤销令牌。'),
 'HC-003':('疑似服务访问 Secret','区分公开客户端标识和服务秘密；高权限秘密移到服务端，轮换旧值并限制权限。'),
 'HC-004':('疑似连接串内嵌凭证','移除数据库/消息服务直接访问凭证，经受认证的业务服务访问；核实后轮换旧凭证。'),
 'HC-005':('疑似常量密钥传入 SecretKeySpec','确认是否为实际业务密钥；移除包内共享密钥，迁移到服务端或使用平台密钥库按设备生成；轮换已分发密钥。'),
 'HC-007':('疑似固定 IV/Nonce 传入密码参数 API','结合实际密码算法和工作模式核实风险；按算法要求使用不可预测或唯一的 IV/Nonce，随密文保存并避免重复。'),
 'HC-006':('疑似包内私钥材料','核实密钥用途；若是真实私钥则撤销/轮换，避免向客户端分发共享私钥。'),
}
KEYS={
 'password':'HC-001','passwd':'HC-001','pwd':'HC-001','dbpassword':'HC-001',
 'accesstoken':'HC-002','refreshtoken':'HC-002','authtoken':'HC-002','bearertoken':'HC-002','sessiontoken':'HC-002',
 'clientsecret':'HC-003','apisecret':'HC-003','secretaccesskey':'HC-003','awssecretaccesskey':'HC-003',
}
PLACEHOLDERS={'','null','none','undefined','changeme','change_me','your_password','your_token','example','placeholder','redacted','test','dummy','password','xxx','xxxx','your_secret'}
def secretlike(v):
    return isinstance(v,str) and len(v.strip())>=6 and v.strip().lower() not in PLACEHOLDERS and not re.fullmatch(r'\$\{[^}]+\}|<[^>]+>|\*+|x+',v.strip(),re.I)
def safe_path(path):
    # Paths are still untrusted labels; redact common credential-bearing path values.
    return re.sub(r'(?i)(password|token|secret)([=:])[^/]+',r'\1\2[REDACTED]',path)
def run(req):
    decode_limit=req.get('scan_options',{}).get('ios_decode_attempt_limit',2000)
    if type(decode_limit) is not int or not 1<=decode_limit<=20000:raise ValueError('invalid_ios_decode_attempt_limit')
    root=Path(req['storage_root']); folder=root/req['artifact_id']
    for p in (folder,folder/'package.bin',folder/'inventory.json'):
        if p.is_symlink():raise ValueError('artifact_symlink')
    inv=json.loads((folder/'inventory.json').read_text())
    deadline=time.monotonic()+90
    private=PrivateEvidence(req)
    key_validator=KeyValidator(req.get('node_executable'),deadline)
    findings=[]; checked=[]; skipped=[]; seen=set(); total=0; truncated=False; node_index=0; checked_count=0; skipped_count=0; skip_counts={}
    android={"decoder":"aapt2", "available":bool(find_aapt2()), "binary_xml_decoded":0, "resource_tables_decoded":0, "failures":{}, "decoded_bytes":0}
    tool=find_aapt2(); table_values={}
    dex_tool=find_dexdump();dex_context={}
    dex={'constant_decode_attempts':0,'constant_decode_recovered':0,'constant_decode_unresolved':0,'decoder':'dexdump','available':bool(dex_tool),'files_total':0,'files_checked':0,'failures':{},'bytes_read':0,'output_bytes':0,'strings_checked':0,'classes_checked':0,'methods_checked':0,'methods_without_flow':0,'methods_skipped_limit':0,'files':[]}
    ios={'components':[],'component_count':0,'components_truncated':False,'files':[],'files_total':0,'files_checked':0,'files_omitted':0,'slices_checked':0,'slices_blocked':0,'bytes_read':0,'strings_checked':0,'failures':{}}
    elf={'files':[],'files_total':0,'files_checked':0,'files_omitted':0,'bytes_read':0,'strings_checked':0,'failures':{}}
    sqlite_files=[]
    identifier_items=[];identifier_seen=set();identifier_truncated=False
    declared={};bundle_roots=[];archive_meta={};archive_labels={};archive_prefixes={};nested_stats={}
    sanitize_path=globals()['safe_path']
    def safe_path(value):
        label=archive_labels.get(value,value)
        if label==value:
            for prefix,replacement in archive_prefixes.items():
                if value.startswith(prefix):label=replacement+value[len(prefix):];break
        return sanitize_path(label)
    def archive_evidence(member):
        data=archive_meta.get(member)
        if not data:return {}
        chain=[{'path':sanitize_path(p['path']),'sha256':p['sha256']} for p in data['archive_chain']]
        path=sanitize_path(data['member_path'])
        return {'archive_chain':chain,'member_path':path,'archive_path_redacted':chain!=data['archive_chain'] or path!=data['member_path']}
    def add(rule,member,location,method,details=None,raw_value=None):
        nonlocal truncated
        identity=(rule,member,location,method,json.dumps(dex_context,sort_keys=True))
        if identity in seen:return
        if len(findings)>=MAX_FINDINGS:truncated=True;return
        seen.add(identity)
        fid='f-'+str(len(findings)+1).zfill(4)
        private.add(fid,raw_value)
        findings.append({'finding_id':fid,'rule_id':rule,'title':RULES[rule][0],
            'severity':'needs_review','confidence':'medium','verification_level':'candidate',
            'value':'[REDACTED]','private_value_available':fid in private.values,'evidence_id':'e-'+fid,'evidence':{'path':safe_path(member),'location':location,'method':method,'member_sha256':member_hash,**dex_context,**archive_evidence(member),**(details or {})},
            'observations':['包内内容命中了指定格式、敏感字段或受限直线指令模式；普通 MCP 结果脱敏；捕获原值可通过本机核查报告查看。'],
            'unknowns':['凭证真实性、有效性、权限、代码是否使用该值及实际运行行为尚未验证。'],
            'remediation':RULES[rule][1],'retest':'重新构建安装包后复扫相同资源，确认敏感材料不再分发；另行验证轮换、权限和业务行为。'})
        if rule=='HC-006':
            findings[-1]['observations']=['私钥格式解析状态见 key_validation；parsed_private_key 表示解析为私钥对象，不代表业务用途或有效权限。其余状态仅为未完成验证的包装线索。']
            findings[-1]['unknowns']=['私钥归属、是否用于真实业务、权限、撤销状态和运行行为未知；加密或不支持的包装未解密验证。']
        if rule=='HC-009':
            findings[-1]['observations']=['在受限方法入口直线前缀中，常量字符串与参数的 String.equals 比较结果直接控制条件分支；方法名称仅提供认证用途线索。']
            findings[-1]['unknowns']=['分支实际业务意义、成功/拒绝方向、可达性、服务端复核及是否构成通用口令或后门均未确认。']
            findings[-1]['retest']='核实认证调用链和分支两侧行为；移除确认的通用口令后验证合法/非法输入及服务端授权，不能只以改名或候选消失确认修复。'
        if rule=='HC-011':
            findings[-1]['observations']=['同一个结构化对象包含明确姓名字段及符合支持格式的邮箱或电话字段；普通报告脱敏；捕获的联系字段可在本机核查报告中查看。']
            findings[-1]['unknowns']=['真实性、归属、是否为公开业务联系信息或未识别的合成样本、分发必要性和运行时使用均未确认。']
            findings[-1]['retest']='检查发行资源和构建输入中的真实数据，使用明确合成样本复测；确认授权获取与数据最小化，不能仅靠候选数量减少认定修复。'
        if rule=='HC-010':
            findings[-1]['observations']=['发现私有网段 URL 字面量。' if method=='private_network_url' else '发现明确开启的调试配置字段；是否生效未知。']
            findings[-1]['unknowns']=['未确认发行环境、配置是否使用、地址可达性或实际敏感性；可能是合法局域网功能、示例或未使用配置。']
            findings[-1]['retest']='核对发行构建和配置加载路径，确认不必要的调试/测试配置已移除；验证合法局域网及业务功能，不能以字符串消失代替用途核实。'
        if rule=='HC-007' and dex_context.get('usage')=='constant_nonce_to_GCMParameterSpec':
            findings[-1]['title']='疑似固定 Nonce 传入 GCMParameterSpec'
            findings[-1]['observations']=['受限直线指令中，已知常量字节或其有效切片传入 GCMParameterSpec；记录长度和标签位数；实际 Nonce 字节可在本机核查报告中查看。']
            findings[-1]['unknowns']=['Nonce 不是秘密；是否用于加密、同一密钥下是否重复、代码可达性及提供方是否接受标签长度均未确认。']
            findings[-1]['remediation']='先核实 Cipher.init 的模式、密钥来源及调用次数；如用于 GCM 加密，应保证同一密钥下每次加密的 Nonce 唯一，并随密文保存。不要只换成另一个固定值；仅用于解密既有数据或测试向量时应结合用途判断。'
            findings[-1]['retest']='复查 Nonce 生成与加密调用链，在同一密钥的重复调用、并发和重启场景验证不重复；验证解密兼容及认证失败处理，候选消失不等于已修复。'
        if rule=='HC-008':
            findings[-1]['observations']=['在受限直线指令范围内，非空常量字节盐传入明确的 PBEKeySpec 构造方法；记录已知参数；实际盐字节可在本机核查报告中查看，未提取调用者口令。']
            findings[-1]['unknowns']=['盐本身不是秘密；是否实际执行派生、使用何种 KDF、是否跨用户或记录复用以及服务端处理尚未确认。']
            findings[-1]['retest']='复查盐来源、每条记录的独立性及派生 API 调用；验证既有数据兼容和新旧口令校验流程，不能仅以候选消失确认修复。'
    def review_identifier(key,value,member,location,method,label=None):
        nonlocal identifier_truncated
        kind=identifier_kind(key,value)
        if not kind:return
        identity=(member,location,key,method,json.dumps(dex_context,sort_keys=True))
        if identity in identifier_seen:return
        if len(identifier_items)>=100:identifier_truncated=True;return
        identifier_seen.add(identity)
        private.add('id-'+str(len(identifier_items)+1).zfill(4),value)
        identifier_items.append({'review_id':'id-'+str(len(identifier_items)+1).zfill(4),'rule_id':'HC-012','classification':kind,'value':'[REDACTED]','value_preview':value[:4]+'…'+value[-4:] if len(value)>=16 else '[REDACTED]',
            'evidence':{'path':safe_path(member),'location':location,'method':method,'field_category':key,'field_label':safe_path(str(label or key))[:512],'member_sha256':member_hash,**dex_context,**archive_evidence(member)},
            'misuse_confirmed':False,'permissions':'unknown','application_restrictions':'unknown','provider':'unknown',
            'review_actions':['确认提供方及该字段的实际用途，不依据字段名认定公开或秘密。','按提供方能力核查应用绑定、允许的 API、权限、配额及服务端授权；客户端 ID 不应单独充当授权凭证。','仅在确认是可滥用的秘密或权限配置不当后，制定限制、迁移或轮换方案。']})
    def walk(value,member,trail='$',depth=0):
        nonlocal node_index
        node_index+=1
        if depth>40:raise ValueError('structured_depth_limit')
        if isinstance(value,dict):
            categories=contact_categories(value)
            if categories:add('HC-011',member,'structured-node:'+str(node_index),'structured_contact_record',{'data_categories':categories,'record_authenticity':'unknown'},raw_value={k:v for k,v in value.items() if contact_key(k) in NAME_KEYS|EMAIL_KEYS|PHONE_KEYS})
            for k,v in value.items():
                key=re.sub('[^a-z0-9]','',str(k).lower())
                if key in KEYS and secretlike(v):add(KEYS[key],member,'structured-node:'+str(node_index)+':field:'+key,'structured_sensitive_field',raw_value=v)
                if debug_enabled(key,v):add('HC-010',member,'structured-node:'+str(node_index)+':field:'+key,'enabled_debug_flag',raw_value={'field':key,'value':v})
                review_identifier(key,v,member,'structured-node:'+str(node_index)+':field:'+key,'structured_identifier_field',label=str(k))
                # Do not emit arbitrary key names or values into evidence.
                walk(v,member,trail,depth+1)
        elif isinstance(value,list):
            for v in value:walk(v,member,trail,depth+1)
        elif isinstance(value,str):patterns(value,member,'structured-string',allow_assignments=False)
    def patterns(text,member,prefix='line',allow_assignments=True):
        def literal(start):return re.split(r'''[\s<>"'\x00]''',text[start:],maxsplit=1)[0]
        def loc(m):return prefix+':'+str(text.count('\n',0,m.start())+1)
        for offset in private_urls(text):add('HC-010',member,prefix+':'+str(text.count('\n',0,offset)+1),'private_network_url',raw_value=literal(offset))
        if allow_assignments:
            for m in re.finditer(r'''(?im)(?:^|[\s,{;])['"]?([a-z][a-z0-9_.-]{0,63})['"]?\s*[:=]\s*['"]?([^\s'"<>,;}{]{1,4096})''',text):
                key=re.sub('[^a-z0-9]','',m.group(1).lower());value=m.group(2)
                line=text[text.rfind('\n',0,m.start())+1:m.end()].lstrip()
                if not line.startswith(('#','//',';')):review_identifier(key,value,member,loc(m),'text_identifier_field')
                if debug_enabled(key,value) and not line.startswith(('#','//',';')):add('HC-010',member,loc(m),'enabled_debug_flag',raw_value={'field':key,'value':value})
                if key in KEYS and secretlike(value):add(KEYS[key],member,loc(m),'text_sensitive_field',raw_value=value)
            for m in re.finditer(r'''(?is)<string\s+name\s*=\s*['"]([^'"]{1,128})['"]\s*>([^<]{1,4096})</string>''',text):
                key=re.sub('[^a-z0-9]','',m.group(1).lower())
                review_identifier(key,m.group(2),member,loc(m),'xml_identifier_field')
                if key in KEYS and secretlike(m.group(2)):add(KEYS[key],member,loc(m),'xml_string_field',raw_value=m.group(2))
        for m in re.finditer(r'(?i)\bBearer\s+([A-Za-z0-9_.~+/-]{12,4096}=*)',text):
            if secretlike(m.group(1)):add('HC-002',member,loc(m),'bearer_literal',raw_value=m.group(0))
        for m in re.finditer(r'(?i)\bBasic\s+([A-Za-z0-9+/]{8,4096}={0,2})',text):
            try:
                value=base64.b64decode(m.group(1),validate=True).decode('utf8')
                if ':' in value and secretlike(value.split(':',1)[1]):add('HC-001',member,loc(m),'basic_base64_decoded',raw_value={'authorization':m.group(0),'decoded':value})
            except (ValueError,UnicodeError):pass
        for m in re.finditer(r'(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqps?)://([^\s:/]{1,256}):([^\s/@]{1,1024})@',text):
            if secretlike(m.group(2)):add('HC-004',member,loc(m),'connection_uri_credentials',raw_value=literal(m.start()))
        for m in ENVELOPES.finditer(text):
            validation=key_validator.validate(m.group(0),'pem')
            if validation['status'] not in ('invalid_or_unsupported','public_key','public_certificate'):
                add('HC-006',member,loc(m),'pem_private_key_material',{'key_validation':validation},raw_value=m.group(0))
    def decoded_fields(fields,member,kind):
        for key,value,line in fields:
            normalized=re.sub('[^a-z0-9]','',key.rsplit('/',1)[-1].lower())
            values=table_values.get(value.lstrip('@').lower(),[]) if value.startswith('@') else [value]
            for v in values:
                review_identifier(normalized,v,member,'aapt2-'+kind+'-line:'+str(line),'android_decoded_identifier_field',label=key)
                if debug_enabled(normalized,v):add('HC-010',member,'aapt2-'+kind+'-line:'+str(line),'enabled_debug_flag',raw_value={'field':normalized,'value':v})
                if normalized in KEYS and secretlike(v):add(KEYS[normalized],member,'aapt2-'+kind+'-line:'+str(line),'android_decoded_sensitive_field',raw_value=v)
                patterns(v,member,'aapt2-'+kind+'-line:'+str(line),allow_assignments=True)
    def dex_emit(value,key,context,rule=None):
        nonlocal dex_context
        # Symbols are labels, not secret values; bound their size and mask credential-like labels.
        dex_context={k:(safe_path(v)[:512] if isinstance(v,str) else v) for k,v in context.items()}
        location='dex:'+str(context.get('file_offset','field'))+':'+safe_path(str(context.get('field','')))[:128]
        if rule:add(rule,name,location,'dex_constant_argument',raw_value=bytes.fromhex(value) if context.get('material_encoding')=='hex' else value)
        if key:
            normalized=re.sub('[^a-z0-9]','',key.lower())
            review_identifier(normalized,value,name,location,'dex_identifier_field')
            if normalized in KEYS and secretlike(value):add(KEYS[normalized],name,location,'dex_sensitive_field',raw_value=value)
        patterns(value,name,location,allow_assignments=True)
        dex_context={}
    def sqlite_emit(value,context):
        nonlocal dex_context
        dex_context=context
        try:walk(value,name)
        finally:dex_context={}
    def native_emit(value,context):
        nonlocal dex_context
        dex_context={k:(safe_path(v)[:512] if isinstance(v,str) else v) for k,v in context.items()}
        parents=[c for c in bundle_roots if name.startswith(c['path']+'/')]
        component=max(parents,key=lambda c:len(c['path'])) if parents else None
        if component:dex_context.update(component_path=safe_path(component['path']),component_role=component['role'])
        patterns(value,name,('elf-offset:' if context.get('usage','').startswith('elf_') else 'macho-offset:')+str(context['file_offset']))
        dex_context={}
    # Verify imported byte identity before trusting cached inventory or reporting findings.
    with open(folder/'package.bin','rb') as source:
        h=hashlib.sha256()
        while True:
            if time.monotonic()>deadline:raise ValueError('scan_timeout')
            data=source.read(1024*1024)
            if not data:break
            h.update(data)
        if h.hexdigest()!=req['artifact_sha256'] or inv['sha256']!=req['artifact_sha256']:raise ValueError('artifact_digest_mismatch')
        source.seek(0)
        with zipfile.ZipFile(source) as z, ExitStack() as nested_stack:
            expected={e['path']:e for e in inv['entries']}
            if len(z.infolist())!=len(expected):raise ValueError('inventory_mismatch')
            z=nested_stack.enter_context(NestedArchiveView(z,expected,deadline))
            archive_meta=z.metadata;archive_labels=z.labels;archive_prefixes=z.prefixes;nested_stats=z.stats
            if inv['platform']=='ios':
                for entry in z.infolist():
                    if not entry.filename.endswith('/Info.plist'):continue
                    parent=entry.filename.rsplit('/',1)[0]
                    suffix=Path(parent).suffix.lower()
                    if suffix not in ('.app','.appex','.framework'):continue
                    ios['component_count']+=1
                    if len(ios['components'])>=128:ios['components_truncated']=True;continue
                    component={'path':parent,'role':{'.app':'app','.appex':'extension','.framework':'framework'}[suffix],'role_basis':'bundle_path_and_info_plist','status':'metadata_only'}
                    bundle_roots.append(component)
                    try:
                        if entry.file_size>MAX_FILE:raise ValueError('info_plist_size_limit')
                        content=z.read(entry)
                        if hashlib.sha256(content).hexdigest()!=expected[entry.filename]['sha256']:raise ValueError('member_digest_mismatch')
                        plist=plistlib.loads(content)
                        exe=plist.get('CFBundleExecutable') if isinstance(plist,dict) else None
                        if not isinstance(exe,str) or not exe or '/' in exe or '\\' in exe or exe in ('.','..'):raise ValueError('executable_not_declared_or_invalid')
                        executable=parent+'/'+exe;component['executable_path']=executable
                        if executable not in expected:raise ValueError('declared_executable_missing')
                        declared[executable]=component
                    except (ValueError,plistlib.InvalidFileException) as e:
                        if str(e)=='member_digest_mismatch':raise
                        component.update(status='partial',reason=str(e) if str(e) in ('info_plist_size_limit','executable_not_declared_or_invalid','declared_executable_missing') else 'info_plist_parse_failed')
                    ios['components'].append({k:safe_path(v) if isinstance(v,str) else v for k,v in component.items()})
            for info in sorted(z.infolist(),key=lambda i:i.filename!='resources.arsc'):
                if time.monotonic()>deadline:raise ValueError('scan_timeout')
                if info.is_dir() or info.filename in z.container_keys:continue
                name=info.filename; extension=Path(name).suffix.lower()
                def skip(reason):
                    nonlocal skipped_count
                    skipped_count+=1;skip_counts[reason]=skip_counts.get(reason,0)+1
                    if len(skipped)<100:skipped.append({'path':safe_path(name),'reason':reason})
                if name in archive_meta and extension=='.arsc':skip('nested_android_binary_resources_not_decoded');continue
                if inv['platform']=='android':
                    with z.open(info) as member:magic=member.read(4)
                    if magic==b'\x7fELF' or extension=='.so':
                        elf['files_total']+=1
                        if len(elf['files'])>=128:elf['files_omitted']+=1;continue
                        record={'path':safe_path(name),'status':'blocked'};elf['files'].append(record)
                        try:
                            if info.file_size>MAX_ELF or elf['bytes_read']+info.file_size>256*1024*1024:raise ValueError('elf_input_limit')
                            data=z.read(info);elf['bytes_read']+=len(data);member_hash=hashlib.sha256(data).hexdigest()
                            if member_hash!=expected[name]['sha256']:raise ValueError('member_digest_mismatch')
                            record['member_sha256']=member_hash;record.update(inspect_elf(data,native_emit,deadline))
                            record['jni_exports']=[{**j,'name':safe_path(j['name'])} for j in record['jni_exports']]
                            parts=archive_meta.get(name,{}).get('member_path',name).split('/');record['packaged_abi']=parts[1] if len(parts)>2 and parts[0]=='lib' else None
                            record['abi_matches_path']=record['packaged_abi']==record['architecture'] if record['packaged_abi'] else None
                            elf['files_checked']+=1;elf['strings_checked']+=record['strings_checked']
                        except ValueError as e:
                            if str(e)=='member_digest_mismatch':raise
                            record['reason']=str(e);elf['failures'][str(e)]=elf['failures'].get(str(e),0)+1
                        finally:dex_context={}
                        continue
                if inv['platform']=='ios':
                    with z.open(info) as member:magic=member.read(4)
                    if is_macho(magic) or name in declared:
                        ios['files_total']+=1
                        if len(ios['files'])>=128:ios['files_omitted']+=1;continue
                        record={'path':safe_path(name),'declared_executable':name in declared,'status':'blocked'};ios['files'].append(record)
                        try:
                            if not is_macho(magic):raise ValueError('declared_executable_not_macho')
                            if info.file_size>MAX_NATIVE_FILE or ios['bytes_read']+info.file_size>MAX_NATIVE_TOTAL:raise ValueError('macho_input_limit')
                            if ios['slices_checked']+ios['slices_blocked']>=128:raise ValueError('macho_total_slice_limit')
                            data=z.read(info);ios['bytes_read']+=len(data);member_hash=hashlib.sha256(data).hexdigest()
                            if member_hash!=expected[name]['sha256']:raise ValueError('member_digest_mismatch')
                            record['member_sha256']=member_hash
                            record['slices']=inspect_macho(data,native_emit,deadline,decode_limit)
                            blocked=sum(s['status']=='blocked' for s in record['slices'])
                            ios['slices_blocked']+=blocked;ios['slices_checked']+=len(record['slices'])-blocked
                            ios['strings_checked']+=sum(s.get('strings_checked',0) for s in record['slices'])
                            record['status']='blocked' if blocked==len(record['slices']) else 'partial'
                            ios['files_checked']+=1
                        except ValueError as e:
                            reason=str(e)
                            if reason=='member_digest_mismatch':raise
                            record['reason']=reason;ios['failures'][reason]=ios['failures'].get(reason,0)+1
                        finally:dex_context={}
                        continue
                if inv['platform']=='android' and extension=='.dex':
                    dex['files_total']+=1
                    record={'path':safe_path(name),'status':'partial'}
                    dex['files'].append(record)
                    try:
                        if info.file_size>MAX_DEX or dex['bytes_read']+info.file_size>128*1024*1024:raise ValueError('dex_input_limit')
                        data=z.read(info);dex['bytes_read']+=len(data);member_hash=hashlib.sha256(data).hexdigest()
                        if member_hash!=expected.get(name,{}).get('sha256'):raise ValueError('member_digest_mismatch')
                        scan_dex(data,dex_tool,deadline,dex_emit,dex)
                        dex['files_checked']+=1;record['status']='constants_pass_finished'
                    except ValueError as e:
                        reason=str(e)
                        if reason=='member_digest_mismatch':raise
                        dex['failures'][reason]=dex['failures'].get(reason,0)+1;record['reason']=reason
                    finally:dex_context={}
                    continue
                with z.open(info) as member:sqlite_magic=member.read(16)==b'SQLite format 3\x00'
                if not sqlite_magic and extension not in TEXT_EXT and Path(name).name!='.env' and not (inv['platform']=='android' and name=='resources.arsc'):skip('unsupported_file_type');continue
                if info.file_size>MAX_FILE:skip('resource_size_limit');continue
                if total+info.file_size>MAX_TOTAL:skip('total_resource_budget');continue
                if info.flag_bits&1 or info.compress_type not in (0,8):skip('unsupported_zip_entry');continue
                with z.open(info) as f:data=f.read(MAX_FILE+1)
                if len(data)>MAX_FILE:raise ValueError('actual_resource_size_limit')
                total+=len(data);member_hash=hashlib.sha256(data).hexdigest()
                if member_hash!=expected.get(name,{}).get('sha256'):raise ValueError('member_digest_mismatch')
                try:
                    binary_xml=inv['platform']=='android' and extension=='.xml' and data[:4]==b'\x03\x00\x08\x00'
                    resource_table=inv['platform']=='android' and name=='resources.arsc'
                    if binary_xml or resource_table:
                        if name in archive_meta:skip('nested_android_binary_resources_not_decoded');continue
                        try:
                            if android['decoded_bytes']>=MAX_TOTAL:raise ValueError('android_decode_total_limit')
                            text=dump(tool,folder/'package.bin','resources' if resource_table else 'xmltree',deadline,None if resource_table else name)
                            android['decoded_bytes']+=len(text.encode('utf8'))
                            if android['decoded_bytes']>MAX_TOTAL:raise ValueError('android_decode_total_limit')
                            if resource_table:
                                rows=table_rows(text)
                                for rid,key,value,line in rows:table_values.setdefault(rid.lower(),[]).append(value)
                                decoded_fields([(key,value,line) for rid,key,value,line in rows],name,'resources')
                                android['resource_tables_decoded']+=1
                            else:
                                decoded_fields(xml_fields(text),name,'xmltree')
                                # Inspect text nodes and literals as well as named attributes.
                                patterns(text,name,'aapt2-xmltree-line',allow_assignments=False)
                                android['binary_xml_decoded']+=1
                        except ValueError as e:
                            reason=str(e);android['failures'][reason]=android['failures'].get(reason,0)+1
                            skip(reason);continue
                    elif data.startswith(b'SQLite format 3\x00') or extension in ('.db','.sqlite','.sqlite3'):
                        if len(sqlite_files)>=100:skip('sqlite_file_count_limit');continue
                        record={'path':safe_path(name),'member_sha256':member_hash,'status':'blocked'}
                        sqlite_files.append(record)
                        try:record.update(inspect_sqlite(data,sqlite_emit,deadline))
                        except ValueError as e:
                            record['reason']=str(e) if str(e) in ('sqlite_header_invalid_or_encrypted','sqlite_parse_or_query_failed','sqlite_deadline') else 'sqlite_parse_failed'
                            skip(record['reason']);continue
                    elif (extension in ('.der','.p8','.pk8') and not data.lstrip().startswith(b'-----')) or extension=='.key' and b'\x00' in data and not data.lstrip().startswith(b'-----'):
                        validation=key_validator.validate(data,'der')
                        if validation['status'] in ('parsed_private_key','encrypted_container_requires_passphrase'):add('HC-006',name,'binary-key:0','der_private_key_material',{'key_validation':validation},raw_value=data)
                        elif validation['status'] not in ('invalid_or_unsupported','public_key','public_certificate'):skip(validation['status']);continue
                    elif extension=='.plist':
                        parsed=plistlib.loads(data);walk(parsed,name)
                    else:
                        text=data.decode('utf-16') if data.startswith((b'\xff\xfe',b'\xfe\xff')) else data.decode('utf-8-sig')
                        if '\x00' in text:skip('binary_resource_not_decoded');continue
                        if extension=='.json':walk(json.loads(text),name)
                        else:patterns(text,name)
                    checked_count+=1
                    if len(checked)<100:checked.append(safe_path(name))
                except (ValueError,UnicodeError,RecursionError,plistlib.InvalidFileException):skip('resource_parse_failed')
    for failure in nested_stats.get('failures',[]):failure['path']=safe_path(failure['path'])
    for component in ios['components']:
        binary=next((f for f in ios['files'] if f['path']==safe_path(component.get('executable_path',''))),None)
        if binary:component['binary_status']=binary['status']
    incomplete=nested_stats.get('status')=='partial' or bool(key_validator.stats['unresolved'] or key_validator.stats['budget_skipped']) or bool(sqlite_files) or bool(skipped_count) or truncated or bool(dex['files_total']) or bool(ios['component_count']) or bool(ios['files_total']) or bool(elf['files_total'])
    return {'private_evidence':private.save(),'nested_archive_scan':nested_stats,'key_material_scan':key_validator.stats,'sqlite_scan':{'status':'partial' if sqlite_files else 'not_run','files':sqlite_files},'client_identifier_review':{'status':'partial','misuse_assessment':'not_evaluated','item_count':len(identifier_items),'items_truncated':identifier_truncated,'items':identifier_items},'android_native_scan':elf,'ios_native_scan':ios,'dex_scan':dex,'findings':findings,'finding_count':len(findings),'resource_scan':{'android_resources':android,'checked_files_sample':checked,'skipped_files_sample':skipped,'checked_count':checked_count,'skipped_count':skipped_count,'skip_reason_counts':skip_counts,'file_samples_truncated':checked_count>100 or skipped_count>100,'bytes_read':total,'findings_truncated':truncated,'source_complete':not incomplete},
      'rules':[{'rule_id':'HC-'+str(i).zfill(3),'status':('partial' if incomplete or i in (10,11,12) else 'complete') if 'HC-'+str(i).zfill(3) in RULES and (i not in (5,7,8,9) or dex['methods_checked']) else 'not_run','scope':'android_dex_named_auth_entry_comparison_branch' if i==9 else 'android_dex_PBEKeySpec_constant_salt_only' if i==8 else 'private_ip_url_and_explicit_debug_flags' if i==10 else 'same_object_json_plist_sqlite_contact_records' if i==11 else 'client_identifier_inventory_only_misuse_not_evaluated' if i==12 else 'supported_resource_dex_and_macho_literal_patterns','reason':'inventory_only_misuse_not_evaluated' if i==12 else 'candidate_detection_not_usage_validation' if 'HC-'+str(i).zfill(3) in RULES and (i not in (5,7,8,9) or dex['methods_checked']) else 'detector_not_run_or_not_implemented'} for i in range(1,13)],
      'coverage':{**inv['coverage'],'nested_archive_contents':nested_stats.get('status','not_run'),'resource_candidate_detection':'partial' if incomplete else 'complete','hardcoding_detection':'partial','native_analysis':('partial' if ios['slices_checked'] or elf['files_checked'] else ('blocked' if ios['files_total'] or elf['files_total'] else 'not_run')),'dex_analysis':'partial' if dex['strings_checked'] or dex['files_checked'] else ('not_run' if inv['platform']=='android' else 'not_applicable'),'resource_decoding':('partial' if android['failures'] or skipped_count else 'complete') if android['binary_xml_decoded'] or android['resource_tables_decoded'] else 'not_run'},
      'limitations':['Nested ZIP/JAR/APK/IPA/AAR recursion is bounded to two containers, 32 archive attempts, 5000 nested entries, 8 MiB per entry, 64 MiB aggregate discovery reads, ratio 200 and 10 seconds discovery time. Nested binary Android resources and Java class bytecode are not decoded; nested DEX candidates have no independent JADX verification. Archive paths and digests accompany evidence.','SQLite reads only standalone unencrypted main files with ordinary tables: at most 64 schema entries, 128 columns, 1000 rows per database and 4096 UTF-8 bytes per text cell, within resource file/total budgets. Views, virtual/generated tables, BLOB cells, WAL/journals, encrypted databases and deleted records are not analyzed; row ordinals are query positions, not stable primary keys.','Static return propagation only summarizes same-DEX static no-argument String literal leaves and up to four exact forwarding wrappers, at most 10000 summaries; cycles, missing targets, extra operations, parameter, cross-DEX, branch and general interprocedural analysis remain unsupported.','String byte constructors support strict UTF-8 with known charset and valid slices, up to 8192 source bytes; malformed replacement semantics, other charsets and general object/cross-method flow are unsupported.','Arrays.copyOf/copyOfRange byte overloads propagate known constants only, with at most 8192 input/output bytes and 8 copy steps; zero-padding is recorded, unknown sources and invalid bounds are unresolved.','Explicit String.getBytes supports only known UTF-8/utf8 names, StandardCharsets.UTF_8 and Charset.forName for those names, bounded to 8192 input characters and output bytes; other charsets, malformed text and unknown sources remain unresolved.','SecretKeySpec/IvParameterSpec detection requires exact supported constructors, nonempty known byte material and valid known slices; SecretKeySpec also requires a known string algorithm. Provider validity and runtime use are not verified.','HC-007 GCM detection covers constant bytes in exact GCMParameterSpec constructors, including known valid array slices; encryption mode, key identity, nonce reuse and provider acceptance are not verified.','iOS Mach-O literal decoding is heuristic, one layer of strict Base64 or explicit hex, a configured per-slice attempt budget (default 2000, maximum 20000) and 8192 input characters; it does not establish a decoding call or plaintext reference.','DEX Base64 restoration is limited to java.util.Base64.getDecoder().decode(String) and android.util.Base64.decode(String,int) with flags 0/2, one layer and at most 8192 input characters; URL-safe/MIME/byte-array overloads and arbitrary decoding remain unsupported.','HC-009 only checks selected authentication-named Android DEX methods with one forward conditional, entry-prefix literal/parameter String.equals and direct result branch. Method names are hints, not security-purpose proof; iOS, other APIs, obfuscation, integer codes, return-only checks and general control flow are unsupported.','HC-012 is a separate field-context inventory, capped at 100 items; no permissions, application restrictions, provider ownership or misuse validation. It is not included in finding_count or compare_scans candidate groups.','HC-011 only checks selected explicit name and email/international-phone fields in the same JSON/plist object or SQLite table row; no identity authenticity, arbitrary business data, encrypted databases, CSV or code-level record reconstruction.','HC-010 only checks literal private IPv4/ULA URLs and selected enabled debug fields; not release provenance, effective settings, reachability, arbitrary debug data or runtime behavior.','HC-008 only detects nonempty constant salt in exact Android PBEKeySpec constructors with known positive numeric parameters in supported straight-line code. Salt secrecy, actual KDF use, parameter strength, other APIs and iOS are not assessed.','Android ELF checks allocated non-executable data literals, bounded one-layer Base64/hex decoding and visible JNI exports only. JNI dynamic registration, cross-language flow, arbitrary encoding and Flutter Dart AOT semantics are not resolved. ELF link-time addresses may differ from the REA image base.','iOS Mach-O sections are checked for literal patterns only, with per-slice encryption and format gaps. Encrypted slices are blocked without decryption; a non-encrypted marker does not prove unpacked code. Native instructions, Swift small strings, Objective-C object graphs, runtime use are not fully analyzed; nested archives are handled only within the separately reported ZIP recursion scope. DEX standard string pools, static string fields and supported straight-line instructions are scanned when possible. Branching methods skip value propagation; reference chains, cross-method flow, reflection, arbitrary decoding and dynamic loading are not resolved. The basic worker does not perform REA verification; the MCP orchestrator can append bounded Android method corroboration for static-deep requests. Android AAPT2 resource strings and XML fields are checked when available; reference chains, styled strings and code usage are not fully resolved.','No credential validity, permissions or runtime use was checked.','Private-key parsing uses Node crypto/OpenSSL for supported PEM/DER private formats, at most 32 attempts, 128 KiB per key and 3 seconds per parse. Supported unencrypted single-key OpenSSH Ed25519/RSA/ECDSA material is also parsed; encrypted and unsupported envelopes remain unresolved; no passphrases, key use, ownership or revocation are verified; PKCS12/JKS, unsupported OpenSSH key types and arbitrary containers are unsupported.','Pattern absence is not proof that no hardcoded secret exists.','This worker performs the bounded basic pass; any added REA corroboration is reported separately in deep_scan.']}
try:
    print(json.dumps({'ok':True,'result':run(json.load(sys.stdin))},ensure_ascii=True))
except Exception as e:
    code=str(e)
    allowed={'artifact_symlink','artifact_digest_mismatch','member_digest_mismatch','inventory_mismatch','scan_timeout','actual_resource_size_limit'}
    print(json.dumps({'ok':False,'error':code if code in allowed else 'resource_scan_failed'}))

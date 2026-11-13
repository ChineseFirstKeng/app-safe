"""Bounded AAPT2 adapter. Decoded secrets remain in memory, never in diagnostics."""
import os, re, shutil, subprocess, selectors, time
from pathlib import Path

LIMIT=8*1024*1024

def find_aapt2():
    explicit=os.environ.get('APP_SECURITY_AAPT2')
    if explicit is not None:
        return explicit if os.path.isabs(explicit) and os.path.isfile(explicit) and os.access(explicit,os.X_OK) else None
    found=shutil.which('aapt2')
    if found:return found
    roots=[os.environ.get('ANDROID_SDK_ROOT'),os.environ.get('ANDROID_HOME'),str(Path.home()/'Library/Android/sdk'),str(Path.home()/'Android/Sdk')]
    for root in roots:
        if not root:continue
        candidates=list((Path(root)/'build-tools').glob('*/aapt2'))
        for p in sorted(candidates,key=lambda p:tuple(int(n) for n in re.findall(r'\d+',p.parent.name)),reverse=True):
            if p.is_file() and os.access(p,os.X_OK):return str(p)
    return None

def dump(tool,package,kind,deadline,member=None):
    if not tool:raise ValueError('android_decoder_unavailable')
    args=[tool,'dump',kind,str(package)]
    if member is not None:args+=['--file',member]
    end=min(deadline,time.monotonic()+5)
    chunks=[];size=0
    try:
        with subprocess.Popen(args,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL) as proc:
            try:
                with selectors.DefaultSelector() as selector:
                    selector.register(proc.stdout,selectors.EVENT_READ)
                    while True:
                        if time.monotonic()>=end:raise ValueError('android_decode_timeout')
                        if not selector.select(min(.1,max(0,end-time.monotonic()))):continue
                        chunk=os.read(proc.stdout.fileno(),65536)
                        if not chunk:break
                        size+=len(chunk)
                        if size>LIMIT:raise ValueError('android_decode_output_limit')
                        chunks.append(chunk)
                if proc.wait(timeout=max(.01,end-time.monotonic())):raise ValueError('android_decode_failed')
            finally:
                if proc.poll() is None:proc.kill();proc.wait()
    except (OSError,subprocess.TimeoutExpired):raise ValueError('android_decode_failed')
    try:return b''.join(chunks).decode('utf8')
    except UnicodeError:raise ValueError('android_decode_failed')

QUOTED=re.compile(r'"((?:\\.|[^"\\])*)"')
def table_rows(text):
    """Return scalar strings by resource ID, with dump line evidence. No reference evaluation."""
    rows=[];rid=None;key=None
    for line_no,line in enumerate(text.splitlines(),1):
        match=re.match(r'\s*resource (0x[0-9a-fA-F]+) (\S+)',line)
        if match:rid,key=match.groups();continue
        if rid:
            # Scalar strings and quoted array/plural values. References are not strings.
            for value in QUOTED.findall(line):rows.append((rid,key,value,line_no))
    return rows

def xml_fields(text):
    """Fields and name/value pairs within one XML element; positions are dump lines."""
    fields=[];group=[]
    def flush():
        names=[v for k,v,n in group if k=='name']
        for k,v,n in group:
            if k in ('value','resource') and names:fields.append((names[0],v,n))
    for line_no,line in enumerate(text.splitlines(),1):
        if re.match(r'\s*E:',line):flush();group=[]
        match=re.match(r'\s*A: (.+?)(?:\(0x[0-9a-fA-F]+\))?=(.*)',line)
        if not match:continue
        name,value=match.groups();name=name.rsplit(':',1)[-1]
        quoted=QUOTED.match(value)
        if quoted:value=quoted.group(1)
        else:value=value.split(' ',1)[0]
        fields.append((name,value,line_no));group.append((name,value,line_no))
    flush()
    return fields

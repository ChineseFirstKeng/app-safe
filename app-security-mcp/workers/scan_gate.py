"""POSIX kernel admission locks survive exec and disappear with the actual worker.
Never unlink lock files: unlinking would let another inode bypass a held lock.
"""
import json
import os
import stat
import sys
import tempfile
from pathlib import Path

def main():
    request=json.load(sys.stdin)
    try:import fcntl
    except ImportError:raise ValueError('global_scan_gate_unsupported')
    root=Path(request['storage_root'])/'_capacity'
    root.mkdir(mode=0o700,parents=True,exist_ok=True)
    if root.is_symlink() or not root.is_dir() or root.stat().st_uid!=os.getuid():raise ValueError('invalid_capacity_storage')
    held=None
    for index in range(2):
        fd=os.open(root/('scan-'+str(index)+'.lock'),os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
        meta=os.fstat(fd)
        if not stat.S_ISREG(meta.st_mode) or meta.st_uid!=os.getuid():os.close(fd);raise ValueError('invalid_capacity_storage')
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:os.close(fd);continue
        held=fd;break
    if held is None:raise ValueError('global_scan_capacity_exceeded')
    # Keep this exact file description open in scan_resources.py across exec.
    os.set_inheritable(held,True)
    source=tempfile.TemporaryFile(mode='w+b')
    source.write(json.dumps(request).encode('utf8'));source.flush();source.seek(0)
    os.dup2(source.fileno(),0,inheritable=True)
    os.execv(sys.executable,[sys.executable,sys.argv[1]])
try:main()
except Exception as error:
    reason=str(error)
    allowed={'global_scan_capacity_exceeded','global_scan_gate_unsupported','invalid_capacity_storage'}
    print(json.dumps({'ok':False,'error':reason if reason in allowed else 'global_scan_gate_failed'}))

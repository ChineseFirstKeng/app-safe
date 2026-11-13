"""Bounded configuration clues, not credential or exploitability validation."""
import ipaddress,re
from urllib.parse import urlsplit
NETWORKS=tuple(ipaddress.ip_network(n) for n in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16','fc00::/7'))
DEBUG_KEYS={'debug','debugmode','enabledebug','debugenabled','debuggable'}
def debug_enabled(key,value):
    if key not in DEBUG_KEYS:return False
    return value is True or type(value) is int and value==1 or isinstance(value,str) and value.strip().lower() in ('true','1','yes','on')
def private_urls(text):
    # No DNS resolution, no requests, no reliance on Python's changing is_private set.
    for m in re.finditer(r'''(?i)\b(?:https?|wss?)://[^\s<>"'\x00]{1,2048}''',text):
        try:
            url=urlsplit(m[0]);host=url.hostname
            if not host or '%' in host:continue
            address=ipaddress.ip_address(host)
            if any(address.version==n.version and address in n for n in NETWORKS):yield m.start()
        except ValueError:continue

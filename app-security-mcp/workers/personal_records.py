"""Same-object contact record candidates. Never returns record values."""
import re
NAME_KEYS={'fullname','realname','contactname','customername','姓名','联系人姓名','客户姓名'}
EMAIL_KEYS={'email','emailaddress','contactemail','邮箱','电子邮箱'}
PHONE_KEYS={'phone','phonenumber','mobile','mobilenumber','联系电话','手机号'}
PLACEHOLDERS={'test','dummy','example','placeholder','redacted','unknown','null','none','姓名','测试','测试用户','张三','李四'}
def normalized(key):
    return re.sub(r'[\s_.-]','',str(key).lower())
def person_name(value):
    if not isinstance(value,str):return False
    value=value.strip()
    return 2<=len(value)<=128 and value.lower() not in PLACEHOLDERS and not re.search(r'[<>${}@:/\\\d*]',value) and any(c.isalpha() for c in value)
def email(value):
    if not isinstance(value,str) or len(value)>254:return False
    value=value.strip()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{0,63}@[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?",value):return False
    local,domain=value.rsplit('@',1);domain=domain.lower()
    if '..' in local or local.endswith('.') or local.lower() in PLACEHOLDERS:return False
    if '.' not in domain or any(not label or len(label)>63 or label.startswith('-') or label.endswith('-') for label in domain.split('.')):return False
    return not any(domain==d or domain.endswith('.'+d) for d in ('example.com','example.net','example.org','invalid','test','example','localhost'))
def phone(value):
    if not isinstance(value,str) or len(value)>40 or not re.fullmatch(r'\+[0-9 ()-]+',value.strip()):return False
    digits=re.sub(r'[ ()-]','',value.strip())[1:]
    if not re.fullmatch(r'[1-9][0-9]{7,14}',digits):return False
    if len(set(digits[-7:]))==1 or digits.endswith(('1234567890','0123456789')):return False
    if re.fullmatch(r'1[0-9]{3}55501[0-9]{2}',digits):return False
    return True

def contact_categories(record):
    if not isinstance(record,dict):return []
    # Do not merge parent/child objects, list entries or similarly named fields.
    entries=[(normalized(k),v) for k,v in record.items()]
    if not any(k in NAME_KEYS and person_name(v) for k,v in entries):return []
    kinds=[]
    if any(k in EMAIL_KEYS and email(v) for k,v in entries):kinds.append('email')
    if any(k in PHONE_KEYS and phone(v) for k,v in entries):kinds.append('international_phone_shape')
    return ['person_name']+kinds if kinds else []

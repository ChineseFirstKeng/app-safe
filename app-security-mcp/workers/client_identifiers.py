"""Field-context inventory, not API permission or credential validation."""
import re
FIELDS={
 'clientid':'client_identifier','oauthclientid':'client_identifier','googleclientid':'client_identifier',
 'apikey':'api_key_role_unknown','googleapikey':'api_key_role_unknown','firebaseapikey':'api_key_role_unknown',
 'androidapikey':'api_key_role_unknown','iosapikey':'api_key_role_unknown',
}
PLACEHOLDERS={'null','none','undefined','example','placeholder','redacted','test','dummy','changeme','your_api_key','your_client_id'}
def identifier_kind(key,value):
    if key not in FIELDS or not isinstance(value,str):return None
    value=value.strip()
    if not 1<=len(value)<=4096 or value.lower() in PLACEHOLDERS:return None
    if value.startswith('@') or re.fullmatch(r'\$\{[^}]+\}|<[^>]+>|\*+|x+',value,re.I):return None
    return FIELDS[key]

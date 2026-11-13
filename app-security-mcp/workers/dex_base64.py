"""Strict bounded subset of standard Base64 decoding; never executes target code."""
import base64,binascii,re

def decode_literal(text,android=False):
    if not isinstance(text,str) or not 1<=len(text)<=8192:return None
    if android:text=re.sub(r'[ \t\r\n]','',text)
    if not re.fullmatch(r'[A-Za-z0-9+/]*={0,2}',text) or not text:return None
    # Unpadded last units of 2/3 chars are accepted by supported decoders.
    if '=' in text:
        if len(text)%4:return None
    elif len(text)%4==1:return None
    else:text+='='*((-len(text))%4)
    try:return base64.b64decode(text,validate=True)
    except (ValueError,binascii.Error):return None

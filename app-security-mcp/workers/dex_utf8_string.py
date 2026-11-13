"""Strict bounded UTF-8 restoration; malformed replacement semantics are unsupported."""
def restore_utf8(data,offset,length):
    if not isinstance(data,bytes) or len(data)>8192:return None
    if type(offset) is not int or type(length) is not int or offset<0 or length<0 or offset+length>len(data):return None
    try:return data[offset:offset+length].decode('utf8')
    except UnicodeError:return None

"""Bounded Java byte-array copy semantics; never execute target code."""
def copy_bytes(source,start,end):
    if not isinstance(source,bytes) or len(source)>8192:return None
    if type(start) is not int or type(end) is not int:return None
    if not 0<=start<=len(source) or not 0<=end-start<=8192:return None
    copied=source[start:end]
    padding=end-start-len(copied)
    return copied+b'\0'*padding,padding

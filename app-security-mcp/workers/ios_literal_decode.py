"""Heuristic one-layer literal restoration, not evidence of a decoding call."""
import re,base64,binascii
class LiteralDecoder:
    def __init__(self,attempt_limit=2000):
        if type(attempt_limit) is not int or not 1<=attempt_limit<=20000:raise ValueError('invalid_ios_decode_attempt_limit')
        self.stats={'attempt_limit':attempt_limit,'attempts':0,'decoded':0,'rejected':0,'skipped_budget':0,'skipped_size':0}
    def decode(self,text):
        candidate=text.strip();kind=None
        if candidate.startswith('base64:'):candidate=candidate[7:];kind='base64'
        elif candidate.startswith('hex:'):candidate=candidate[4:];kind='hex'
        elif 24<=len(candidate)<=8192 and re.fullmatch(r'[A-Za-z0-9+/]+={0,2}',candidate) and len(candidate)%4==0:kind='base64'
        if kind is None:return None
        if not 16<=len(candidate)<=8192:self.stats['skipped_size']+=1;return None
        if self.stats['attempts']>=self.stats['attempt_limit']:self.stats['skipped_budget']+=1;return None
        self.stats['attempts']+=1
        try:
            if kind=='hex' and not re.fullmatch(r'(?:[0-9a-fA-F]{2})+',candidate):raise ValueError()
            value=(base64.b64decode(candidate,validate=True) if kind=='base64' else bytes.fromhex(candidate)).decode('utf8')
            if not value.isprintable():raise ValueError()
        except (ValueError,UnicodeError,binascii.Error):self.stats['rejected']+=1;return None
        self.stats['decoded']+=1
        return value,kind+'_one_layer'

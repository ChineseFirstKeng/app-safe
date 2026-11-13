"""Bounded static ()String leaf and exact forwarding-wrapper summaries."""
import re

MAX_WRAPPERS=4

def summarize(instructions,pool,klass,name,proto,is_static):
    if not is_static or proto!='()Ljava/lang/String;' or not klass or not name or name.startswith('<'):return None
    ops=[(off,pc,op) for off,pc,op in instructions if op!='nop']
    key=klass+'.'+name+':'+proto
    provenance={'transform':'static_constant_string_return','callee_class_descriptor':klass,'callee_method':name,'callee_prototype':proto}
    if len(ops)==2:
        m=re.fullmatch(r'const-string(?:/jumbo)? v(\d+), .* // string@([0-9a-f]+)',ops[0][2])
        if not m or ops[1][2]!='return-object v'+m[1]:return None
        index=int(m[2],16)
        if index>=len(pool) or len(pool[index][0])>8192:return None
        provenance.update(callee_literal_file_offset=ops[0][0],callee_return_file_offset=ops[1][0])
        return key,{'kind':'method_return','value':pool[index][0],'provenance':provenance}
    if len(ops)==3:
        call=re.fullmatch(r'invoke-static(?:/range)? \{\}, (L[^ ]+;\.[^ :]+:\(\)Ljava/lang/String;) // method@[0-9a-f]+',ops[0][2])
        move=re.fullmatch(r'move-result-object v(\d+)',ops[1][2])
        if not call or not move or ops[2][2]!='return-object v'+move[1]:return None
        provenance.update(callee_invoke_file_offset=ops[0][0],callee_return_file_offset=ops[2][0])
        return key,{'kind':'method_wrapper','target':call[1],'provenance':provenance}
    return None

def resolve_summaries(summaries):
    result={};unresolved=0
    for key,item in summaries.items():
        current=key;seen=set();chain=[];leaf=None
        while current not in seen:
            seen.add(current);node=summaries.get(current)
            if not node:break
            chain.append(dict(node['provenance']))
            if node['kind']=='method_return':leaf=node;break
            if node['kind']!='method_wrapper' or len(chain)>MAX_WRAPPERS:break
            current=node['target']
        if leaf is None:
            if item is not None:unresolved+=1
            result[key]=None;continue
        provenance=dict(item['provenance'])
        provenance.update(return_chain=chain,wrapper_depth=len(chain)-1)
        result[key]={'kind':'method_return','value':leaf['value'],'provenance':provenance}
    return result,unresolved

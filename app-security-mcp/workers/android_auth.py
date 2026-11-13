"""Conservative entry-prefix string comparison -> conditional branch evidence."""
import re

def inspect_guard(instructions,pool,base,parameter_registers,emit):
    name=re.sub('_','',base.get('method') or '').lower()
    if not re.fullmatch(r'(check|verify|validate|authenticate)(password|pin|otp|passcode|verificationcode)',name):return
    # One forward conditional only: no loops, joins into the prefix, switches or handlers.
    branches=[(i,pc,op) for i,(_,pc,op) in enumerate(instructions) if op.startswith('if-')]
    if len(branches)!=1 or any(op.startswith(('goto','packed-switch','sparse-switch','move-exception')) for _,_,op in instructions):return
    branch_index,branch_pc,branch=branches[0]
    bm=re.fullmatch(r'if-(?:eqz|nez) v(\d+), ([0-9a-f]+) //.*',branch)
    if not bm:return
    target=int(bm[2],16)
    if target<=branch_pc or target not in {pc for _,pc,_ in instructions}:return
    regs={r:('parameter',None) for r in parameter_registers};pending=None
    for off,pc,op in instructions[:branch_index]:
        opcode=op.split(' ',1)[0];operands=op[len(opcode):].strip();previous=pending;pending=None
        m=re.fullmatch(r'v(\d+), .* // string@([0-9a-f]+)',operands)
        if opcode in ('const-string','const-string/jumbo') and m:
            index=int(m[2],16)
            if index>=len(pool):return
            literal=pool[index][0]
            if not 1<=len(literal)<=4096:return
            regs[int(m[1])]=('literal',index);continue
        if opcode in ('move-object','move-object/from16','move-object/16'):
            m=re.fullmatch(r'v(\d+), v(\d+)',operands)
            if not m:return
            regs[int(m[1])]=regs.get(int(m[2]));continue
        if opcode=='move-result':
            m=re.fullmatch(r'v(\d+)',operands)
            if not m or previous is None:return
            regs[int(m[1])]=previous;continue
        if opcode in ('invoke-virtual','invoke-virtual/range'):
            m=re.fullmatch(r'\{([^}]*)\}, Ljava/lang/String;\.equals:\(Ljava/lang/Object;\)Z // method@[0-9a-f]+',operands)
            if not m:return
            rr=[int(r) for r in re.findall(r'v(\d+)',m[1])]
            if '..' in m[1]:
                if len(rr)!=2 or rr[1]-rr[0]!=1:return
                rr=list(range(rr[0],rr[1]+1))
            if len(rr)!=2:return
            values=[regs.get(r) for r in rr]
            if any(v is None for v in values) or sorted(v[0] for v in values)!=['literal','parameter']:return
            index=next(v[1] for v in values if v[0]=='literal')
            pending=('comparison',{'string_index':index,'comparison_file_offset':off,'comparison_code_unit_offset':pc})
            continue
        if opcode=='nop':continue
        # Unknown instructions/calls/overwrites do not preserve a guessed relation.
        return
    result=regs.get(int(bm[1]))
    if not result or result[0]!='comparison':return
    emit(pool[result[1]['string_index']][0],None,{**base,**result[1],
        'file_offset':instructions[branch_index][0],'dex_code_unit_offset':branch_pc,
        'branch_target_code_unit_offset':target,'branch_opcode':branch.split(' ',1)[0],
        'usage':'constant_string_equals_parameter_controls_branch','security_purpose':'unknown',
        'selection_basis':'authentication_method_name_hint','comparison_result_controls_branch':True},'HC-009')

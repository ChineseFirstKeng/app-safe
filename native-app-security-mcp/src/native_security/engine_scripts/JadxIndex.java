import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import com.google.gson.GsonBuilder;
import jadx.api.*;
import jadx.core.dex.nodes.*;
import jadx.core.dex.instructions.*;
import jadx.core.dex.instructions.args.*;
import jadx.api.plugins.pass.JadxPassInfo;
import jadx.api.plugins.pass.impl.OrderedJadxPassInfo;
import jadx.api.plugins.pass.types.JadxDecompilePass;

/** Bounded method identities and static using relationships for one explicit DEX. */
public class JadxIndex {
    static final int METHOD_LIMIT = 2000, CLASS_BODY_LIMIT = 24, BODY_LIMIT = 12000, EDGE_LIMIT = 12000;
    static Map<String,Object> row(Object... values) {
        Map<String,Object> result = new LinkedHashMap<>();
        for(int i=0;i<values.length;i+=2) result.put((String)values[i],values[i+1]);
        return result;
    }
    static class ValueCapture implements JadxDecompilePass {
        final Map<String,Map<String,Object>> methods=new HashMap<>();
        int calls=0,errors=0;
        public JadxPassInfo getInfo() {return new OrderedJadxPassInfo("NativeSecuritySSA","Capture bounded SSA argument origins")
            .after("SSATransform").before("MoveInlineVisitor");}
        public void init(RootNode root) {}
        public boolean visit(ClassNode cls) {return true;}
        Map<String,Object> unknown(String reason) {return row("kind","unknown","reason",reason);}
        Map<String,Object> value(MethodNode method,InsnArg arg,int depth,Set<InsnNode> active,int[] budget) {
            if(arg==null)return unknown("missing_operand");
            if(depth>10 || --budget[0]<0)return unknown("expression_budget");
            if(arg.isThis())return row("kind","receiver");
            if(arg instanceof RegisterArg) {
                RegisterArg reg=(RegisterArg)arg;
                List<RegisterArg> params=method.getArgRegs();
                for(int i=0;i<params.size();i++)if(reg.sameRegAndSVar(params.get(i)))return row("kind","parameter","index",i);
                return expression(method,reg.getAssignInsn(),depth+1,active,budget);
            }
            if(arg instanceof InsnWrapArg)return expression(method,((InsnWrapArg)arg).getWrapInsn(),depth+1,active,budget);
            if(arg instanceof LiteralArg)return row("kind","constant","value_type","literal");
            return unknown("unsupported_operand");
        }
        Map<String,Object> expression(MethodNode method,InsnNode insn,int depth,Set<InsnNode> active,int[] budget) {
            if(insn==null)return unknown("definition_missing");
            if(depth>10 || --budget[0]<0)return unknown("expression_budget");
            if(!active.add(insn))return unknown("ssa_cycle");
            try {
                String type=insn.getType().name();
                if(type.equals("CONST_STR") || type.equals("CONST") || type.equals("CONST_CLASS"))
                    return row("kind","constant","value_type",type.toLowerCase(Locale.ROOT));
                if(Set.of("MOVE","CHECK_CAST","CAST","ONE_ARG").contains(type) && insn.getArgsCount()>0)
                    return value(method,insn.getArg(0),depth+1,active,budget);
                if(type.equals("PHI") || type.equals("TERNARY")) {
                    List<Object> choices=new ArrayList<>();
                    if(insn.getArgsCount()>8)return unknown("merge_budget");
                    if(type.equals("TERNARY"))return unknown("conditional_expression");
                    for(InsnArg arg:insn.getArguments())choices.add(value(method,arg,depth+1,active,budget));
                    return row("kind","merge","choices",choices);
                }
                if(insn instanceof InvokeNode) {
                    InvokeNode invoke=(InvokeNode)insn;
                    List<Object> args=new ArrayList<>();
                    int first=invoke.getFirstArgOffset();
                    if(insn.getArgsCount()-first>16)return unknown("argument_budget");
                    for(int i=first;i<insn.getArgsCount();i++)args.add(value(method,insn.getArg(i),depth+1,active,budget));
                    return row("kind","invoke_return","target",invoke.getCallMth().getRawFullId(),
                        "site",insn.getOffset()>=0?insn.getOffset():null,"arguments",args,
                        "receiver",invoke.isStaticCall()?null:value(method,invoke.getInstanceArg(),depth+1,active,budget));
                }
                if(type.equals("NEW_INSTANCE"))return row("kind","constructed_object");
                return unknown("unsupported_"+type.toLowerCase(Locale.ROOT));
            } finally {active.remove(insn);}
        }
        public void visit(MethodNode method) {
            if(method.isNoCode() || methods.size()>=2000)return;
            try {
                List<BlockNode> blocks=method.getBasicBlocks();
                if(blocks==null)return;
                List<Map<String,Object>> invokes=new ArrayList<>();
                List<Object> returns=new ArrayList<>();
                boolean truncated=false;
                for(BlockNode block:blocks)for(InsnNode insn:block.getInstructions()) {
                    if(insn instanceof InvokeNode) {
                        if(invokes.size()>=128 || calls>=1000){truncated=true;continue;}
                        InvokeNode invoke=(InvokeNode)insn;
                        int first=invoke.getFirstArgOffset();
                        if(insn.getArgsCount()-first>16){truncated=true;continue;}
                        int[] budget={64};
                        Set<InsnNode> active=Collections.newSetFromMap(new IdentityHashMap<>());
                        List<Object> values=new ArrayList<>();
                        for(int i=first;i<insn.getArgsCount();i++)values.add(value(method,insn.getArg(i),0,active,budget));
                        MethodNode target=method.root().resolveMethod(invoke.getCallMth());
                        boolean exact=invoke.isStaticCall() || invoke.getInvokeType()==InvokeType.DIRECT || invoke.getInvokeType()==InvokeType.SUPER;
                        if(target!=null)exact |= target.getAccessFlags().isPrivate() || target.getAccessFlags().isFinal() || target.getParentClass().getAccessFlags().isFinal();
                        invokes.add(row("target",invoke.getCallMth().getRawFullId(),"site",insn.getOffset()>=0?insn.getOffset():null,
                            "site_kind","jadx_ir_offset","invoke_kind",invoke.getInvokeType().name(),"dispatch_exact",exact,
                            "arguments",values,"receiver",invoke.isStaticCall()?null:value(method,invoke.getInstanceArg(),0,active,budget)));
                        calls++;
                    } else if(insn.getType()==InsnType.RETURN && insn.getArgsCount()>0) {
                        if(returns.size()<8)returns.add(value(method,insn.getArg(0),0,Collections.newSetFromMap(new IdentityHashMap<>()),new int[]{64}));
                        else truncated=true;
                    }
                }
                methods.put(method.getMethodInfo().getRawFullId(),row("status","captured_partial","phase","after_ssa_before_move_inline",
                    "parameter_count",method.getArgRegs().size(),"invocations",invokes,"returns",returns,"truncated",truncated));
            } catch(Exception error) {errors++;methods.put(method.getMethodInfo().getRawFullId(),row("status","capture_failed"));}
        }
    }
    public static void main(String[] argv) throws Exception {
        if(argv.length != 2) throw new IllegalArgumentException("expected dex and output");
        JadxArgs args = new JadxArgs();
        args.setInputFiles(Collections.singletonList(new File(argv[0])));
        args.setThreadsCount(1);
        args.setSkipResources(true);
        args.setDeobfuscationOn(false);
        args.setInlineMethods(false);
        args.setInlineAnonymousClasses(false);
        List<Map<String,Object>> methods = new ArrayList<>(), edges = new ArrayList<>();
        int total=0, bodies=0, bodyErrors=0, omittedEdges=0;
        Set<String> bodyClasses = new HashSet<>();
        ValueCapture capture=new ValueCapture();
        try(JadxDecompiler decompiler = new JadxDecompiler(args)) {
            decompiler.addCustomPass(capture);
            decompiler.load();
            int classCount=0;
            for(JavaClass cls: decompiler.getClasses()) {
                if(classCount++ >= CLASS_BODY_LIMIT) break;
                try { cls.decompile(); bodyClasses.add(cls.getFullName()); }
                catch(Exception failure) { bodyErrors++; }
            }
            List<ClassNode> classes = new ArrayList<>(decompiler.getRoot().getClasses());
            classes.sort(Comparator.comparing(c -> c.getClassInfo().getFullName()));
            for(ClassNode cls: classes) {
                for(MethodNode method: cls.getMethods()) {
                    total++;
                    if(methods.size() >= METHOD_LIMIT) continue;
                    String id = method.getMethodInfo().getRawFullId();
                    String code = null;
                    boolean truncated = false;
                    if(bodyClasses.contains(cls.getTopParentClass().getFullName())) {
                        try {
                            code = method.getCodeStr();
                            if(code != null && code.length() > BODY_LIMIT) {code=code.substring(0,BODY_LIMIT);truncated=true;}
                            if(code != null && !code.isEmpty()) bodies++;
                        } catch(Exception failure) {bodyErrors++;}
                    }
                    methods.add(row("identity",id,"name",method.getMethodInfo().getName(),
                        "class_name",cls.getClassInfo().getFullName(),"body",code,"body_truncated",truncated,
                        "dex_code_offset",null,"instruction_count",method.getInsnsCount(),
                        "argument_flow",capture.methods.getOrDefault(id,row("status","not_captured_within_class_budget"))));
                    for(MethodNode target: method.getUsed()) {
                        if(edges.size() >= EDGE_LIMIT) {omittedEdges++;continue;}
                        edges.add(row("from",id,"to",target.getMethodInfo().getRawFullId(),"kind","static_method_use","site",null));
                    }
                    for(var target: method.getUnresolvedUsed()) {
                        if(edges.size() >= EDGE_LIMIT) {omittedEdges++;continue;}
                        edges.add(row("from",id,"to",target.getRawFullId(),"kind","unresolved_method_use","site",null));
                    }
                }
            }
            Map<String,Object> coverage = row("methods_total",total,"methods_indexed",methods.size(),"bodies_recovered",bodies,
                "body_errors",bodyErrors,"methods_omitted",Math.max(0,total-methods.size()),"edges_indexed",edges.size(),
                "edges_omitted",omittedEdges,"ssa_methods_captured",capture.methods.values().stream().filter(v -> "captured_partial".equals(v.get("status"))).count(),"ssa_invocations_captured",capture.calls,
                "ssa_capture_errors",capture.errors,"relationship_coverage","partial","source_line_coverage","unknown");
            Map<String,Object> output = row("schema","jadx-index/1","engine_version",jadx.core.Jadx.getVersion(),
                "java_version",System.getProperty("java.version"),
                "methods",methods,"edges",edges,"coverage",coverage,
                "limitations",List.of("Bounded class decompilation; missing bodies are explicit.",
                    "Using relationships are not individual invoke sites or runtime calls.",
                    "One DEX at a time; cross-DEX dispatch, reflection and JNI remain unresolved.",
                    "DEX offsets and original source lines unavailable in this adapter."));
            try(Writer writer = new OutputStreamWriter(new FileOutputStream(argv[1]),StandardCharsets.UTF_8)) {
                new GsonBuilder().serializeNulls().create().toJson(output,writer);
            }
        }
    }
}

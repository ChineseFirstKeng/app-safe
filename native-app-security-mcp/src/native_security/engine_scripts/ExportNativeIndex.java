// @category NativeAppSecurity
import ghidra.app.util.headless.HeadlessScript;
import ghidra.framework.Application;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import com.google.gson.GsonBuilder;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** Bounded static function/string index; never executes the imported program. */
public class ExportNativeIndex extends HeadlessScript {
    static final int FUNCTION_LIMIT=2000, BODY_LIMIT=12000, DECOMPILE_LIMIT=24, STRING_LIMIT=1000, EDGE_LIMIT=12000;
    Map<String,Object> row(Object... values) {
        Map<String,Object> result=new LinkedHashMap<>();
        for(int i=0;i<values.length;i+=2) result.put((String)values[i],values[i+1]);
        return result;
    }
    @Override public void run() throws Exception {
        String[] args=getScriptArgs();
        if(args.length!=2) throw new IllegalArgumentException("expected output path and export deadline");
        long deadline=Long.parseLong(args[1]);
        List<Map<String,Object>> functions=new ArrayList<>(),strings=new ArrayList<>(),edges=new ArrayList<>();
        int total=0,bodies=0,bodyErrors=0,indirect=0,unresolved=0,omittedEdges=0,stringOmitted=0;
        boolean exportBudget=false,bodyBudget=false,functionEnumerationComplete=false;
        DecompInterface decompiler=new DecompInterface();
        decompiler.openProgram(currentProgram);
        try {
            FunctionIterator iterator=currentProgram.getFunctionManager().getFunctions(true);
            while(iterator.hasNext() && !monitor.isCancelled()) {
                if(System.currentTimeMillis()>deadline-1500){exportBudget=true;break;}
                Function function=iterator.next();
                if(function.isExternal()) continue;
                total++;
                if(functions.size()>=FUNCTION_LIMIT) continue;
                String address=function.getEntryPoint().toString();
                String body=null;
                boolean truncated=false;
                int bodySeconds=(int)Math.min(3,(deadline-System.currentTimeMillis()-2500)/1000);
                if(functions.size()<DECOMPILE_LIMIT && bodySeconds>0) {
                    DecompileResults result=decompiler.decompileFunction(function,bodySeconds,monitor);
                    if(result.decompileCompleted() && result.getDecompiledFunction()!=null) {
                        body=result.getDecompiledFunction().getC();
                        if(body.length()>BODY_LIMIT){body=body.substring(0,BODY_LIMIT);truncated=true;}
                        bodies++;
                    } else bodyErrors++;
                } else if(functions.size()<DECOMPILE_LIMIT)bodyBudget=true;
                functions.add(row("identity",address,"name",function.getName(true),"address",address,
                    "body",body,"body_format","c_like","body_truncated",truncated,"file_offset",null,"is_thunk",function.isThunk()));
                InstructionIterator instructions=currentProgram.getListing().getInstructions(function.getBody(),true);
                while(instructions.hasNext()) {
                    if(System.currentTimeMillis()>deadline-1500){exportBudget=true;break;}
                    Instruction instruction=instructions.next();
                    if(!instruction.getFlowType().isCall())continue;
                    if(instruction.getFlowType().isComputed())indirect++;
                    boolean referenced=false;
                    for(Reference reference:instruction.getReferencesFrom()) {
                        if(!reference.getReferenceType().isCall())continue;
                        referenced=true;
                        if(edges.size()>=EDGE_LIMIT){omittedEdges++;continue;}
                        Function target=currentProgram.getFunctionManager().getFunctionAt(reference.getToAddress());
                        edges.add(row("from",address,"to",reference.getToAddress().toString(),
                            "target_name",target==null?null:target.getName(true),"site",instruction.getAddress().toString(),
                            "kind",reference.getReferenceType().isComputed()?"computed_call_candidate":"static_call_reference"));
                    }
                    if(!referenced) {
                        unresolved++;
                        if(edges.size()>=EDGE_LIMIT)omittedEdges++;
                        else edges.add(row("from",address,"to",null,"target_name",null,
                            "site",instruction.getAddress().toString(),"kind","call_target_unresolved"));
                    }
                }
            }
            functionEnumerationComplete=!iterator.hasNext();
            DataIterator data=currentProgram.getListing().getDefinedData(true);
            while(data.hasNext() && !monitor.isCancelled()) {
                if(System.currentTimeMillis()>deadline-1000){exportBudget=true;break;}
                Data value=data.next();
                if(!value.hasStringValue())continue;
                if(strings.size()>=STRING_LIMIT){stringOmitted++;continue;}
                String address=value.getAddress().toString();
                String text=String.valueOf(value.getValue());
                boolean truncated=text.length()>4096;
                if(truncated)text=text.substring(0,4096);
                strings.add(row("identity","string@"+address,"name","string@"+address,"address",address,"value",text,"truncated",truncated));
                ReferenceIterator refs=currentProgram.getReferenceManager().getReferencesTo(value.getAddress());
                while(refs.hasNext()) {
                    if(System.currentTimeMillis()>deadline-1000){exportBudget=true;break;}
                    Reference reference=refs.next();
                    Function owner=currentProgram.getFunctionManager().getFunctionContaining(reference.getFromAddress());
                    if(owner==null)continue;
                    if(edges.size()>=EDGE_LIMIT){omittedEdges++;continue;}
                    edges.add(row("from",owner.getEntryPoint().toString(),"to","string@"+address,
                        "site",reference.getFromAddress().toString(),"kind","static_string_reference"));
                }
            }
            Map<String,Object> coverage=row("functions_total",functionEnumerationComplete?total:null,"functions_scanned",total,"functions_indexed",functions.size(),
                "function_enumeration_complete",functionEnumerationComplete,"export_budget_exhausted",exportBudget,"body_budget_exhausted",bodyBudget,
                "functions_omitted",functionEnumerationComplete?Math.max(0,total-functions.size()):null,"bodies_recovered",bodies,"body_errors",bodyErrors,
                "strings_indexed",strings.size(),"strings_omitted",stringOmitted,"edges_indexed",edges.size(),
                "edges_omitted",omittedEdges,"computed_calls",indirect,"unresolved_calls",unresolved,"analysis_timed_out",analysisTimeoutOccurred(),
                "relationship_coverage","partial");
            Map<String,Object> output=row("schema","ghidra-index/1","engine_version",Application.getApplicationVersion(),
                "java_version",System.getProperty("java.version"),
                "language",currentProgram.getLanguageID().toString(),"functions",functions,"strings",strings,"edges",edges,
                "coverage",coverage,"limitations",List.of("Bounded functions, pseudocode and defined strings.",
                    "Computed calls and Objective-C/Swift dispatch are incomplete; no runtime calls observed.",
                    "Addresses belong to the selected slice and analysis address space; file offsets unavailable.",
                    "String references include exact recovered starts only; missing references are not absence proof."));
            try(Writer writer=new OutputStreamWriter(new FileOutputStream(args[0]),StandardCharsets.UTF_8)) {
                new GsonBuilder().serializeNulls().create().toJson(output,writer);
            }
        } finally {decompiler.dispose();}
    }
}

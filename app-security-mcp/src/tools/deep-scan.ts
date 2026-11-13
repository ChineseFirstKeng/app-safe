import { verifyDexMethod } from './dex-verification.js';

/** Bounded independent corroboration, not a general data-flow or vulnerability proof. */
export async function corroborateFindings(record: any, root: string, signal: AbortSignal,
  progress: (summary: any, verifications: any) => Promise<void>, verify = verifyDexMethod, nativeVerify?: (record:any,finding:any,root:string,signal?:AbortSignal)=>Promise<any>) {
  const groups = new Map<string, any[]>();
  for (const finding of record.findings) {
    const e = finding.evidence;
    if (e?.archive_chain?.length || record.platform !== 'android' || !e?.path?.endsWith('.dex') || !e.class_descriptor || !e.method || !e.prototype) continue;
    const key = JSON.stringify([e.path, e.class_descriptor, e.method, e.prototype]);
    const group = groups.get(key) ?? []; group.push(finding); groups.set(key, group);
  }
  const dexMethods=groups.size;
  const nativeGroups=new Map<string,any[]>();
  if(nativeVerify)for(const finding of record.findings){
    const e=finding.evidence;
    if(!['elf_literal_only','native_literal_only'].includes(e?.usage) || e.transform!==undefined&&e.transform!=='none')continue;
    const key=JSON.stringify([e.path,e.member_sha256,e.slice_sha256??null,e.slice_index??null,e.file_offset]);
    const group=nativeGroups.get(key)??[];group.push(finding);nativeGroups.set(key,group);
  }
  const limit = record.scan_options.deep_method_limit ?? 3;
  const summary: any = { status: 'partial', scope: nativeVerify?'bounded_dex_and_native_corroboration':'android_dex_method_corroboration',
    method_limit: limit, eligible_methods: groups.size, attempted_methods: 0, recovered_methods: 0,
    eligible_findings: [...groups.values()].reduce((n, g) => n + g.length, 0),
    unsupported_findings: record.findings.length - [...groups.values()].reduce((n, g) => n + g.length, 0),
    remaining_methods: groups.size, usage_confirmed: false,
    native_limit:record.scan_options.deep_native_limit??2,eligible_native_literals:nativeGroups.size,
    attempted_native_literals:0,recovered_functions:0,remaining_native_literals:nativeGroups.size };
  summary.eligible_dex_findings=summary.eligible_findings;
  summary.eligible_native_findings=[...nativeGroups.values()].reduce((n,g)=>n+g.length,0);
  summary.eligible_findings+=summary.eligible_native_findings;
  summary.unsupported_findings=record.findings.length-summary.eligible_findings;
  const verifications: any = {};
  if (!groups.size && !nativeGroups.size) summary.reason = record.platform === 'android' ? (nativeVerify?'no_eligible_findings':'no_eligible_dex_findings') : nativeVerify?'no_eligible_native_findings':'automatic_native_verification_not_implemented';
  await progress(summary, verifications);
  const work=[...groups.values()].slice(0,limit).map(group=>({group,native:false}));
  work.push(...[...nativeGroups.values()].slice(0,summary.native_limit).map(group=>({group,native:true})));
  for (const {group,native} of work) {
    if (signal.aborted) { summary.reason = 'deep_cancelled_or_timeout'; break; }
    if(native){summary.attempted_native_literals++;summary.remaining_native_literals=nativeGroups.size-summary.attempted_native_literals;}
    else{summary.attempted_methods++;summary.remaining_methods=dexMethods-summary.attempted_methods;}
    const value=await (native?nativeVerify!:verify)(record,group[0],root,signal);
    if (signal.aborted) { summary.reason = 'deep_cancelled_or_timeout'; break; }
    if(value.status==='function_body_recovered')summary.recovered_functions++;
    if (value.status === 'method_body_recovered') summary.recovered_methods++;
    summary.remaining_methods = groups.size - summary.attempted_methods;
    for (const f of group) verifications[f.finding_id] = { ...value, checked_at: new Date().toISOString(), automatic: true, corroboration_source_finding_id: group[0].finding_id };
    await progress(summary, verifications);
    if (value.status === 'blocked') { summary.reason = 'verification_blocked'; break; }
  }
  if(!summary.reason&&summary.remaining_native_literals)summary.reason='deep_candidate_budget_reached';
  if (!summary.reason && summary.remaining_methods) summary.reason = 'deep_method_budget_reached';
  if (!summary.reason) summary.reason = 'bounded_corroboration_finished';
  await progress(summary, verifications);
  return summary;
}

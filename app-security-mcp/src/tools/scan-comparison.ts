// Compare detection groups, never secret equality or remediation success.
type Scan = Record<string, any>;
const canonical = (v: any): string => JSON.stringify(v, Object.keys(v).sort());
export function compareScans(before: Scan, after: Scan) {
  if (before.platform !== after.platform) throw Error('comparison_platform_mismatch');
  if (![before, after].every(s => ['partial','completed'].includes(s.state) && Array.isArray(s.findings))) throw Error('comparison_scan_not_finished_successfully');
  const warnings: string[] = [];
  for (const key of ['scanner_version','ruleset_version','profile']) if (!before[key] || before[key] !== after[key]) warnings.push(key + '_mismatch_or_missing');
  if (before.effective_profile !== after.effective_profile) warnings.push('effective_profile_mismatch_or_missing');
  if (!before.scan_options || !after.scan_options || canonical(before.scan_options) !== canonical(after.scan_options)) warnings.push('scan_options_mismatch_or_missing');
  if (JSON.stringify(before.rules) !== JSON.stringify(after.rules)) warnings.push('rule_coverage_changed');
  if (JSON.stringify(before.coverage) !== JSON.stringify(after.coverage)) warnings.push('coverage_status_changed');
  if (before.artifact_sha256 === after.artifact_sha256) warnings.push('same_artifact_not_a_repair_build');
  const coverage = (s: Scan) => ({state:s.state, effective_profile:s.effective_profile??null, deep_scan:s.deep_scan??null, scan_options:s.scan_options??null, coverage:s.coverage, rules:s.rules, resource_scan:s.resource_scan, dex_scan:s.dex_scan, android_native_scan:s.android_native_scan, ios_native_scan:s.ios_native_scan});
  for (const [label,s] of [['before',before],['after',after]] as const) {
    if (s.state === 'partial') warnings.push(label+'_coverage_partial');
    if (s.resource_scan?.findings_truncated) warnings.push(label+'_findings_truncated');
  }
  // Offsets, node indices, package/member hashes and sequential finding IDs change on rebuild.
  // Coarse groups intentionally expose counts, not one-to-one secret identities.
  const group = (s: Scan) => {
    const groups = new Map<string, {scope:any, ids:string[]}>();
    for (const f of s.findings) {
      const e=f.evidence??{};
      const scope={archive_chain:e.archive_chain?.map((p:any)=>p.path)??null,member_path:e.member_path??null,rule_id:f.rule_id,path:e.path,usage:e.usage??'resource',method:e.method??null,class_descriptor:e.class_descriptor??null,prototype:e.prototype??null,field:e.field??null,architecture:e.architecture??null,transform:e.transform??null};
      const key=canonical(scope), row=groups.get(key)??{scope,ids:[]};row.ids.push(f.finding_id);groups.set(key,row);
    }
    return groups;
  };
  const b=group(before),a=group(after);
  const groups=[...new Set([...b.keys(),...a.keys()])].sort().map(key=>{
    const old=b.get(key),next=a.get(key);
    return {scope:(old??next)!.scope,status:old&&next?'still_detected':next?'newly_detected':'not_redetected',before_finding_ids:old?.ids??[],after_finding_ids:next?.ids??[],before_count:old?.ids.length??0,after_count:next?.ids.length??0};
  });
  return {schema_version:'0.1',before_scan_id:before.scan_id,after_scan_id:after.scan_id,platform:before.platform,before_artifact_sha256:before.artifact_sha256,after_artifact_sha256:after.artifact_sha256,
    status:'partial',matching:'rule_and_evidence_scope_groups',settings_match:!warnings.some(w=>w.endsWith('_mismatch_or_missing')),repair_confirmed:false,warnings,
    summary:{still_detected:groups.filter(g=>g.status==='still_detected').length,newly_detected:groups.filter(g=>g.status==='newly_detected').length,not_redetected:groups.filter(g=>g.status==='not_redetected').length},groups,
    coverage:{before:coverage(before),after:coverage(after)},
    limitations:['结果比较的是规则与证据范围分组，不比较秘密值；同组仍检出不代表同一凭证。','本次未再检出不等于已修复；路径/架构变更、扫描缺口或截断均可能导致候选消失。','必须结合两次覆盖记录、源码修改、凭证轮换及业务验证确认修复；当前工具不自动确认已修复。']};
}

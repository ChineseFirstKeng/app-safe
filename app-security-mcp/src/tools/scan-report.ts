// Package labels and values are untrusted data. Never emit them as active markup.
const label = (value: unknown): string => String(value ?? 'unknown')
  .replace(/[\r\n\u0000-\u001f\u007f]/g, ' ')
  .replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;')
  .replace(/[\\`*_{}[\]()#+.!|~-]/g, '\\$&');
const safeJson=(value:unknown)=>JSON.stringify(value,null,2).replaceAll('`','\\u0060').replaceAll('<','\\u003c').replaceAll('>','\\u003e');

export function markdownReport(record: any): string {
  const sensitive=record.contains_sensitive_values===true;
  const reviews=record.client_identifier_review?.items??[];
  const lines = ['# 硬编码内容与安全核查报告', '',
    `- 扫描：${label(record.scan_id)}`,
    `- 平台：${label(record.platform)}；状态：${label(record.state)}`,
    `- 包 SHA-256：${label(record.artifact_sha256)}`,
    `- 安全候选：${label(record.finding_count)}；待核查标识：${reviews.length}`,
    `- 请求配置：${label(record.profile)}；实际配置：${label(record.effective_profile ?? 'static-basic')}；分析器：${label(record.scanner_version)}；规则版本：${label(record.ruleset_version)}`, '',
    sensitive?'本机核查文件包含捕获原值。内容存在不等于已确认可利用风险；用途、权限与运行行为需要对应证据。':'本报告默认脱敏。需要核对原值时，可导出 include_sensitive_values=true 的本机报告；工具只返回文件路径。', '',
    '## 候选与修复', ''];
  if (!record.findings?.length) lines.push('本次已执行规则没有检出安全候选；尚未确认任何泄密漏洞。下方待核查项仍需检查，未分析范围也不能据此排除问题。', '');
  for (const f of record.findings ?? []) {
    lines.push(`### ${label(f.finding_id)} · ${label(f.rule_id)} · ${label(f.title)}`, '',
      `- 内容：${sensitive?'见下方原值':label(f.value_preview??f.value)}`,
      `- 级别：${label(f.severity)}；置信度：${label(f.confidence)}；验证层级：${label(f.verification_level)}`,
      `- 位置：${label(f.evidence?.path)} / ${label(f.evidence?.location)}`,
      `- 方法/用途线索：${label(f.evidence?.method??f.evidence?.usage)}；${label(f.evidence?.sink??'实际用途待核查')}`,
      `- 证据 ID：${label(f.evidence_id)}`, '');
    if(sensitive)lines.push(`编码：${label(f.value_encoding??'unknown')}`, '', '```json', safeJson(f.value), '```', '');
    lines.push('**观察**', '');for (const observation of f.observations ?? []) lines.push(`- ${label(observation)}`);
    lines.push('', '**尚未确认**', '');for (const unknown of f.unknowns ?? []) lines.push(`- ${label(unknown)}`);
    lines.push('', '**修复建议**', '', label(f.remediation), '', '**复测方法**', '', label(f.retest), '');
  }
  lines.push('## 待核查的 Key 与客户端标识', '');
  if(!reviews.length)lines.push('本次没有检出支持字段范围内的额外标识。', '');
  for(const item of reviews){
    const e=item.evidence??{};
    lines.push(`### ${label(item.review_id)} · ${label(e.field_label??e.field_category)}`, '',
      `- 内容：${sensitive?'见下方原值':label(item.value_preview??item.value)}`,
      `- 来源：${label(e.path)} / ${label(e.location)}`,
      `- 分类：${label(item.classification)}；风险状态：待核查，未确认泄密`,
      `- 已知：该内容存在于安装包中。未知：实际调用用途、权限及应用绑定限制。`, '');
    if(sensitive)lines.push(`编码：${label(item.value_encoding??'unknown')}`, '', '```json', safeJson(item.value), '```', '');
    lines.push('核查与处理：', '');for(const action of item.review_actions??[])lines.push(`- ${label(action)}`);
    lines.push('');
  }
  lines.push('## 覆盖与缺口', '', '| 分析面 | 状态 |', '| --- | --- |');
  for (const [key, value] of Object.entries(record.coverage ?? {})) lines.push(`| ${label(key)} | ${label(typeof value === 'object' ? JSON.stringify(value) : value)} |`);
  lines.push('', '## 分析限制', '');for (const limitation of record.limitations ?? []) lines.push(`- ${label(limitation)}`);
  lines.push('', sensitive?'## 完整本机核查结果（含原值）':'## 完整脱敏结果', '', '包含规则状态、详细位置、复核结果和截断统计。', '', '```json', safeJson(record), '```', '');
  return lines.join('\n');
}

import { createHash } from 'node:crypto';

export function findingPage(record: any, args: any) {
  const filters = { rule_id: args.rule_id ?? null, severity: args.severity ?? null, confidence: args.confidence ?? null };
  const signature = createHash('sha256').update(JSON.stringify({
    scan_id: record.scan_id, findings: record.findings, filters,
  })).digest('hex');
  let offset = args.offset ?? 0;
  if (args.cursor) {
    try {
      const cursor = JSON.parse(Buffer.from(args.cursor, 'base64url').toString('utf8'));
      if (offset !== 0 || cursor.signature !== signature || !Number.isSafeInteger(cursor.offset) || cursor.offset < 0) throw new Error();
      offset = cursor.offset;
    } catch { throw new Error('invalid_or_stale_cursor'); }
  }
  const findings = record.findings.filter((f: any) => Object.entries(filters).every(([key, value]) => value === null || f[key] === value));
  const end = offset + args.limit;
  const next = end < findings.length ? end : null;
  return { schema_version: '0.1', scan_id: record.scan_id, state: record.state,
    finding_count: record.finding_count, filtered_count: findings.length,
    findings: findings.slice(offset, end), next_offset: next,
    next_cursor: next === null ? null : Buffer.from(JSON.stringify({ signature, offset: next })).toString('base64url'),
    source_complete: false, findings_truncated: record.resource_scan?.findings_truncated ?? false,
    coverage: record.coverage };
}

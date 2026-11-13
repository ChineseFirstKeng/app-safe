const address = (a: any): a is string => typeof a === 'string' && /^0x[0-9a-f]+$/i.test(a) && a.length <= 34;
const equal = (a: any, b: any) => address(a) && address(b) && BigInt(a) === BigInt(b);
export function containsAddress(body: any, query: any): boolean {
  return address(query) && body?.available === true && Array.isArray(body.ranges) && body.ranges.length <= 64 && body.ranges.some((r: any) => address(r.start) && address(r.end) && BigInt(r.start) <= BigInt(query) && BigInt(query) <= BigInt(r.end));
}

/** Identity-bound original offsets; never infer a load bias or a nearby function. */
export async function discoverNativeProcedure(e: any, identity: string, provider: string, isElf: boolean,
  call: (name: string, args: any) => Promise<any>) {
  const base: any = { status: 'partial', string_mappings_checked: 0, mapping_failures: 0,
    strings_truncated: false, references_checked: 0, references_truncated: false, usage_confirmed: false };
  if (e.transform !== undefined && e.transform !== 'none') return { ...base, reason: 'decoded_value_not_a_direct_literal' };
  const offset = isElf ? e.file_offset : e.file_offset - e.slice_offset;
  if (!Number.isSafeInteger(offset) || offset < 0 || !isElf && (!Number.isSafeInteger(e.slice_offset) || e.slice_offset < 0)) return { ...base, reason: 'candidate_file_offset_invalid' };
  const bound = async (name: string, args: any) => {
    const r = await call(name, args);
    if (r.subject?.digest?.sha256 !== identity || r.provider?.id !== provider || typeof r.evidence_id !== 'string') throw Error('rea_native_discovery_identity_mismatch');
    return r;
  };
  const mapped = async (a: string) => {
    base.string_mappings_checked++;
    try {
      const r = await bound('address_to_file_offset', { address: a });
      if (!equal(r.normalized_result?.address, a) || r.normalized_result.file_offset !== offset) return null;
      return { address: a, evidence_id: r.evidence_id, file_offset: offset };
    } catch { base.mapping_failures++; return null; }
  };
  let match = address(e.virtual_address) ? await mapped(e.virtual_address) : null;
  if (!match) {
    const inventory = await bound('list_strings', {});
    if (!Array.isArray(inventory.normalized_result)) return { ...base, reason: 'provider_strings_unavailable' };
    const addresses = [...new Set<string>(inventory.normalized_result.map((r: any) => r?.address).filter(address))];
    base.strings_truncated = addresses.length > 128;
    // Values from the inventory remain transient and are never persisted or used as instructions.
    for (const a of addresses.slice(0, 128)) {
      if (equal(a, e.virtual_address)) continue;
      match = await mapped(a); if (match) break;
    }
  }
  if (!match) return { ...base, reason: 'candidate_address_not_mapped' };
  const refs = await bound('xrefs', { address: match.address });
  if (!Array.isArray(refs.normalized_result)) return { ...base, reason: 'provider_references_unavailable' };
  const sources = [...new Set<string>(refs.normalized_result.filter(address))];
  base.references_truncated = sources.length > 32;
  for (const source of sources.slice(0, 32)) {
    base.references_checked++;
    const resolved = await bound('resolve_containing_procedure', { address: source });
    const r = resolved.normalized_result;
    if (r?.found !== true || !equal(r.query_address, source) || !address(r.procedure?.address) || r.procedure.classification?.external === true || !containsAddress(r.procedure.body, source) || !containsAddress(r.procedure.body, r.procedure.address)) continue;
    return { ...base, status: 'selected', procedure: r.procedure.address,
      string_address: match.address, original_file_offset: offset, mapping_evidence_id: match.evidence_id,
      reference_source_address: source, xrefs_evidence_id: refs.evidence_id, procedure_evidence_id: resolved.evidence_id,
      selection: 'identity_bound_offset_then_xref_containing_function' };
  }
  return { ...base, reason: 'no_function_in_returned_references' };
}

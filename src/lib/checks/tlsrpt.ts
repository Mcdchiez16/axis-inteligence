import { attempt, type DnsClient } from '../dns.ts';
import { parseTags } from './dmarc.ts';
import type { CheckResult, Finding } from './types.ts';

export const TLSRPT_MAX = 10;

export async function checkTlsRpt(domain: string, dns: DnsClient): Promise<CheckResult<{ rua: string[] }>> {
  const base = { id: 'tlsrpt', title: 'TLS-RPT', max: TLSRPT_MAX } as const;
  const res = await attempt(() => dns.txt(`_smtp._tls.${domain}`));
  if (!res.ok) return { ...base, status: 'unknown', summary: `The TLS-RPT record could not be looked up (${res.error}).`, points: 0, findings: [] };
  const records = res.value.filter((r) => /^v=TLSRPTv1\s*;?/i.test(r.trim()));
  if (records.length === 0) return { ...base, status: 'missing', summary: 'No TLS-RPT record is published, so you will not be told when other servers cannot deliver mail to you securely.', points: 0, findings: [{ level: 'warn', text: `Publish a TXT record at _smtp._tls.${domain}, for example: v=TLSRPTv1; rua=mailto:tls-reports@${domain}` }] };
  if (records.length > 1) return { ...base, status: 'fail', summary: 'More than one TLS-RPT record is published.', points: 0, record: records.join('\n'), findings: [{ level: 'bad', text: 'Keep exactly one TLS-RPT record.' }] };
  const record = records[0];
  const tags = parseTags(record);
  const rua = (tags.rua ?? '').split(',').map((s) => s.trim()).filter(Boolean);
  const findings: Finding[] = [];
  const valid = rua.filter((u) => /^mailto:[^@\s]+@[^@\s]+$/i.test(u) || /^https:\/\/\S+$/i.test(u));
  if (!rua.length) return { ...base, status: 'fail', summary: 'The TLS-RPT record has no rua= address.', points: 0, record, findings: [{ level: 'bad', text: 'Add rua=mailto:... or rua=https://... so reports have somewhere to go.' }], data: { rua } };
  for (const u of rua) if (!valid.includes(u)) findings.push({ level: 'warn', text: `"${u}" is not a valid mailto: or https: address.` });
  if (valid.length) findings.push({ level: 'ok', text: `TLS reports go to ${valid.join(', ')}.` });
  return { ...base, status: valid.length ? 'pass' : 'fail', summary: valid.length ? 'TLS-RPT is set up.' : 'The TLS-RPT addresses are not valid.', points: valid.length ? TLSRPT_MAX : 0, record, findings, data: { rua } };
}

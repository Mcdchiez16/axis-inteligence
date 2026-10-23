import { attempt, type DnsClient } from '../dns.ts';
import type { CheckResult, Finding } from './types.ts';

export type MxData = { records: { priority: number; exchange: string; resolves: boolean; isCname: boolean }[]; mode: 'mail' | 'no-mail'; implicit?: boolean };

export async function checkMx(domain: string, dns: DnsClient): Promise<CheckResult<MxData>> {
  const base = { id: 'mx', title: 'Mail servers (MX)', max: 0 } as const;
  const mx = await attempt(() => dns.mx(domain));
  if (!mx.ok) return { ...base, status: 'unknown', summary: `The MX records could not be looked up (${mx.error}).`, points: 0, findings: [], data: { records: [], mode: 'mail' } };
  const findings: Finding[] = [];

  if (mx.value.length === 1 && (mx.value[0].exchange === '' || mx.value[0].exchange === '.')) {
    return { ...base, status: 'pass', summary: 'A "null MX" is published: this domain declares that it does not send or receive email.', points: 0, findings: [{ level: 'ok', text: 'Null MX (RFC 7505) is the correct way to say a domain handles no mail.' }], data: { records: [], mode: 'no-mail' } };
  }
  if (mx.value.length === 0) {
    const [a, aaaa] = await Promise.all([attempt(() => dns.a(domain)), attempt(() => dns.aaaa(domain))]);
    const hasAddress = (a.ok && a.value.length > 0) || (aaaa.ok && aaaa.value.length > 0);
    // like a null MX, no MX at all marks a domain that does not handle email; it only has to block spoofing
    if (hasAddress) findings.push({ level: 'info', text: 'Without MX records, senders could still fall back to the website address. If this domain should receive email, publish MX records.' });
    else findings.push({ level: 'info', text: 'The domain publishes no MX records and no address, so it cannot receive email.' });
    return { ...base, status: 'missing', summary: 'No MX records are published, so this is treated as a domain that does not send email.', points: 0, findings, data: { records: [], mode: 'no-mail', implicit: hasAddress } };
  }

  const sorted = [...mx.value].sort((a, b) => a.priority - b.priority);
  const records = await Promise.all(
    sorted.map(async (m) => {
      const [a, aaaa, c] = await Promise.all([attempt(() => dns.a(m.exchange)), attempt(() => dns.aaaa(m.exchange)), attempt(() => dns.cname(m.exchange))]);
      return { ...m, resolves: (a.ok && a.value.length > 0) || (aaaa.ok && aaaa.value.length > 0), isCname: c.ok && c.value.length > 0 };
    }),
  );
  for (const r of records) {
    if (!r.resolves) findings.push({ level: 'bad', text: `${r.exchange} does not resolve to an address, so mail to it will fail.` });
    if (r.isCname) findings.push({ level: 'warn', text: `${r.exchange} is a CNAME; MX records must point at a name with an address record.` });
  }
  if (records.length === 1) findings.push({ level: 'info', text: 'Only one mail server is listed. A second one adds resilience.' });
  if (!findings.length) findings.push({ level: 'ok', text: `${records.length} mail servers, all resolving.` });
  const bad = records.some((r) => !r.resolves);
  return { ...base, status: bad ? 'fail' : 'pass', summary: `${records.length} mail server${records.length === 1 ? '' : 's'} found.`, points: 0, findings, data: { records, mode: 'mail' } };
}

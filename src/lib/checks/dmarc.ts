import { attempt, type DnsClient } from '../dns.ts';
import { organizationalDomain } from '../domain.ts';
import type { CheckResult, Finding } from './types.ts';

export type DmarcPolicy = 'none' | 'quarantine' | 'reject';
export type DmarcData = {
  policy?: DmarcPolicy;
  subdomainPolicy?: DmarcPolicy;
  pct: number;
  rua: string[];
  ruf: string[];
  adkim: 'r' | 's';
  aspf: 'r' | 's';
  foundAt?: string;
  /** report destinations on other domains that have not agreed to receive reports */
  unauthorisedReports?: string[];
  tags: Record<string, string>;
};

export const DMARC_MAX = 30;

export function parseTags(record: string): Record<string, string> {
  const tags: Record<string, string> = {};
  for (const part of record.split(';')) {
    const i = part.indexOf('=');
    if (i < 0) continue;
    const k = part.slice(0, i).trim().toLowerCase();
    if (k && !(k in tags)) tags[k] = part.slice(i + 1).trim();
  }
  return tags;
}

const isPolicy = (v?: string): v is DmarcPolicy => v === 'none' || v === 'quarantine' || v === 'reject';

function uris(v?: string): string[] {
  return (v ?? '').split(',').map((s) => s.trim()).filter(Boolean);
}

/** Is DMARC enforcing (receivers act on failures) for the whole domain? */
export function dmarcEnforced(d?: DmarcData): boolean {
  return !!d && (d.policy === 'quarantine' || d.policy === 'reject') && d.pct === 100;
}

export async function checkDmarc(domain: string, dns: DnsClient): Promise<CheckResult<DmarcData>> {
  const base: Pick<CheckResult<DmarcData>, 'id' | 'title' | 'max'> = { id: 'dmarc', title: 'DMARC', max: DMARC_MAX };
  const findings: Finding[] = [];

  const lookup = async (name: string) => attempt(() => dns.txt(`_dmarc.${name}`));
  let foundAt = domain;
  let res = await lookup(domain);
  if (!res.ok) return { ...base, status: 'unknown', summary: `The DMARC record could not be looked up (${res.error}).`, points: 0, findings: [{ level: 'warn', text: 'DNS did not answer for _dmarc.' + domain }] };
  let records = res.value.filter((r) => /^v=DMARC1\s*;?/i.test(r.trim()));

  // no record on the subdomain: DMARC falls back to the organizational domain (RFC 7489 section 6.6.3)
  const org = organizationalDomain(domain);
  if (records.length === 0 && org !== domain) {
    const orgRes = await lookup(org);
    if (orgRes.ok) {
      const orgRecords = orgRes.value.filter((r) => /^v=DMARC1\s*;?/i.test(r.trim()));
      if (orgRecords.length) {
        records = orgRecords;
        foundAt = org;
        findings.push({ level: 'info', text: `No DMARC record on ${domain}; the policy of ${org} applies.` });
      }
    }
  }

  if (records.length === 0) {
    return { ...base, status: 'missing', summary: 'No DMARC record is published, so receivers have no instruction for mail that fails authentication.', points: 0, findings: [{ level: 'bad', text: 'Publish a DMARC record at _dmarc.' + domain + ', starting with p=none and a reporting address, then move to quarantine and reject.' }] };
  }
  if (records.length > 1) {
    return { ...base, status: 'fail', summary: 'More than one DMARC record is published, which makes DMARC invalid.', points: 0, record: records.join('\n'), findings: [{ level: 'bad', text: `${records.length} DMARC records were found. Keep exactly one.` }] };
  }

  const record = records[0];
  const tags = parseTags(record);
  const policy = tags.p?.toLowerCase();
  if (!isPolicy(policy)) {
    return { ...base, status: 'fail', summary: 'The DMARC record has no valid p= policy.', points: 0, record, findings: [{ level: 'bad', text: 'p= must be none, quarantine or reject.' }], data: { pct: 100, rua: [], ruf: [], adkim: 'r', aspf: 'r', foundAt, tags } };
  }
  const sp = tags.sp?.toLowerCase();
  const pct = tags.pct !== undefined && /^\d+$/.test(tags.pct) ? Math.min(100, Number(tags.pct)) : 100;
  const rua = uris(tags.rua);
  const ruf = uris(tags.ruf);
  const data: DmarcData = { policy, subdomainPolicy: isPolicy(sp) ? sp : undefined, pct, rua, ruf, adkim: tags.adkim?.toLowerCase() === 's' ? 's' : 'r', aspf: tags.aspf?.toLowerCase() === 's' ? 's' : 'r', foundAt, tags };

  let points = policy === 'reject' ? 26 : policy === 'quarantine' ? 18 : 6;
  if (policy !== 'none' && pct < 100) {
    points = Math.round(points * (0.4 + (0.5 * pct) / 100));
    findings.push({ level: 'warn', text: `pct=${pct}: the policy only applies to ${pct}% of failing mail. Raise it to 100.` });
  }
  if (policy === 'none') findings.push({ level: 'warn', text: 'p=none only monitors. Fake mail is still delivered. Move to p=quarantine, then p=reject, once reports look clean.' });
  if (policy === 'quarantine') findings.push({ level: 'info', text: 'p=quarantine sends failing mail to spam. p=reject blocks it completely.' });
  if (policy === 'reject') findings.push({ level: 'ok', text: 'p=reject: mail that fails authentication is refused.' });

  if (data.subdomainPolicy && rank(data.subdomainPolicy) < rank(policy)) {
    points -= 3;
    findings.push({ level: 'warn', text: `sp=${data.subdomainPolicy} is weaker than the main policy, leaving subdomains easier to spoof.` });
  }
  if (rua.length) {
    points += 4;
    findings.push({ level: 'ok', text: `Aggregate reports go to ${rua.join(', ')}.` });
    for (const u of rua) if (!/^mailto:[^@\s]+@[^@\s]+$/i.test(u) && !/^https:\/\//i.test(u)) findings.push({ level: 'warn', text: `rua address "${u}" is not a valid mailto: or https: URI.` });
  } else findings.push({ level: 'warn', text: 'There is no rua= reporting address, so you cannot see who sends mail as this domain.' });
  const unauthorised = await unauthorisedReportHosts(foundAt, rua, dns);
  if (unauthorised.length) {
    data.unauthorisedReports = unauthorised;
    for (const h of unauthorised) findings.push({ level: 'bad', text: `${h} has not confirmed that it accepts DMARC reports for ${foundAt}, so receivers will not send reports there. It needs to publish ${foundAt}._report._dmarc.${h}.` });
  }
  if (data.adkim === 's' || data.aspf === 's') findings.push({ level: 'info', text: 'Strict alignment is set (adkim/aspf=s). Make sure every sender uses your exact domain.' });
  if (tags.ruf) findings.push({ level: 'info', text: 'ruf= (forensic reports) is set; many receivers ignore it for privacy reasons.' });

  points = Math.max(0, Math.min(DMARC_MAX, points));
  const status = policy === 'reject' && pct === 100 ? 'pass' : policy === 'none' ? 'fail' : 'warn';
  const summary =
    status === 'pass' ? 'DMARC is enforced with p=reject.' : policy === 'none' ? 'DMARC is published but only monitors; spoofed mail is still delivered.' : 'DMARC is partly enforced.';
  return { ...base, status, summary, points, record, findings, data };
}

/**
 * Reports may only go to another domain if that domain publishes <policy domain>._report._dmarc.<its host>
 * (RFC 7489 section 7.1). Hosts that could not be checked are given the benefit of the doubt.
 */
async function unauthorisedReportHosts(policyDomain: string, uris: string[], dns: DnsClient): Promise<string[]> {
  const org = organizationalDomain(policyDomain);
  const hosts = new Set<string>();
  for (const u of uris) {
    const host = /^mailto:[^@]+@([^!?\s]+)/i.exec(u)?.[1]?.toLowerCase().replace(/\.$/, '');
    if (host && host !== org && !host.endsWith(`.${org}`) && organizationalDomain(host) !== org) hosts.add(host);
  }
  const results = await Promise.all(
    [...hosts].map(async (h) => {
      const r = await attempt(() => dns.txt(`${policyDomain}._report._dmarc.${h}`));
      return r.ok && !r.value.some((t) => /^v=DMARC1/i.test(t.trim())) ? h : null;
    }),
  );
  return results.filter((h): h is string => h !== null);
}

function rank(p: DmarcPolicy) {
  return p === 'reject' ? 2 : p === 'quarantine' ? 1 : 0;
}

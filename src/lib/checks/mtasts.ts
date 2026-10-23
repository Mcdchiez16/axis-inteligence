import { attempt, type DnsClient } from '../dns.ts';
import { safeFetch } from '../safe-fetch.ts';
import { parseTags } from './dmarc.ts';
import type { CheckResult, Finding } from './types.ts';

export const MTASTS_MAX = 15;

export type MtaStsPolicy = { version?: string; mode?: string; mx: string[]; maxAge?: number };

export function parseMtaStsPolicy(body: string): MtaStsPolicy {
  const policy: MtaStsPolicy = { mx: [] };
  for (const line of body.split(/\r?\n/)) {
    const i = line.indexOf(':');
    if (i < 0) continue;
    const k = line.slice(0, i).trim().toLowerCase();
    const v = line.slice(i + 1).trim();
    if (k === 'version') policy.version = v;
    else if (k === 'mode') policy.mode = v.toLowerCase();
    else if (k === 'mx') policy.mx.push(v.toLowerCase());
    else if (k === 'max_age' && /^\d+$/.test(v)) policy.maxAge = Number(v);
  }
  return policy;
}

/** Does an MX host match an MTA-STS pattern such as "mail.example.com" or "*.example.com"? */
export function mxMatches(host: string, pattern: string): boolean {
  host = host.toLowerCase().replace(/\.$/, '');
  if (pattern.startsWith('*.')) {
    const suffix = pattern.slice(1);
    return host.endsWith(suffix) && host.length > suffix.length && !host.slice(0, -suffix.length).includes('.');
  }
  return host === pattern;
}

export type MtaStsData = { id?: string; policy?: MtaStsPolicy; policyUrl: string };

export async function checkMtaSts(domain: string, dns: DnsClient, mxHosts: string[]): Promise<CheckResult<MtaStsData>> {
  const base = { id: 'mtasts', title: 'MTA-STS', max: MTASTS_MAX } as const;
  const policyUrl = `https://mta-sts.${domain}/.well-known/mta-sts.txt`;
  const res = await attempt(() => dns.txt(`_mta-sts.${domain}`));
  if (!res.ok) return { ...base, status: 'unknown', summary: `The MTA-STS record could not be looked up (${res.error}).`, points: 0, findings: [], data: { policyUrl } };
  const records = res.value.filter((r) => /^v=STSv1\s*;?/i.test(r.trim()));
  if (records.length === 0) return { ...base, status: 'missing', summary: 'MTA-STS is not set up, so email to this domain can be downgraded to unencrypted delivery.', points: 0, findings: [{ level: 'warn', text: `Publish a TXT record at _mta-sts.${domain} and host a policy file at ${policyUrl}.` }], data: { policyUrl } };
  if (records.length > 1) return { ...base, status: 'fail', summary: 'More than one MTA-STS record is published.', points: 0, record: records.join('\n'), findings: [{ level: 'bad', text: 'Keep exactly one.' }], data: { policyUrl } };

  const record = records[0];
  const tags = parseTags(record);
  const findings: Finding[] = [];
  if (!tags.id) findings.push({ level: 'bad', text: 'The record has no id= value.' });

  let fetched;
  try {
    fetched = await safeFetch(policyUrl, { timeoutMs: 5000, maxBytes: 64 * 1024, accept: 'text/plain' });
  } catch (e) {
    findings.push({ level: 'bad', text: `The policy file at ${policyUrl} could not be fetched (${e instanceof Error ? e.message.replace(/^fetch failed$/, 'connection failed') : 'error'}). Check that mta-sts.${domain} has a valid HTTPS certificate.` });
    return { ...base, status: 'fail', summary: 'The MTA-STS record exists, but the policy file is not reachable.', points: 2, record, findings, data: { id: tags.id, policyUrl } };
  }
  if (fetched.status >= 300 && fetched.status < 400) {
    findings.push({ level: 'bad', text: 'The policy file redirects. MTA-STS requires it to be served directly, without redirects.' });
    return { ...base, status: 'fail', summary: 'The MTA-STS policy file redirects.', points: 2, record, findings, data: { id: tags.id, policyUrl } };
  }
  if (fetched.status !== 200) {
    findings.push({ level: 'bad', text: `The policy file returned HTTP ${fetched.status}.` });
    return { ...base, status: 'fail', summary: 'The MTA-STS policy file could not be read.', points: 2, record, findings, data: { id: tags.id, policyUrl } };
  }
  const policy = parseMtaStsPolicy(fetched.body);
  if (policy.version !== 'STSv1') findings.push({ level: 'bad', text: 'The policy file must start with "version: STSv1".' });
  if (!/^text\/plain/i.test(fetched.contentType)) findings.push({ level: 'warn', text: `The policy is served as "${fetched.contentType || 'no content type'}"; it should be text/plain.` });
  if (!policy.mx.length) findings.push({ level: 'bad', text: 'The policy lists no mx: hosts.' });
  const unmatched = mxHosts.filter((h) => !policy.mx.some((p) => mxMatches(h, p)));
  if (mxHosts.length && unmatched.length) findings.push({ level: 'bad', text: `These mail servers are not covered by the policy: ${unmatched.join(', ')}. In enforce mode, senders would refuse to deliver to them.` });
  if (policy.maxAge === undefined) findings.push({ level: 'bad', text: 'The policy has no max_age.' });
  else if (policy.maxAge < 86400) findings.push({ level: 'warn', text: `max_age is ${policy.maxAge} seconds; use at least one day, ideally a week or more.` });

  let points = policy.mode === 'enforce' ? 15 : policy.mode === 'testing' ? 8 : 3;
  if (policy.mode === 'enforce') findings.push({ level: 'ok', text: 'mode: enforce. Senders must deliver over verified TLS.' });
  else if (policy.mode === 'testing') findings.push({ level: 'warn', text: 'mode: testing only reports problems. Switch to enforce once reports look clean.' });
  else findings.push({ level: 'warn', text: `mode: ${policy.mode ?? 'missing'} gives no protection.` });
  if (findings.some((f) => f.level === 'bad')) points = Math.min(points, 6);
  const status = points >= 15 ? 'pass' : points >= 6 ? 'warn' : 'fail';
  return { ...base, status, summary: status === 'pass' ? 'MTA-STS is enforced.' : 'MTA-STS is published but not fully effective.', points, record, findings, data: { id: tags.id, policy, policyUrl } };
}

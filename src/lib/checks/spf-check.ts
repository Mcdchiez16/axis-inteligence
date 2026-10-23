import type { DnsClient } from '../dns.ts';
import { analyzeSpf, type SpfAnalysis } from './spf.ts';
import type { CheckResult, Finding } from './types.ts';

export const SPF_MAX = 12;

export async function checkSpf(domain: string, dns: DnsClient): Promise<CheckResult<SpfAnalysis>> {
  const base = { id: 'spf', title: 'SPF', max: SPF_MAX } as const;
  const a = await analyzeSpf(domain, dns);
  if (a.unreachable) return { ...base, status: 'unknown', summary: `The SPF record could not be looked up (${a.unreachable}).`, points: 0, findings: [], data: a };
  if (a.status === 'missing') return { ...base, status: 'missing', summary: 'No SPF record is published, so any server can claim to send for this domain.', points: 0, findings: [{ level: 'bad', text: `Publish one TXT record on ${domain} listing your senders, ending in -all.` }], data: a };
  const findings: Finding[] = a.issues.map((text) => ({ level: /\+all|limit|invalid|error|no SPF record|records are published/i.test(text) ? 'bad' : 'warn', text }));
  if (a.status === 'multiple' || a.status === 'invalid') return { ...base, status: 'fail', summary: 'The SPF record is invalid, so receivers treat it as an error.', points: 2, record: a.records.join('\n'), findings, data: a };
  let points = a.allQualifier === '-' ? 12 : a.allQualifier === '~' ? 9 : a.allQualifier === '?' ? 3 : a.allQualifier === '+' ? 0 : 6;
  if (a.lookups >= 8 && points > 0) points -= 1;
  findings.unshift({ level: points >= 12 ? 'ok' : 'info', text: `${a.lookups} of 10 DNS lookups used${a.includes.length ? `; includes ${a.includes.join(', ')}` : ''}.` });
  const status = points >= 12 ? 'pass' : points >= 6 ? 'warn' : 'fail';
  return { ...base, status, summary: status === 'pass' ? 'SPF is valid and ends with -all.' : 'SPF is published but does not fully block unlisted senders.', points, record: a.record, findings, data: a };
}

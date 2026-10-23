import { bimiComplete, checkBimi, type BimiData } from './checks/bimi.ts';
import { checkDkim, type DkimData } from './checks/dkim.ts';
import { checkDmarc, type DmarcData } from './checks/dmarc.ts';
import { checkMtaSts, type MtaStsData } from './checks/mtasts.ts';
import { checkMx, type MxData } from './checks/mx.ts';
import { checkSpf } from './checks/spf-check.ts';
import { MAX_LOOKUPS, type SpfAnalysis } from './checks/spf.ts';
import { checkTlsRpt } from './checks/tlsrpt.ts';
import type { CheckResult } from './checks/types.ts';
import { attempt, type DnsClient } from './dns.ts';
import { organizationalDomain } from './domain.ts';
import { dnsProvider, emailProvider, reportProviders } from './providers.ts';
import type { Risk } from './risk.ts';

export type { Risk } from './risk.ts';
export type CategoryId = 'impersonation' | 'privacy' | 'branding';
export type Category = { id: CategoryId; title: string; question: string; rating: number; risk: Risk; explanation: string; checks: string[] };

export type CommonRecords = {
  ns: string[];
  mx: string[];
  a: string[];
  dnsProvider: string;
  emailProvider: string;
  website: boolean;
};

export type DomainReport = {
  domain: string;
  organizationalDomain: string;
  checkedAt: string;
  score: number;
  grade: string;
  risk: Risk;
  summary: string;
  mailMode: 'mail' | 'no-mail';
  categories: Category[];
  checks: Record<string, CheckResult>;
  common: CommonRecords;
  providers: { dmarc: string[]; tlsrpt: string[] };
  recommendations: string[];
};

/** Category weights: impersonation protection matters most, a brand logo least. */
export const WEIGHTS: Record<CategoryId, number> = { impersonation: 80, privacy: 15, branding: 5 };

export function gradeFor(score: number): string {
  if (score >= 90) return 'A';
  if (score >= 75) return 'B';
  if (score >= 60) return 'C';
  if (score >= 40) return 'D';
  return 'F';
}

export const riskForRating = (r: number): Risk => (r >= 5 ? 'low' : r === 4 ? 'medium' : 'high');
export const riskForScore = (s: number): Risk => (s >= 80 ? 'low' : s >= 50 ? 'medium' : 'high');

type Inputs = { dmarc: CheckResult<DmarcData>; spf: CheckResult<SpfAnalysis>; dkim: CheckResult<DkimData>; mtasts: CheckResult<MtaStsData>; tlsrpt: CheckResult; bimi: CheckResult<BimiData>; mailMode: 'mail' | 'no-mail' };

/**
 * Gaps in impersonation protection, out of 10. Each one costs a tenth of the impersonation points (two
 * tenths of the score for a domain that sends no email). DKIM is not counted: selectors cannot be listed
 * from DNS, so a missing key only means none of the common names matched.
 */
export function impersonationGaps({ dmarc, spf, mailMode }: Inputs): number {
  let gaps = 0;
  const d = dmarc.data;
  if (dmarc.status === 'missing' || dmarc.status === 'unknown' || !d?.policy) gaps += 5;
  else {
    gaps += d.policy === 'none' ? 3 : d.policy === 'quarantine' ? 1 : 0;
    gaps += d.subdomainPolicy === 'none' ? 3 : d.subdomainPolicy === 'quarantine' ? 1 : 0;
    if (d.pct < 100) gaps += 1;
    if (!d.rua.length) gaps += 1;
    if (d.unauthorisedReports?.length) gaps += 1;
  }
  const s = spf.data;
  // without MX records a missing SPF record is not held against the domain; DMARC alone blocks spoofing
  if (mailMode === 'no-mail' && (!s || s.status === 'missing')) return Math.min(10, gaps);
  if (!s || s.status === 'missing' || s.status === 'multiple' || spf.status === 'unknown') gaps += 5;
  else {
    if (s.lookups > MAX_LOOKUPS) gaps += 2;
    if (s.allQualifier === '+') gaps += 5;
    else if (s.allQualifier === '?' || !s.allQualifier) gaps += 1;
  }
  return Math.min(10, gaps);
}

/** Out of 15: TLS-RPT is worth 7, an MTA-STS policy 8 when enforced or 6 while testing. */
export function privacyPoints({ mtasts, tlsrpt }: Inputs): number {
  const mode = mtasts.status === 'pass' || mtasts.status === 'warn' ? mtasts.data?.policy?.mode : undefined;
  const sts = mode === 'enforce' ? 8 : mode === 'testing' ? 6 : 0;
  const rpt = tlsrpt.status === 'pass' || tlsrpt.status === 'warn' ? 7 : 0;
  return sts + rpt;
}

/** 0, 2 or 5: no usable logo, a logo with a problem around it, or a complete BIMI setup. */
export function brandingRating({ bimi, dmarc }: Inputs): number {
  if (!bimi.data?.logoValid) return 0;
  return bimiComplete(bimi.data, dmarc.data) ? 5 : 2;
}

const EXPLAIN: Record<CategoryId, string[]> = {
  impersonation: [
    'Anyone can send email that appears to come from this domain. There is no DMARC or SPF record to stop it.',
    'Protection is minimal. Fake email using this domain will usually still be delivered.',
    'Little protection: without an enforced DMARC policy, fake email using this domain still reaches inboxes.',
    'Some protection is in place, but gaps remain that let spoofed email reach inboxes.',
    'Strong protection with one gap left. Close it to block impersonation completely.',
    'Fully protected. DMARC rejects email that fails authentication and SPF lists your senders, so email faking this domain is blocked.',
  ],
  privacy: [
    'Email sent to this domain can be downgraded to an unencrypted connection, and you would not be told.',
    'A transport security policy is published but is not effective yet.',
    'Partial protection: either encryption is not enforced or failures are not reported to you.',
    'Encryption is requested, but not fully enforced or reported.',
    'Failures are reported to you, but the MTA-STS policy is still in testing mode, so encryption is not enforced.',
    'Email to this domain must be delivered over verified encryption, and you receive reports when that fails.',
  ],
  branding: [
    'Your logo is not shown next to your email. BIMI adds a verified brand logo in supporting inboxes.',
    'A BIMI record exists, but the logo will not display until the image, the certificate and DMARC enforcement are all in place.',
    'Your BIMI logo is valid, but the record, the certificate or the DMARC policy has a problem, so inboxes may not show it.',
    'BIMI is partly set up; one part still needs attention.',
    'BIMI is nearly complete.',
    'Your logo is set up to appear next to your email in supporting inboxes.',
  ],
};

const SUMMARY: Record<Risk, string> = {
  low: 'This domain is well protected against email impersonation. Keep reading your DMARC reports to keep it that way.',
  medium: 'This domain has some protection, but gaps remain that attackers could use to impersonate it or intercept its email.',
  high: 'This domain can easily be used to send fake email. Set up DMARC, SPF and DKIM first.',
};

/** A subdomain usually has no NS records of its own: walk up to the zone that serves it. */
async function zoneNameServers(domain: string, dns: DnsClient): Promise<string[]> {
  const labels = domain.split('.');
  for (let i = 0; i < labels.length - 1; i++) {
    const r = await attempt(() => dns.ns(labels.slice(i).join('.')));
    if (r.ok && r.value.length) return r.value.map((n) => n.toLowerCase().replace(/\.$/, ''));
  }
  return [];
}

async function commonRecords(domain: string, dns: DnsClient, mx: CheckResult<MxData>): Promise<CommonRecords> {
  const [nsList, a, aaaa] = await Promise.all([zoneNameServers(domain, dns), attempt(() => dns.a(domain)), attempt(() => dns.aaaa(domain))]);
  const mxList = (mx.data?.records ?? []).map((r) => r.exchange);
  const addresses = [...(a.ok ? a.value : []), ...(aaaa.ok ? aaaa.value : [])];
  return { ns: nsList, mx: mxList, a: addresses, dnsProvider: dnsProvider(nsList), emailProvider: mxList.length ? emailProvider(mxList) : 'None, not an email sending domain', website: addresses.length > 0 };
}

/** Runs every check for a domain and turns them into ratings, a 0-100 score and a to-do list. */
export async function analyseDomain(domain: string, dns: DnsClient, opts: { dkimSelector?: string } = {}): Promise<DomainReport> {
  const [mx, dmarc, spf, dkim, tlsrpt] = await Promise.all([checkMx(domain, dns), checkDmarc(domain, dns), checkSpf(domain, dns), checkDkim(domain, dns, opts.dkimSelector), checkTlsRpt(domain, dns)]);
  const mxHosts = (mx.data?.records ?? []).map((r) => r.exchange);
  const [mtasts, bimi, common] = await Promise.all([checkMtaSts(domain, dns, mxHosts), checkBimi(domain, dns, dmarc.data), commonRecords(domain, dns, mx)]);
  const checks: Record<string, CheckResult> = { mx, dmarc, spf, dkim, mtasts, tlsrpt, bimi };
  const mailMode = mx.data?.mode ?? 'mail';
  const noMail = mailMode === 'no-mail';
  if (noMail && dkim.status === 'missing') checks.dkim = { ...dkim, status: 'pass', notRequired: true, summary: 'No MX records, so DKIM is not required.', findings: [] };
  if (noMail && spf.status === 'missing') checks.spf = { ...spf, status: 'pass', notRequired: true, summary: 'No MX records, so SPF is not required.', findings: [] };
  const inputs: Inputs = { dmarc, spf, dkim, mtasts, tlsrpt, bimi, mailMode };

  const make = (id: CategoryId, title: string, question: string, rating: number, ids: string[]): Category => ({ id, title, question, rating, risk: riskForRating(rating), explanation: EXPLAIN[id][rating], checks: ids });
  const gaps = impersonationGaps(inputs);
  const privacy = privacyPoints(inputs);
  const branding = brandingRating(inputs);
  const categories = [
    make('impersonation', 'Impersonation', 'Can someone send email pretending to be you?', noMail ? Math.max(0, 5 - gaps) : Math.floor((10 - gaps) / 2), ['dmarc', 'spf', 'dkim']),
    make('privacy', 'Privacy', 'Is email sent to you protected from interception?', Math.floor(privacy / 3), ['tlsrpt', 'mtasts']),
    make('branding', 'Branding', 'Does your logo appear next to your email?', branding, ['bimi']),
  ];
  // a domain without email is judged only on whether it blocks spoofing
  const score = noMail ? categories[0].rating * 20 : Math.round((WEIGHTS.impersonation * (10 - gaps)) / 10 + privacy + (WEIGHTS.branding * branding) / 5);

  const org = organizationalDomain(domain);
  const providers = {
    dmarc: reportProviders([...(dmarc.data?.rua ?? []), ...(dmarc.data?.ruf ?? [])], domain, org),
    tlsrpt: reportProviders(((tlsrpt.data as { rua?: string[] } | undefined)?.rua ?? []), domain, org),
  };

  const order = ['dmarc', 'spf', 'dkim', 'mx', 'mtasts', 'tlsrpt', 'bimi'];
  const recommendations = order
    .flatMap((id) => checks[id].findings.filter((f) => f.level === 'bad' || f.level === 'warn').map((f) => `${checks[id].title}: ${f.text}`))
    .filter((r) => mailMode === 'mail' || /^(DMARC|SPF)/.test(r))
    .slice(0, 8);

  const risk = riskForScore(score);
  return { domain, organizationalDomain: org, checkedAt: new Date().toISOString(), score, grade: gradeFor(score), risk, summary: SUMMARY[risk], mailMode, categories, checks, common, providers, recommendations };
}

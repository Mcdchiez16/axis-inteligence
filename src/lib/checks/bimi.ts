import { X509Certificate } from 'node:crypto';

import { attempt, type DnsClient } from '../dns.ts';
import { safeFetch } from '../safe-fetch.ts';
import { dmarcEnforced, parseTags, type DmarcData } from './dmarc.ts';
import type { CheckResult, Finding } from './types.ts';

export const BIMI_MAX = 15;

export type BimiData = {
  logoUrl?: string;
  vmcUrl?: string;
  logoSvg?: string;
  logoValid?: boolean;
  /** the logo is only reached through a redirect, which some inboxes refuse */
  logoRedirected?: boolean;
  certValid?: boolean;
  /** no a= tag at all, or one that leads to a valid certificate */
  certOk?: boolean;
  certificate?: { subject: string; issuer: string; validTo: string; expired: boolean };
};

export function checkSvgTinyPs(svg: string): string[] {
  const problems: string[] = [];
  if (!/<svg[\s>]/i.test(svg)) problems.push('The file is not an SVG.');
  if (!/baseProfile\s*=\s*["']tiny-ps["']/i.test(svg)) problems.push('The SVG must declare baseProfile="tiny-ps" (SVG Tiny Portable/Secure).');
  if (!/version\s*=\s*["']1\.2["']/i.test(svg)) problems.push('The SVG should declare version="1.2".');
  if (/<script[\s>]/i.test(svg) || /\son[a-z]+\s*=/i.test(svg)) problems.push('The SVG must not contain scripts or event handlers.');
  if (/<image[\s>]/i.test(svg) && /href\s*=\s*["']https?:/i.test(svg)) problems.push('The SVG must not load external images.');
  return problems;
}

export async function checkBimi(domain: string, dns: DnsClient, dmarc?: DmarcData): Promise<CheckResult<BimiData>> {
  const base = { id: 'bimi', title: 'BIMI', max: BIMI_MAX } as const;
  const res = await attempt(() => dns.txt(`default._bimi.${domain}`));
  if (!res.ok) return { ...base, status: 'unknown', summary: `The BIMI record could not be looked up (${res.error}).`, points: 0, findings: [] };
  const records = res.value.filter((r) => /^v=BIMI1\s*;?/i.test(r.trim()));
  if (records.length === 0) return { ...base, status: 'missing', summary: 'BIMI is not set up, so your logo will not appear next to your email in supporting inboxes.', points: 0, findings: [{ level: 'info', text: 'BIMI shows your brand logo in the inbox. It needs DMARC at p=quarantine or p=reject first.' }] };

  const record = records[0];
  const tags = parseTags(record);
  const findings: Finding[] = [];
  const data: BimiData = { logoUrl: tags.l, vmcUrl: tags.a };
  let points = 0;

  if (!dmarcEnforced(dmarc)) findings.push({ level: 'bad', text: 'BIMI is ignored unless DMARC is enforced (p=quarantine or p=reject at 100%).' });

  if (!tags.l) findings.push({ level: 'bad', text: 'The record has no l= logo URL.' });
  else {
    try {
      const logo = await safeFetch(tags.l, { timeoutMs: 5000, maxBytes: 64 * 1024, accept: 'image/svg+xml', maxRedirects: 3 });
      if (logo.redirected) {
        data.logoRedirected = true;
        findings.push({ level: 'warn', text: `The logo URL redirects to ${logo.finalUrl}. Serve the logo directly from the l= address.` });
      }
      if (logo.status !== 200) findings.push({ level: 'bad', text: `The logo URL returned HTTP ${logo.status}.` });
      else {
        const problems = checkSvgTinyPs(logo.body);
        if (!/svg/i.test(logo.contentType)) problems.push(`The logo is served as "${logo.contentType || 'no content type'}", not image/svg+xml.`);
        if (logo.truncated || Buffer.byteLength(logo.body) > 32 * 1024) problems.push('The logo is larger than the recommended 32 KB.');
        if (problems.length) problems.forEach((p) => findings.push({ level: 'warn', text: p }));
        else findings.push({ level: 'ok', text: 'The logo is a valid SVG Tiny PS image.' });
        points += problems.length ? 4 : 7;
        data.logoSvg = logo.body;
        data.logoValid = problems.length === 0;
      }
    } catch (e) {
      findings.push({ level: 'bad', text: `The logo at ${tags.l} could not be fetched (${e instanceof Error ? e.message : 'error'}).` });
    }
  }

  if (!('a' in tags)) {
    data.certOk = true;
    findings.push({ level: 'info', text: 'No a= certificate (VMC/CMC). Major providers such as Gmail need one before they show the logo.' });
  } else if (!tags.a) findings.push({ level: 'warn', text: 'The a= tag is empty. Remove it, or point it at your mark certificate (VMC/CMC).' });
  else {
    try {
      const cert = await safeFetch(tags.a, { timeoutMs: 5000, maxBytes: 64 * 1024, accept: 'application/x-pem-file,text/plain' });
      const pem = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/.exec(cert.body)?.[0];
      if (cert.status !== 200 || !pem) findings.push({ level: 'bad', text: 'The certificate URL did not return a PEM certificate.' });
      else {
        const x = new X509Certificate(pem);
        const expired = new Date(x.validTo).getTime() < Date.now();
        data.certificate = { subject: x.subject.replace(/\n/g, ', '), issuer: x.issuer.replace(/\n/g, ', '), validTo: x.validTo, expired };
        if (expired) findings.push({ level: 'bad', text: `The certificate expired on ${x.validTo}.` });
        else {
          findings.push({ level: 'ok', text: `Certificate valid until ${x.validTo}.` });
          points += 8;
          data.certValid = true;
          data.certOk = true;
        }
      }
    } catch (e) {
      findings.push({ level: 'bad', text: `The certificate could not be read (${e instanceof Error ? e.message : 'error'}).` });
    }
  }
  if (!dmarcEnforced(dmarc)) points = Math.min(points, 4);
  const status = bimiComplete(data, dmarc) ? 'pass' : data.logoValid ? 'warn' : 'fail';
  const summary = status !== 'pass' ? 'BIMI is published but incomplete.' : data.certValid ? 'BIMI is set up with a valid logo and certificate.' : 'BIMI is set up with a valid logo. Add a mark certificate so Gmail and Apple Mail show it too.';
  return { ...base, status, summary, points, record, findings, data };
}

/** A valid logo served directly, no broken certificate and an enforced DMARC policy. */
export function bimiComplete(data: BimiData | undefined, dmarc?: DmarcData): boolean {
  return !!data?.logoValid && !!data.certOk && !data.logoRedirected && dmarcEnforced(dmarc);
}

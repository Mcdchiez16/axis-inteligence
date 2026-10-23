import { createPublicKey } from 'node:crypto';

import { attempt, type DnsClient } from '../dns.ts';
import { parseTags } from './dmarc.ts';
import type { CheckResult, Finding } from './types.ts';

export const DKIM_MAX = 18;

/** Selectors used by common mail providers and tools. DKIM selectors cannot be listed, so the report probes these. */
export const COMMON_SELECTORS = [
  'default', 'google', 'selector1', 'selector2', 'k1', 'k2', 'k3', 's1', 's2', 'dkim', 'mail', 'email', 'smtp', 'mandrill', 'mxvault', 'zoho', 'pm', 'scph', 'sendgrid', 'm1', 'mailo', 'everlytickey1', 'cm', 'fm1', 'fm2', 'fm3', 'protonmail', 'protonmail2', 'protonmail3', 'zmail', 'x', 'dk', 'ses', 'amazonses',
];

export type DkimKey = { selector: string; record: string; keyType: string; bits?: number; testing: boolean; revoked: boolean };
export type DkimData = { keys: DkimKey[]; probed: number; custom?: string };

export function rsaBits(p: string): number | undefined {
  try {
    const der = Buffer.from(p.replace(/\s+/g, ''), 'base64');
    const pem = `-----BEGIN PUBLIC KEY-----\n${der.toString('base64').replace(/(.{64})/g, '$1\n')}\n-----END PUBLIC KEY-----`;
    return createPublicKey(pem).asymmetricKeyDetails?.modulusLength;
  } catch {
    return undefined;
  }
}

export function parseDkimRecord(selector: string, record: string): DkimKey | null {
  const tags = parseTags(record);
  if (tags.v && tags.v.toUpperCase() !== 'DKIM1') return null;
  if (!('p' in tags)) return null;
  const k = (tags.k ?? 'rsa').toLowerCase();
  const p = tags.p.replace(/\s+/g, '');
  return { selector, record, keyType: k, bits: k === 'rsa' && p ? rsaBits(p) : k === 'ed25519' ? 256 : undefined, testing: /(^|:)y(:|$)/.test(tags.t ?? ''), revoked: p === '' };
}

async function mapLimit<T, R>(items: T[], limit: number, fn: (x: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let i = 0;
  await Promise.all(
    Array.from({ length: Math.min(limit, items.length) }, async () => {
      while (i < items.length) {
        const n = i++;
        out[n] = await fn(items[n]);
      }
    }),
  );
  return out;
}

export async function checkDkim(domain: string, dns: DnsClient, customSelector?: string): Promise<CheckResult<DkimData>> {
  const base: Pick<CheckResult<DkimData>, 'id' | 'title' | 'max'> = { id: 'dkim', title: 'DKIM', max: DKIM_MAX };
  const selectors = [...new Set([...(customSelector ? [customSelector.toLowerCase()] : []), ...COMMON_SELECTORS])];
  const keys: DkimKey[] = [];
  await mapLimit(selectors, 10, async (sel) => {
    const r = await attempt(() => dns.txt(`${sel}._domainkey.${domain}`));
    if (!r.ok) return;
    for (const rec of r.value) {
      const key = parseDkimRecord(sel, rec);
      if (key) keys.push(key);
    }
  });
  keys.sort((a, b) => a.selector.localeCompare(b.selector));
  const data: DkimData = { keys, probed: selectors.length, custom: customSelector };
  const findings: Finding[] = [];

  const live = keys.filter((k) => !k.revoked);
  if (live.length === 0) {
    const text = customSelector
      ? `No valid key was found at ${customSelector}._domainkey.${domain}, or at ${selectors.length - 1} other common selectors.`
      : `No DKIM key was found at ${selectors.length} common selectors. Your provider may use a different selector name; enter it to check it directly.`;
    return { ...base, status: 'missing', summary: 'No DKIM public key was found.', points: 0, findings: [{ level: 'warn', text }], data };
  }

  let best = 0;
  for (const k of live) {
    let pts = 18;
    if (k.keyType === 'rsa') {
      if (k.bits === undefined) {
        pts = 12;
        findings.push({ level: 'warn', text: `${k.selector}: the key could not be read; check the record is not truncated.` });
      } else if (k.bits < 1024) {
        pts = 3;
        findings.push({ level: 'bad', text: `${k.selector}: a ${k.bits}-bit key is trivially breakable. Use 2048 bits.` });
      } else if (k.bits < 2048) {
        findings.push({ level: 'info', text: `${k.selector}: ${k.bits}-bit RSA key. It works, but 2048-bit keys are recommended; rotate when convenient.` });
      } else findings.push({ level: 'ok', text: `${k.selector}: ${k.bits}-bit RSA key.` });
    } else findings.push({ level: 'ok', text: `${k.selector}: ${k.keyType} key.` });
    if (k.testing) {
      pts = Math.min(pts, 10);
      findings.push({ level: 'warn', text: `${k.selector}: t=y marks this key as "testing", so receivers may ignore failures. Remove it when live.` });
    }
    best = Math.max(best, pts);
  }
  for (const k of keys.filter((x) => x.revoked)) findings.push({ level: 'info', text: `${k.selector}: key is revoked (empty p=).` });
  const status = best >= 18 ? 'pass' : 'warn';
  return { ...base, status, summary: `${live.length} DKIM key${live.length === 1 ? '' : 's'} found (${live.map((k) => k.selector).join(', ')}).`, points: best, record: live[0].record, findings, data };
}

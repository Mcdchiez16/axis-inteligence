import type { NextRequest } from 'next/server';

import { fail, rateLimit } from '@/lib/api.ts';
import { evaluateSpf, spfTree } from '@/lib/checks/spf.ts';
import { defaultDns } from '@/lib/dns.ts';
import { InputError, normalizeDomain } from '@/lib/domain.ts';
import { format, parseIp } from '@/lib/net.ts';

/** "Is this IP allowed to send for this address?" Accepts an email address (or a bare domain) and an IP. */
export async function GET(req: NextRequest) {
  const limited = rateLimit(req, 'spf', 30);
  if (limited) return limited;
  try {
    const q = req.nextUrl.searchParams;
    const raw = (q.get('email') ?? q.get('domain') ?? '').trim().slice(0, 254);
    if (raw.includes('@') && !/^[^\s@]+@[^\s@]+$/.test(raw)) throw new InputError('Enter a valid email address');
    const domain = normalizeDomain(raw);
    const sender = raw.includes('@') ? raw.toLowerCase() : `postmaster@${domain}`;
    const ip = parseIp(q.get('ip') ?? '');
    if (!ip) throw new InputError('Enter a valid IPv4 or IPv6 address');
    const dns = defaultDns();
    const [result, tree] = await Promise.all([evaluateSpf({ domain, ip: format(ip), sender }, dns), spfTree(domain, dns)]);
    return Response.json({ domain, sender, ip: format(ip), ...result, tree });
  } catch (e) {
    return fail(e);
  }
}

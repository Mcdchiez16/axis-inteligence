import type { NextRequest } from 'next/server';

import { fail, rateLimit } from '@/lib/api.ts';
import { attempt, defaultDns } from '@/lib/dns.ts';
import { InputError, normalizeDomain } from '@/lib/domain.ts';
import { parseIp, reverseName } from '@/lib/net.ts';

const TYPES = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA', 'CAA', 'PTR'] as const;
type RType = (typeof TYPES)[number];

export async function GET(req: NextRequest) {
  const limited = rateLimit(req, 'dns', 60);
  if (limited) return limited;
  try {
    const raw = (req.nextUrl.searchParams.get('name') ?? '').trim();
    const type = (req.nextUrl.searchParams.get('type') ?? 'ALL').toUpperCase();
    if (type !== 'ALL' && !TYPES.includes(type as RType)) throw new InputError('Unsupported record type');
    const dns = defaultDns();
    const ip = parseIp(raw);
    if (ip) {
      const name = reverseName(ip);
      const r = await attempt(() => dns.ptr(name));
      return Response.json({ name: raw, results: { PTR: r.ok ? r.value : { error: r.error } } });
    }
    const name = normalizeDomain(raw);
    const wanted = (type === 'ALL' ? TYPES.filter((t) => t !== 'PTR') : [type]) as RType[];
    const run = (t: RType) => {
      switch (t) {
        case 'A': return dns.a(name);
        case 'AAAA': return dns.aaaa(name);
        case 'MX': return dns.mx(name);
        case 'TXT': return dns.txt(name);
        case 'NS': return dns.ns(name);
        case 'CNAME': return dns.cname(name);
        case 'SOA': return dns.soa(name);
        case 'CAA': return dns.caa(name);
        case 'PTR': return dns.ptr(name);
      }
    };
    const entries = await Promise.all(wanted.map(async (t) => {
      const r = await attempt(() => run(t) as Promise<unknown>);
      return [t, r.ok ? r.value : { error: r.error }] as const;
    }));
    return Response.json({ name, results: Object.fromEntries(entries) });
  } catch (e) {
    return fail(e);
  }
}

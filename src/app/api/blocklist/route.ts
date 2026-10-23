import type { NextRequest } from 'next/server';

import { fail, rateLimit } from '@/lib/api.ts';
import { checkBlocklists } from '@/lib/blocklist.ts';
import { blocklistDns } from '@/lib/dns.ts';
import { InputError, normalizeDomain } from '@/lib/domain.ts';
import { format, isPrivateOrReserved, parseIp } from '@/lib/net.ts';

export async function GET(req: NextRequest) {
  const limited = rateLimit(req, 'blocklist', 15);
  if (limited) return limited;
  try {
    const raw = (req.nextUrl.searchParams.get('target') ?? '').trim();
    const ip = parseIp(raw);
    if (ip && isPrivateOrReserved(ip)) throw new InputError('That is a private or reserved address; blocklists only track public IPs');
    const target = ip ? format(ip) : normalizeDomain(raw);
    return Response.json(await checkBlocklists(target, blocklistDns()));
  } catch (e) {
    return fail(e);
  }
}

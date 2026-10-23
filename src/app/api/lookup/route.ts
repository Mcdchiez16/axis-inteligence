import type { NextRequest } from 'next/server';

import { fail, rateLimit } from '@/lib/api.ts';
import { defaultDns } from '@/lib/dns.ts';
import { InputError } from '@/lib/domain.ts';
import { lookup, LOOKUP_TYPES, type LookupType } from '@/lib/lookup.ts';
import { readDomainAndSelector } from '@/lib/params.ts';

export async function GET(req: NextRequest) {
  const limited = rateLimit(req, 'lookup', 40);
  if (limited) return limited;
  try {
    const type = (req.nextUrl.searchParams.get('type') ?? 'dns').toLowerCase() as LookupType;
    if (!LOOKUP_TYPES.includes(type)) throw new InputError('Unknown lookup type');
    const { domain, selector } = readDomainAndSelector(req.nextUrl.searchParams);
    return Response.json(await lookup(type, domain, defaultDns(), selector));
  } catch (e) {
    return fail(e);
  }
}

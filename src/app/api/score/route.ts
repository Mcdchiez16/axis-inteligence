import type { NextRequest } from 'next/server';

import { fail, rateLimit } from '@/lib/api.ts';
import { readDomainAndSelector } from '@/lib/params.ts';
import { getReport } from '@/lib/report-cache.ts';

export async function GET(req: NextRequest) {
  const limited = rateLimit(req, 'score', 20);
  if (limited) return limited;
  try {
    const { domain, selector } = readDomainAndSelector(req.nextUrl.searchParams);
    return Response.json(await getReport(domain, selector));
  } catch (e) {
    return fail(e);
  }
}

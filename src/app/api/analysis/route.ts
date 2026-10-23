import type { NextRequest } from 'next/server';

import { analysisDetail } from '@/lib/analysis.ts';
import { fail, rateLimit } from '@/lib/api.ts';
import { readDomainAndSelector } from '@/lib/params.ts';
import { getReport } from '@/lib/report-cache.ts';

export async function GET(req: NextRequest) {
  const limited = rateLimit(req, 'analysis', 20);
  if (limited) return limited;
  try {
    const { domain, selector } = readDomainAndSelector(req.nextUrl.searchParams);
    const report = await getReport(domain, selector);
    return Response.json({ report, detail: await analysisDetail(report) });
  } catch (e) {
    return fail(e);
  }
}

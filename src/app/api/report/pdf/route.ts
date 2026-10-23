import type { NextRequest } from 'next/server';

import { fail, rateLimit } from '@/lib/api.ts';
import { readDomainAndSelector } from '@/lib/params.ts';
import { getReport } from '@/lib/report-cache.ts';
import { reportPdf } from '@/lib/report-pdf.ts';

export async function GET(req: NextRequest) {
  const limited = rateLimit(req, 'pdf', 10);
  if (limited) return limited;
  try {
    const { domain, selector } = readDomainAndSelector(req.nextUrl.searchParams);
    const pdf = await reportPdf(await getReport(domain, selector));
    return new Response(new Uint8Array(pdf), {
      headers: { 'content-type': 'application/pdf', 'content-disposition': `attachment; filename="axis-intelligence-${domain}.pdf"`, 'cache-control': 'no-store' },
    });
  } catch (e) {
    return fail(e);
  }
}

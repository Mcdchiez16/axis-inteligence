import type { NextRequest } from 'next/server';

import { fail, rateLimit } from '@/lib/api.ts';
import { escapeHtml, LeadError, mailConfigured, saveLead, sendMail, validateLead } from '@/lib/leads.ts';

export async function POST(req: NextRequest) {
  const limited = rateLimit(req, 'contact', 5);
  if (limited) return limited;
  try {
    const lead = validateLead((await req.json().catch(() => ({}))) as Record<string, unknown>, 'contact');
    await saveLead(lead);
    if (mailConfigured() && process.env.SALES_EMAIL) {
      await sendMail({ to: process.env.SALES_EMAIL, subject: `New enquiry from ${lead.firstName} ${lead.lastName}`, replyTo: lead.email, text: JSON.stringify(lead, null, 2), html: `<pre>${escapeHtml(JSON.stringify(lead, null, 2))}</pre>` }).catch(() => undefined);
    }
    return Response.json({ saved: true, message: 'Thanks. An Axis Solutions specialist will be in touch shortly.' });
  } catch (e) {
    if (e instanceof LeadError) return Response.json({ error: e.message }, { status: 400 });
    return fail(e);
  }
}

import type { NextRequest } from 'next/server';

import { fail, rateLimit } from '@/lib/api.ts';
import { normalizeDomain } from '@/lib/domain.ts';
import { escapeHtml, LeadError, mailConfigured, saveLead, sendMail, validateLead } from '@/lib/leads.ts';
import { getReport } from '@/lib/report-cache.ts';
import { reportPdf } from '@/lib/report-pdf.ts';
import { RISK_LABEL } from '@/lib/risk.ts';

/** "Email report": records the request and emails the PDF when SMTP is configured. */
export async function POST(req: NextRequest) {
  const limited = rateLimit(req, 'email-report', 5);
  if (limited) return limited;
  try {
    const body = (await req.json().catch(() => ({}))) as Record<string, unknown>;
    const domain = normalizeDomain(String(body.domain ?? ''));
    const lead = validateLead({ ...body, domain }, 'report');
    await saveLead(lead);
    if (!mailConfigured()) {
      return Response.json({ sent: false, saved: true, message: 'Thanks, your details were received. Email delivery is not set up on this server yet, so please use Download report for now.' });
    }
    const report = await getReport(domain);
    const pdf = await reportPdf(report);
    const name = escapeHtml(lead.firstName);
    await sendMail({
      to: lead.email,
      subject: `Your domain security report for ${domain}: ${report.score}/100`,
      text: `Hi ${lead.firstName},\n\nAttached is the Axis Intelligence report for ${domain}. Score: ${report.score}/100 (${RISK_LABEL[report.risk].toLowerCase()} risk).\n\n${report.summary}\n\nAxis Solutions`,
      html: `<p>Hi ${name},</p><p>Attached is the Axis Intelligence report for <strong>${escapeHtml(domain)}</strong>.</p><p style="font-size:20px"><strong>${report.score}/100</strong> · ${RISK_LABEL[report.risk].toLowerCase()} risk</p><p>${escapeHtml(report.summary)}</p><p>Axis Solutions<br>Mobility. Agility. Security.</p>`,
      attachments: [{ filename: `axis-intelligence-${domain}.pdf`, content: pdf }],
    });
    if (process.env.SALES_EMAIL) {
      await sendMail({ to: process.env.SALES_EMAIL, subject: `Report request: ${domain} (${report.score}/100)`, text: JSON.stringify(lead, null, 2), html: `<pre>${escapeHtml(JSON.stringify(lead, null, 2))}</pre>`, replyTo: lead.email }).catch(() => undefined);
    }
    return Response.json({ sent: true, saved: true, message: `The report is on its way to ${lead.email}.` });
  } catch (e) {
    if (e instanceof LeadError) return Response.json({ error: e.message }, { status: 400 });
    return fail(e);
  }
}

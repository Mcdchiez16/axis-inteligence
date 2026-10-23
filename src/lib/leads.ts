import { appendFile, mkdir } from 'node:fs/promises';
import path from 'node:path';

import nodemailer from 'nodemailer';

export type Lead = { kind: 'report' | 'contact'; firstName: string; lastName: string; email: string; phone?: string; company?: string; message?: string; domain?: string; at: string };

export class LeadError extends Error {}

const clean = (v: unknown, max: number) => String(v ?? '').replace(/[\r\n\t]+/g, ' ').trim().slice(0, max);

export function validateLead(body: Record<string, unknown>, kind: Lead['kind']): Lead {
  const lead: Lead = {
    kind,
    firstName: clean(body.firstName, 60),
    lastName: clean(body.lastName, 60),
    email: clean(body.email, 254).toLowerCase(),
    phone: clean(body.phone, 30) || undefined,
    company: clean(body.company, 120) || undefined,
    message: String(body.message ?? '').trim().slice(0, 2000) || undefined,
    domain: clean(body.domain, 253) || undefined,
    at: new Date().toISOString(),
  };
  if (!lead.firstName || !lead.lastName) throw new LeadError('Please enter your first and last name.');
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(lead.email)) throw new LeadError('Please enter a valid email address.');
  if (lead.phone && !/^[+()\d\s.-]{6,30}$/.test(lead.phone)) throw new LeadError('Please enter a valid contact number.');
  return lead;
}

/** Leads are appended to data/leads.jsonl (outside the public folder) so the sales team can follow up. */
export async function saveLead(lead: Lead) {
  const dir = path.join(process.cwd(), 'data');
  await mkdir(dir, { recursive: true });
  await appendFile(path.join(dir, 'leads.jsonl'), JSON.stringify(lead) + '\n', { mode: 0o600 });
}

export function mailConfigured() {
  return !!(process.env.SMTP_HOST && process.env.SMTP_FROM);
}

export async function sendMail(opts: { to: string; subject: string; html: string; text: string; attachments?: { filename: string; content: Buffer }[]; replyTo?: string }) {
  const transport = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT ?? 587),
    secure: Number(process.env.SMTP_PORT ?? 587) === 465,
    auth: process.env.SMTP_USER ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } : undefined,
  });
  await transport.sendMail({ from: process.env.SMTP_FROM, ...opts });
}

export const escapeHtml = (s: string) => s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);

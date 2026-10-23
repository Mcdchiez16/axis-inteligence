'use client';

import { CheckCircle2 } from 'lucide-react';
import { useState } from 'react';

import { Button, ErrorNote, Field, inputClass } from './ui';

/** Contact details form used by "Email report" and "Contact us". */
export function LeadForm({ endpoint, extra, submitLabel, intro, withMessage }: { endpoint: string; extra?: Record<string, string>; submitLabel: string; intro: string; withMessage?: boolean }) {
  const [form, setForm] = useState({ firstName: '', lastName: '', phone: '', email: '', company: '', message: '' });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<string | null>(null);
  const set = (k: keyof typeof form) => (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => setForm((f) => ({ ...f, [k]: e.target.value }));

  if (done) {
    return (
      <div className="flex flex-col items-center gap-3 py-6 text-center">
        <CheckCircle2 className="size-12 text-good" aria-hidden />
        <p className="text-[15px] text-ink">{done}</p>
      </div>
    );
  }

  return (
    <form
      onSubmit={async (e) => {
        e.preventDefault();
        setBusy(true);
        setError(null);
        try {
          const res = await fetch(endpoint, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ ...form, ...extra }) });
          const body = (await res.json().catch(() => ({}))) as { error?: string; message?: string };
          if (!res.ok) throw new Error(body.error ?? 'Something went wrong. Please try again.');
          setDone(body.message ?? 'Thank you.');
        } catch (err) {
          setError((err as Error).message);
        } finally {
          setBusy(false);
        }
      }}
      className="space-y-4">
      <p className="text-sm leading-relaxed text-muted">{intro}</p>
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label="First name"><input required className={inputClass} value={form.firstName} onChange={set('firstName')} autoComplete="given-name" /></Field>
        <Field label="Last name"><input required className={inputClass} value={form.lastName} onChange={set('lastName')} autoComplete="family-name" /></Field>
      </div>
      <Field label="Contact number"><input className={inputClass} value={form.phone} onChange={set('phone')} autoComplete="tel" placeholder="+260 97 123 4567" /></Field>
      <Field label="Email address"><input required type="email" className={inputClass} value={form.email} onChange={set('email')} autoComplete="email" /></Field>
      {withMessage ? (
        <>
          <Field label="Company (optional)"><input className={inputClass} value={form.company} onChange={set('company')} autoComplete="organization" /></Field>
          <Field label="How can we help?"><textarea className={inputClass} rows={4} value={form.message} onChange={set('message')} /></Field>
        </>
      ) : null}
      {error ? <ErrorNote>{error}</ErrorNote> : null}
      <Button type="submit" busy={busy} className="w-full">{submitLabel}</Button>
      <p className="text-center text-xs text-muted">We use these details only to send what you asked for and to follow up if your domain is at risk.</p>
    </form>
  );
}

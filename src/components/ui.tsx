'use client';

import { AlertTriangle, Check, CheckCircle2, Copy, Info, Loader2, XCircle } from 'lucide-react';
import { useState, type ReactNode } from 'react';

export type Level = 'ok' | 'info' | 'warn' | 'bad';
export type Status = 'pass' | 'warn' | 'fail' | 'missing' | 'unknown';

export function Card({ children, className = '' }: { children: ReactNode; className?: string }) {
  return <div className={`card-3d rounded-3xl bg-white ${className}`}>{children}</div>;
}

export function Container({ children, className = '' }: { children: ReactNode; className?: string }) {
  return <div className={`mx-auto w-full max-w-7xl px-4 sm:px-6 ${className}`}>{children}</div>;
}

/** Page title block: the tool's name and a short explanation. */
export function PageIntro({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <Container className="pt-6 sm:pt-10">
      <h1 className="text-[26px] font-extrabold leading-tight tracking-tight text-ink sm:text-[34px]">{title}</h1>
      {children ? <div className="mt-2 max-w-3xl text-[15px] font-semibold leading-relaxed text-muted sm:text-base">{children}</div> : null}
    </Container>
  );
}

export function Field({ label, hint, children }: { label: string; hint?: string; children: ReactNode }) {
  return (
    <label className="block space-y-1.5">
      <span className="text-sm font-extrabold text-ink">{label}</span>
      {children}
      {hint ? <span className="block text-xs font-semibold text-muted">{hint}</span> : null}
    </label>
  );
}

export const inputClass =
  'w-full rounded-2xl border-2 border-line bg-mist px-4 py-3 text-[16px] font-bold text-ink placeholder:font-semibold placeholder:text-muted/70 outline-none transition focus:border-sky-400 focus:bg-white';

type Variant = 'primary' | 'secondary' | 'good' | 'ghost-dark';
const VARIANT: Record<Variant, string> = {
  primary: 'btn-3d edge-red bg-axis-red text-white',
  secondary: 'btn-3d edge-line border-2 border-line bg-white text-ink',
  good: 'btn-3d edge-good bg-good-400 text-white',
  'ghost-dark': 'btn-3d edge-white border-2 border-white/40 bg-transparent text-white',
};

/** Class names for a pressable button, also used on links that look like buttons. */
export const buttonClass = (variant: Variant = 'primary', size: 'md' | 'sm' = 'md') =>
  `${VARIANT[variant]} inline-flex items-center justify-center gap-2 rounded-2xl font-extrabold ${size === 'sm' ? 'px-4 py-2 text-xs' : 'px-6 py-3 text-[15px]'}`;

export function Button({ children, busy, variant = 'primary', size = 'md', className = '', ...rest }: React.ButtonHTMLAttributes<HTMLButtonElement> & { busy?: boolean; variant?: Variant; size?: 'md' | 'sm' }) {
  return (
    <button {...rest} disabled={busy || rest.disabled} className={`${buttonClass(variant, size)} ${className}`}>
      {busy ? <Loader2 className="size-4 animate-spin" aria-hidden /> : null}
      {children}
    </button>
  );
}

const STATUS = {
  pass: { label: 'Pass', cls: 'bg-good-50 text-good ring-good/25', Icon: CheckCircle2 },
  warn: { label: 'Needs attention', cls: 'bg-warn-50 text-warn ring-warn/25', Icon: AlertTriangle },
  fail: { label: 'Fail', cls: 'bg-bad-50 text-bad ring-bad/20', Icon: XCircle },
  missing: { label: 'Missing', cls: 'bg-bad-50 text-bad ring-bad/20', Icon: XCircle },
  unknown: { label: 'Unavailable', cls: 'bg-mist text-muted ring-line-dark', Icon: Info },
} as const;

export function StatusPill({ status }: { status: Status }) {
  const s = STATUS[status];
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-extrabold ring-2 ring-inset ${s.cls}`}>
      <s.Icon className="size-3.5" strokeWidth={2} aria-hidden />
      {s.label}
    </span>
  );
}

export function StatusIcon({ status, className = 'size-5' }: { status: Status; className?: string }) {
  const s = STATUS[status];
  const color = status === 'pass' ? 'text-good' : status === 'warn' ? 'text-warn' : status === 'unknown' ? 'text-muted' : 'text-bad';
  return <s.Icon className={`${className} ${color} shrink-0`} strokeWidth={2} aria-label={s.label} />;
}

const LEVEL = {
  ok: { Icon: CheckCircle2, cls: 'text-good' },
  info: { Icon: Info, cls: 'text-sky' },
  warn: { Icon: AlertTriangle, cls: 'text-warn' },
  bad: { Icon: XCircle, cls: 'text-bad' },
} as const;

export function FindingList({ items }: { items: { level: Level; text: string }[] }) {
  if (!items.length) return null;
  return (
    <ul className="space-y-2.5">
      {items.map((f, i) => {
        const L = LEVEL[f.level];
        return (
          <li key={i} className="flex gap-2.5 text-sm font-semibold leading-relaxed text-ink/85">
            <L.Icon className={`mt-0.5 size-4 shrink-0 ${L.cls}`} strokeWidth={2} aria-hidden />
            <span>{f.text}</span>
          </li>
        );
      })}
    </ul>
  );
}

export function RiskPill({ risk }: { risk: 'low' | 'medium' | 'high' }) {
  const map = { low: 'bg-good-50 text-good', medium: 'bg-warn-50 text-warn', high: 'bg-bad-50 text-bad' } as const;
  const label = { low: 'Low', medium: 'Moderate', high: 'High' } as const;
  return <span className={`rounded-full px-3 py-1 text-xs font-extrabold ${map[risk]}`}>{label[risk]} risk</span>;
}

export function CopyButton({ text, label = 'Copy' }: { text: string; label?: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      type="button"
      onClick={() => {
        void navigator.clipboard?.writeText(text).then(() => {
          setDone(true);
          setTimeout(() => setDone(false), 1500);
        });
      }}
      className={buttonClass(done ? 'good' : 'secondary', 'sm')}>
      {done ? <Check className="size-3.5" strokeWidth={2.5} aria-hidden /> : <Copy className="size-3.5" aria-hidden />}
      {done ? 'Copied' : label}
    </button>
  );
}

export function Code({ children, copy }: { children: string; copy?: boolean }) {
  return (
    <div className="relative">
      <pre className={`${copy ? 'pr-28 ' : ''}overflow-x-auto whitespace-pre-wrap break-all rounded-2xl border-2 border-line bg-mist px-4 py-3.5 font-mono text-[13px] leading-relaxed text-ink/90`}>{children}</pre>
      {copy ? (
        <div className="absolute right-2.5 top-2.5">
          <CopyButton text={children} />
        </div>
      ) : null}
    </div>
  );
}

export function ErrorNote({ children }: { children: ReactNode }) {
  return <p role="alert" className="flex items-start gap-2 rounded-2xl border-2 border-bad/25 bg-bad-50 px-4 py-3 text-sm font-bold text-bad"><XCircle className="mt-0.5 size-4 shrink-0" strokeWidth={2} />{children}</p>;
}

/** Fetch JSON from one of our API routes, turning error bodies into thrown messages. */
export async function getJson<T>(url: string): Promise<T> {
  const res = await fetch(url, { cache: 'no-store' });
  const body = (await res.json().catch(() => ({}))) as T & { error?: string };
  if (!res.ok) throw new Error(body.error ?? `Request failed (${res.status})`);
  return body;
}

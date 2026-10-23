'use client';

import { Info, X } from 'lucide-react';
import { useEffect, useState } from 'react';

import { Button, buttonClass, Card, inputClass } from './ui';

/** "www.example.com" names a website, while email is set up on "example.com": suggest the bare domain. */
function bareDomainFor(input: string): string | null {
  const host = input.trim().toLowerCase().replace(/^[a-z][a-z0-9+.-]*:\/\//, '').replace(/[/?#].*$/, '').replace(/:\d+$/, '').replace(/\.$/, '');
  return /^www\d*\.(.+\..+)$/.exec(host)?.[1] ?? null;
}

/** The domain entry card used by the score and analysis pages. */
export function DomainForm({ initial, busy, onSubmit, withSelector, initialSelector, submitLabel = 'Get your domain score' }: { initial: string; busy: boolean; onSubmit: (domain: string, selector?: string) => void; withSelector?: boolean; initialSelector?: string; submitLabel?: string; dark?: boolean }) {
  const [domain, setDomain] = useState(initial);
  const [selector, setSelector] = useState(initialSelector ?? '');
  const [keepWww, setKeepWww] = useState(false);
  useEffect(() => setDomain(initial), [initial]);

  const bare = keepWww ? null : bareDomainFor(domain);
  const change = (v: string) => {
    setDomain(v);
    setKeepWww(false);
  };
  const run = (d: string) => {
    if (d.trim()) onSubmit(d, selector);
  };

  return (
    <Card className="p-4 sm:p-7">
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (!bare) run(domain);
        }}>
        <div className={`grid gap-4 sm:items-end ${withSelector ? 'sm:grid-cols-[1fr_220px_auto]' : 'sm:grid-cols-[1fr_auto]'}`}>
          <div className="space-y-1.5">
            <label htmlFor="domain" className="text-sm font-extrabold text-ink">Domain name</label>
            <div className="relative">
              <input id="domain" value={domain} onChange={(e) => change(e.target.value)} placeholder="e.g. example.com" autoComplete="off" spellCheck={false} aria-describedby={bare ? 'domain-hint' : undefined} className={`${inputClass} py-3.5 pr-11 text-base ${bare ? 'ring-2 ring-warn/40' : ''}`} />
              {domain ? (
                <button type="button" aria-label="Clear" onClick={() => change('')} className="absolute right-3 top-1/2 -translate-y-1/2 rounded-full p-1 text-muted hover:bg-white hover:text-ink">
                  <X className="size-4" />
                </button>
              ) : null}
            </div>
          </div>
          {withSelector ? (
            <div className="space-y-1.5">
              <label htmlFor="selector" className="text-sm font-semibold text-ink">DKIM selector <span className="font-normal text-muted">(optional)</span></label>
              <input id="selector" value={selector} onChange={(e) => setSelector(e.target.value)} placeholder="e.g. selector1" autoComplete="off" spellCheck={false} className={`${inputClass} py-3.5 text-base`} />
            </div>
          ) : null}
          <Button type="submit" busy={busy} disabled={!!bare} className="h-[56px] px-7">{busy ? 'Checking…' : submitLabel}</Button>
        </div>

        {bare ? (
          <div id="domain-hint" role="status" className="mt-4 flex flex-col gap-3 rounded-2xl border-2 border-warn/30 bg-warn-50 px-4 py-3 text-sm font-semibold text-ink sm:flex-row sm:items-center">
            <p className="flex items-start gap-2 sm:flex-1">
              <Info className="mt-0.5 size-4 shrink-0 text-warn" aria-hidden />
              <span>
                <strong>www</strong> is the website part of a domain. Email security is set up on the main domain, so check <strong>{bare}</strong> instead.
              </span>
            </p>
            <span className="flex shrink-0 flex-wrap items-center gap-3">
              <button type="button" onClick={() => { change(bare); run(bare); }} className={buttonClass('primary', 'sm')}>Use {bare}</button>
              <button type="button" onClick={() => setKeepWww(true)} className={buttonClass('secondary', 'sm')}>Keep www</button>
            </span>
          </div>
        ) : null}
      </form>
    </Card>
  );
}

'use client';

import { Ban, Calculator, Gauge, Globe, KeyRound, LayoutGrid, Mail, ScanSearch, ShieldCheck, X, type LucideIcon } from 'lucide-react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useEffect, useState } from 'react';

type Tab = { href: string; label: string; Icon: LucideIcon; match: (path: string) => boolean };

const TABS: Tab[] = [
  { href: '/', label: 'Score', Icon: Gauge, match: (p) => p === '/' },
  { href: '/domain-analysis', label: 'Analysis', Icon: ScanSearch, match: (p) => p.startsWith('/domain-analysis') },
  { href: '/lookup', label: 'Lookup', Icon: Globe, match: (p) => p.startsWith('/lookup') || p.startsWith('/dns-lookup') },
  { href: '/header-analysis', label: 'Headers', Icon: Mail, match: (p) => p.startsWith('/header-analysis') },
];

const LOOKUPS = ['DNS', 'DMARC', 'SPF', 'DKIM', 'MTA-STS', 'TLS-RPT', 'BIMI'];

const MORE: { href: string; label: string; text: string; Icon: LucideIcon }[] = [
  { href: '/spf-test', label: 'SPF Policy Test', text: 'Would this server pass SPF for your domain?', Icon: ShieldCheck },
  { href: '/blocklist', label: 'Blocklist Lookup', text: 'Is an IP address or domain on a spam list?', Icon: Ban },
  { href: '/cidr', label: 'CIDR Calculator', text: 'Ranges, subnets and address checks.', Icon: Calculator },
  { href: '/dkim-generator', label: 'DKIM Key Generator', text: 'Create a key pair and the DNS record.', Icon: KeyRound },
];

/** The app-style tab bar shown on phones and tablets, with a sheet for the less used tools. */
export function MobileNav() {
  const path = usePathname();
  const [open, setOpen] = useState(false);
  useEffect(() => setOpen(false), [path]);
  useEffect(() => {
    if (!open) return;
    const esc = (e: KeyboardEvent) => e.key === 'Escape' && setOpen(false);
    document.addEventListener('keydown', esc);
    document.body.style.overflow = 'hidden';
    return () => {
      document.removeEventListener('keydown', esc);
      document.body.style.overflow = '';
    };
  }, [open]);

  const moreActive = open || !TABS.some((t) => t.match(path));
  const item = (active: boolean) => `flex flex-col items-center gap-1 py-2 text-[11px] font-bold transition ${active ? 'text-axis-red' : 'text-muted hover:text-ink'}`;
  const pill = (active: boolean) => `grid h-7 w-12 place-items-center rounded-full transition ${active ? 'bg-axis-red-50' : ''}`;

  return (
    <div className="lg:hidden">
      {open ? (
        <div className="fixed inset-0 z-40 bg-ink/40 backdrop-blur-[2px]" onClick={() => setOpen(false)} aria-hidden>
          <div
            role="dialog"
            aria-label="More tools"
            onClick={(e) => e.stopPropagation()}
            className="absolute inset-x-0 bottom-0 max-h-[80dvh] overflow-y-auto rounded-t-3xl bg-white px-4 pt-3 pb-[calc(5.5rem+env(safe-area-inset-bottom))] shadow-[0_-12px_40px_-12px_rgba(31,27,24,0.35)]">
            <div className="mx-auto mb-3 h-1 w-10 rounded-full bg-line-dark" />
            <div className="flex items-center justify-between">
              <h2 className="text-lg font-black text-ink">All tools</h2>
              <button type="button" onClick={() => setOpen(false)} aria-label="Close" className="grid size-9 place-items-center rounded-full text-muted hover:bg-mist hover:text-ink">
                <X className="size-5" strokeWidth={2} />
              </button>
            </div>

            <p className="mt-4 text-xs font-extrabold uppercase tracking-[0.12em] text-muted">Record lookups</p>
            <div className="mt-2 grid grid-cols-4 gap-2">
              {LOOKUPS.map((l) => (
                <Link key={l} href={`/lookup?type=${l.toLowerCase()}`} className="rounded-xl border-2 border-line px-1 py-2 text-center text-xs font-extrabold text-ink transition hover:border-axis-red/30 hover:bg-axis-red-50 hover:text-axis-red">
                  {l}
                </Link>
              ))}
            </div>

            <p className="mt-5 text-xs font-extrabold uppercase tracking-[0.12em] text-muted">More tools</p>
            <ul className="mt-2 divide-y divide-line">
              {MORE.map(({ href, label, text, Icon }) => (
                <li key={href}>
                  <Link href={href} className={`flex items-center gap-3 rounded-xl px-1 py-3 ${path.startsWith(href) ? 'text-axis-red' : 'text-ink'}`}>
                    <span className="grid size-10 shrink-0 place-items-center rounded-xl bg-axis-red-50 text-axis-red"><Icon className="size-5" strokeWidth={1.75} aria-hidden /></span>
                    <span className="min-w-0">
                      <span className="block text-[15px] font-extrabold">{label}</span>
                      <span className="block truncate text-xs font-semibold text-muted">{text}</span>
                    </span>
                  </Link>
                </li>
              ))}
            </ul>
          </div>
        </div>
      ) : null}

      <nav aria-label="Main" className="fixed inset-x-0 bottom-0 z-50 border-t-2 border-line bg-white/95 pb-[env(safe-area-inset-bottom)] backdrop-blur">
        <ul className="mx-auto grid max-w-lg grid-cols-5 px-2">
          {TABS.map(({ href, label, Icon, match }) => {
            const active = !open && match(path);
            return (
              <li key={href}>
                <Link href={href} aria-current={active ? 'page' : undefined} className={item(active)}>
                  <span className={pill(active)}><Icon className="size-5" strokeWidth={active ? 2.25 : 1.75} aria-hidden /></span>
                  {label}
                </Link>
              </li>
            );
          })}
          <li>
            <button type="button" onClick={() => setOpen((o) => !o)} aria-expanded={open} className={`${item(moreActive)} w-full`}>
              <span className={pill(moreActive)}><LayoutGrid className="size-5" strokeWidth={moreActive ? 2.25 : 1.75} aria-hidden /></span>
              More
            </button>
          </li>
        </ul>
      </nav>
    </div>
  );
}

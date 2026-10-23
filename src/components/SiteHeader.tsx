'use client';

import { ChevronDown } from 'lucide-react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useEffect, useRef, useState } from 'react';

import { Brand } from './Brand';
import { NAV, type NavLink } from './nav';

const isActive = (path: string, href: string) => {
  const base = href.split('?')[0];
  return base === '/' ? path === '/' : path.startsWith(base);
};

const tab = (active: boolean) =>
  `flex items-center gap-1 px-1 py-2 text-sm font-bold transition ${active ? 'text-axis-red' : 'text-ink/60 hover:text-ink'}`;

function Dropdown({ label, items, path }: { label: string; items: NavLink[]; path: string }) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLLIElement>(null);
  useEffect(() => {
    const close = (e: MouseEvent) => !ref.current?.contains(e.target as Node) && setOpen(false);
    const esc = (e: KeyboardEvent) => e.key === 'Escape' && setOpen(false);
    document.addEventListener('mousedown', close);
    document.addEventListener('keydown', esc);
    return () => {
      document.removeEventListener('mousedown', close);
      document.removeEventListener('keydown', esc);
    };
  }, []);
  useEffect(() => setOpen(false), [path]);
  const active = items.some((i) => isActive(path, i.href));
  return (
    <li ref={ref} className="relative">
      <button type="button" aria-expanded={open} aria-haspopup="menu" onClick={() => setOpen((o) => !o)} className={tab(active)}>
        {label}
        <ChevronDown className={`size-4 transition ${open ? 'rotate-180' : ''}`} aria-hidden />
      </button>
      {open ? (
        <ul role="menu" className="absolute right-0 top-full z-50 mt-2 min-w-56 overflow-hidden rounded-2xl border border-line bg-white p-1.5 shadow-[0_16px_40px_-16px_rgba(31,27,24,0.28)]">
          {items.map((i) => (
            <li key={i.href} role="none">
              <Link role="menuitem" href={i.href} aria-current={isActive(path, i.href) ? 'page' : undefined} className={`block rounded-xl px-4 py-2.5 text-sm font-bold transition ${isActive(path, i.href) ? 'bg-axis-red-50 text-axis-red' : 'text-ink hover:bg-mist'}`}>
                {i.label}
              </Link>
            </li>
          ))}
        </ul>
      ) : null}
    </li>
  );
}

/** Brand and the tool tabs on wide screens; phones and tablets use the bottom bar in MobileNav. */
export function SiteHeader() {
  const path = usePathname();

  return (
    <header className="sticky top-0 z-40">
      {/* phones and tablets: a plain brand bar; the tabs live in the bottom bar */}
      <div className="border-b-2 border-line bg-white/95 backdrop-blur lg:hidden">
        <div className="mx-auto flex h-14 w-full max-w-7xl items-center px-4 sm:px-6">
          <Link href="/" aria-label="Axis Intelligence home">
            <Brand />
          </Link>
        </div>
      </div>

      {/* desktop: one floating bar, brand on the left, tools on the right */}
      <div className="hidden px-6 pt-4 lg:block">
        <nav aria-label="Tools" className="mx-auto flex h-16 w-full max-w-7xl items-center justify-between gap-8 rounded-2xl border border-line bg-white/90 pl-5 pr-2.5 shadow-[0_10px_34px_-18px_rgba(31,27,24,0.35)] backdrop-blur">
          <Link href="/" aria-label="Axis Intelligence home" className="shrink-0">
            <Brand />
          </Link>
          <ul className="flex items-center gap-7">
            {NAV.map((item) =>
              'items' in item ? (
                <Dropdown key={item.label} label={item.label} items={item.items} path={path} />
              ) : (
                <li key={item.href}>
                  <Link href={item.href} aria-current={isActive(path, item.href) ? 'page' : undefined} className={tab(isActive(path, item.href))}>
                    {item.label}
                  </Link>
                </li>
              ),
            )}
          </ul>
        </nav>
      </div>
    </header>
  );
}

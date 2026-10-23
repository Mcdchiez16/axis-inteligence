import Link from 'next/link';

import { Brand } from './Brand';
import { TOOLS } from './nav';

export function SiteFooter() {
  return (
    <footer className="mt-10 border-t-2 border-line bg-white sm:mt-12">
      <div className="mx-auto flex w-full max-w-7xl flex-col items-center gap-4 px-4 py-7 text-center sm:gap-5 sm:px-6 sm:py-10">
        <Brand />
        <p className="text-sm font-semibold tracking-wide text-ink">Mobility. Agility. Security.</p>
        <ul className="hidden flex-wrap justify-center gap-x-6 gap-y-2 text-sm text-muted lg:flex">
          {TOOLS.map((t) => (
            <li key={t.href}>
              <Link href={t.href} className="hover:text-axis-red">
                {t.label}
              </Link>
            </li>
          ))}
        </ul>
        <p className="text-xs text-muted">
          Copyright © {new Date().getFullYear()} Axis Solutions · <a href="https://axissolafrica.com" className="text-axis-red hover:underline">Website</a> · Nothing you paste into the header, CIDR or DKIM tools leaves your browser.
        </p>
      </div>
    </footer>
  );
}

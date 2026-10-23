import type { Metadata } from 'next';
import { JetBrains_Mono, Nunito } from 'next/font/google';

import { HelpBand } from '@/components/HelpBand';
import { MobileNav } from '@/components/MobileNav';
import { SiteFooter } from '@/components/SiteFooter';
import { SiteHeader } from '@/components/SiteHeader';

import './globals.css';

const nunito = Nunito({ subsets: ['latin'], weight: ['500', '600', '700', '800', '900'], variable: '--font-nunito', display: 'swap' });
const mono = JetBrains_Mono({ subsets: ['latin'], variable: '--font-mono-face', display: 'swap' });

export const metadata: Metadata = {
  title: { default: 'Axis Intelligence: email and domain security', template: '%s · Axis Intelligence' },
  description: 'Check how well your domain is protected against email impersonation, phishing and spoofing. DMARC, SPF, DKIM, MTA-STS, TLS-RPT and BIMI in one report.',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${nunito.variable} ${mono.variable}`}>
      {/* room at the bottom on phones and tablets for the fixed tab bar */}
      <body className="flex min-h-dvh flex-col pb-[calc(4.25rem+env(safe-area-inset-bottom))] font-sans lg:pb-0">
        <SiteHeader />
        <main className="flex-1">{children}</main>
        <HelpBand />
        <SiteFooter />
        <MobileNav />
      </body>
    </html>
  );
}

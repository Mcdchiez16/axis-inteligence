/** Recognise well-known providers from DNS hostnames and report addresses. */

const EMAIL: [RegExp, string][] = [
  [/\.mail\.protection\.outlook\.com$|\.outlook\.com$/, 'Microsoft 365 Exchange'],
  [/(^|\.)google\.com$|(^|\.)googlemail\.com$/, 'Google Workspace'],
  [/\.zoho\.(com|eu|in)$/, 'Zoho Mail'],
  [/\.mimecast\.(com|co\.za)$/, 'Mimecast'],
  [/\.pphosted\.com$|\.ppe-hosted\.com$/, 'Proofpoint'],
  [/\.barracudanetworks\.com$/, 'Barracuda'],
  [/\.messagelabs\.com$/, 'Broadcom (Symantec) Email Security'],
  [/\.iphmx\.com$/, 'Cisco Secure Email'],
  [/\.secureserver\.net$/, 'GoDaddy'],
  [/\.mailgun\.org$/, 'Mailgun'],
  [/amazonaws\.com$|amazonses\.com$/, 'Amazon SES'],
  [/\.protonmail\.ch$/, 'Proton Mail'],
  [/\.icloud\.com$/, 'iCloud Mail'],
  [/\.yandex\.(net|ru)$/, 'Yandex 360'],
  [/\.mx\.cloudflare\.net$/, 'Cloudflare Email Routing'],
  [/\.afrihost\.co\.za$/, 'Afrihost'],
  [/\.hostinger\.com$/, 'Hostinger'],
];

const DNS: [RegExp, string][] = [
  [/\.ns\.cloudflare\.com$/, 'Cloudflare'],
  [/awsdns/, 'Amazon Route 53'],
  [/\.domaincontrol\.com$/, 'GoDaddy'],
  [/\.azure-dns\./, 'Azure DNS'],
  [/\.googledomains\.com$|ns-cloud-[a-z]\d*\.googledomains\.com$|\.google\.com$/, 'Google Cloud DNS'],
  [/\.registrar-servers\.com$/, 'Namecheap'],
  [/\.nsone\.net$/, 'NS1'],
  [/\.ultradns\./, 'UltraDNS'],
  [/\.dnsmadeeasy\.com$/, 'DNS Made Easy'],
  [/\.akam\.net$/, 'Akamai'],
  [/\.ns\.joker\.com$/, 'Joker'],
  [/\.afrihost\.co\.za$/, 'Afrihost'],
  [/\.hostinger\.com$/, 'Hostinger'],
  [/\.sendmarc\.net$/, 'Sendmarc'],
  [/\.digitalocean\.com$/, 'DigitalOcean'],
  [/\.linode\.com$/, 'Linode'],
];

const REPORTS: [RegExp, string][] = [
  [/sdmarc\.net$|sendmarc\.net$|sendmarc\.com$/, 'Sendmarc'],
  [/dmarcian\.com$|dmarcian\.eu$/, 'dmarcian'],
  [/valimail\.com$/, 'Valimail'],
  [/agari\.com$/, 'Agari'],
  [/ondmarc\.com$|redsift\.cloud$/, 'Red Sift OnDMARC'],
  [/easydmarc\.(com|us|eu)$/, 'EasyDMARC'],
  [/postmarkapp\.com$/, 'Postmark'],
  [/uriports\.com$/, 'URIports'],
  [/dmarc-reports\.cloudflare\.net$/, 'Cloudflare'],
  [/powerdmarc\.com$/, 'PowerDMARC'],
  [/mailhardener\.com$/, 'Mailhardener'],
  [/report-uri\.com$/, 'Report URI'],
  [/proofpoint\.com$/, 'Proofpoint'],
  [/mimecast\.(com|report)$/, 'Mimecast'],
  [/google\.com$/, 'Google'],
];

const match = (host: string, table: [RegExp, string][]) => table.find(([re]) => re.test(host.toLowerCase().replace(/\.$/, '')))?.[1];

export function emailProvider(mxHosts: string[]): string {
  for (const h of mxHosts) {
    const m = match(h, EMAIL);
    if (m) return m;
  }
  return mxHosts.length ? 'Unknown' : 'None';
}

export function dnsProvider(nsHosts: string[]): string {
  for (const h of nsHosts) {
    const m = match(h, DNS);
    if (m) return m;
  }
  return 'Unknown';
}

/** Who receives the reports: a known service, or "Self-managed" when they go to the domain itself. */
export function reportProviders(uris: string[], domain: string, orgDomain: string): string[] {
  const out = new Set<string>();
  for (const u of uris) {
    const host = /^mailto:[^@]+@(.+)$/i.exec(u)?.[1] ?? (() => { try { return new URL(u).hostname; } catch { return ''; } })();
    if (!host) continue;
    const h = host.toLowerCase();
    const known = match(h, REPORTS);
    if (known) out.add(known);
    else if (h === domain || h === orgDomain || h.endsWith('.' + orgDomain)) out.add('Self-managed');
    else out.add(h);
  }
  return [...out];
}

export type NavLink = { href: string; label: string };
export type NavItem = NavLink | { label: string; items: NavLink[] };

export const NAV: NavItem[] = [
  { href: '/', label: 'Know Your Score' },
  { href: '/domain-analysis', label: 'Domain Analysis' },
  {
    label: 'Lookup',
    items: [
      { href: '/lookup?type=dns', label: 'DNS' },
      { href: '/lookup?type=dmarc', label: 'DMARC' },
      { href: '/lookup?type=spf', label: 'SPF' },
      { href: '/lookup?type=dkim', label: 'DKIM' },
      { href: '/lookup?type=mta-sts', label: 'MTA-STS' },
      { href: '/lookup?type=tls-rpt', label: 'TLS-RPT' },
      { href: '/lookup?type=bimi', label: 'BIMI' },
      { href: '/blocklist', label: 'Blocklist' },
    ],
  },
  { href: '/header-analysis', label: 'Header Analysis' },
  { href: '/spf-test', label: 'SPF Policy Test' },
  {
    label: 'More Tools',
    items: [
      { href: '/cidr', label: 'CIDR Calculator' },
      { href: '/dkim-generator', label: 'DKIM Key Generator' },
    ],
  },
];

export const TOOLS: NavLink[] = [
  { href: '/', label: 'Know Your Score' },
  { href: '/domain-analysis', label: 'Domain Analysis' },
  { href: '/lookup', label: 'Lookup' },
  { href: '/blocklist', label: 'Blocklist Lookup' },
  { href: '/header-analysis', label: 'Header Analysis' },
  { href: '/spf-test', label: 'SPF Policy Test' },
  { href: '/cidr', label: 'CIDR Calculator' },
  { href: '/dkim-generator', label: 'DKIM Key Generator' },
];

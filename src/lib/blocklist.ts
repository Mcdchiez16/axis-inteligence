import { attempt, type DnsClient } from './dns.ts';
import { dnsblLabel, format, parseIp, type ParsedIp } from './net.ts';

export type Zone = { zone: string; name: string; kind: 'ip' | 'domain'; ipv6?: boolean; info: string };

/** Public blocklists. Several (notably Spamhaus) refuse queries from big public resolvers; see README. */
export const ZONES: Zone[] = [
  { zone: 'zen.spamhaus.org', name: 'Spamhaus ZEN', kind: 'ip', ipv6: true, info: 'https://check.spamhaus.org/' },
  { zone: 'b.barracudacentral.org', name: 'Barracuda', kind: 'ip', info: 'https://www.barracudacentral.org/lookups' },
  { zone: 'bl.spamcop.net', name: 'SpamCop', kind: 'ip', info: 'https://www.spamcop.net/bl.shtml' },
  { zone: 'psbl.surriel.com', name: 'PSBL', kind: 'ip', info: 'https://psbl.org/' },
  { zone: 'dnsbl-1.uceprotect.net', name: 'UCEPROTECT L1', kind: 'ip', info: 'https://www.uceprotect.net/' },
  { zone: 'dnsbl.dronebl.org', name: 'DroneBL', kind: 'ip', info: 'https://dronebl.org/' },
  { zone: 'all.s5h.net', name: 's5h', kind: 'ip', info: 'https://www.usenix.org.uk/content/rbl.html' },
  { zone: 'ix.dnsbl.manitu.net', name: 'NiX Spam', kind: 'ip', info: 'https://www.dnsbl.manitu.net/' },
  { zone: 'dbl.spamhaus.org', name: 'Spamhaus DBL', kind: 'domain', info: 'https://check.spamhaus.org/' },
  { zone: 'multi.surbl.org', name: 'SURBL', kind: 'domain', info: 'https://www.surbl.org/' },
  { zone: 'multi.uribl.com', name: 'URIBL', kind: 'domain', info: 'https://admin.uribl.com/' },
];

export type ZoneResult = { zone: string; name: string; target: string; status: 'listed' | 'clear' | 'error' | 'refused'; codes: string[]; reason?: string; info: string };

/** Answers that mean "you may not query us from here", not "listed". */
function refusal(codes: string[]): boolean {
  return codes.some((c) => c.startsWith('127.255.255.') || c === '127.0.0.255' || c === '127.0.1.255');
}

async function query(dns: DnsClient, label: string, z: Zone, target: string): Promise<ZoneResult> {
  const name = `${label}.${z.zone}`;
  const r = await attempt(() => dns.a(name));
  if (!r.ok) return { zone: z.zone, name: z.name, target, status: 'error', codes: [], info: z.info };
  const codes = r.value.filter((c) => c.startsWith('127.'));
  if (!codes.length) return { zone: z.zone, name: z.name, target, status: 'clear', codes: [], info: z.info };
  if (refusal(codes)) return { zone: z.zone, name: z.name, target, status: 'refused', codes, reason: 'This list refused the query (public resolver or rate limit).', info: z.info };
  const txt = await attempt(() => dns.txt(name));
  return { zone: z.zone, name: z.name, target, status: 'listed', codes, reason: txt.ok ? txt.value[0] : undefined, info: z.info };
}

export async function checkBlocklists(target: string, dns: DnsClient): Promise<{ target: string; ips: string[]; results: ZoneResult[] }> {
  const ip = parseIp(target);
  const results: Promise<ZoneResult>[] = [];
  const ips: ParsedIp[] = [];
  if (ip) ips.push(ip);
  else {
    const [a, aaaa] = await Promise.all([attempt(() => dns.a(target)), attempt(() => dns.aaaa(target))]);
    for (const x of [...(a.ok ? a.value : []), ...(aaaa.ok ? aaaa.value : [])].slice(0, 4)) {
      const p = parseIp(x);
      if (p) ips.push(p);
    }
    for (const z of ZONES.filter((z) => z.kind === 'domain')) results.push(query(dns, target, z, target));
  }
  for (const p of ips) {
    for (const z of ZONES.filter((z) => z.kind === 'ip' && (p.family === 4 || z.ipv6))) {
      results.push(query(dns, dnsblLabel(p), z, format(p)));
    }
  }
  const all = await Promise.all(results);
  return { target, ips: ips.map(format), results: all };
}

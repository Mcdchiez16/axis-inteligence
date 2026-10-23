import type { DnsClient, MxRecord } from '../src/lib/dns.ts';

/** In-memory DNS for tests. Keys are lower-case names. */
export function fakeDns(zone: { txt?: Record<string, string[]>; mx?: Record<string, MxRecord[]>; a?: Record<string, string[]>; aaaa?: Record<string, string[]>; cname?: Record<string, string[]> }): DnsClient & { queries: string[] } {
  const queries: string[] = [];
  const get = <T>(m: Record<string, T[]> | undefined, n: string, type: string): Promise<T[]> => {
    queries.push(`${type} ${n}`);
    return Promise.resolve(m?.[n.toLowerCase()] ?? []);
  };
  return {
    queries,
    txt: (n) => get(zone.txt, n, 'TXT'),
    mx: (n) => get(zone.mx, n, 'MX'),
    a: (n) => get(zone.a, n, 'A'),
    aaaa: (n) => get(zone.aaaa, n, 'AAAA'),
    cname: (n) => get(zone.cname, n, 'CNAME'),
    ns: () => Promise.resolve([]),
    ptr: () => Promise.resolve([]),
    soa: () => Promise.resolve(null),
    caa: () => Promise.resolve([]),
  };
}

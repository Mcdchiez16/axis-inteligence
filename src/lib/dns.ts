import { Resolver } from 'node:dns/promises';

import { dohQuery } from './doh.ts';

export type MxRecord = { priority: number; exchange: string };
export type SoaRecord = { nsname: string; hostmaster: string; serial: number; refresh: number; retry: number; expire: number; minttl: number };
export type CaaRecord = { critical: number; issue?: string; issuewild?: string; iodef?: string };

/** A DNS failure that is not simply "the name does not exist" (timeout, SERVFAIL, refused...). */
export class DnsError extends Error {
  code: string;
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}

/** The DNS operations the checks need. Tests supply an in-memory implementation. */
export interface DnsClient {
  txt(name: string): Promise<string[]>;
  mx(name: string): Promise<MxRecord[]>;
  a(name: string): Promise<string[]>;
  aaaa(name: string): Promise<string[]>;
  cname(name: string): Promise<string[]>;
  ns(name: string): Promise<string[]>;
  ptr(name: string): Promise<string[]>;
  soa(name: string): Promise<SoaRecord | null>;
  caa(name: string): Promise<CaaRecord[]>;
}

const EMPTY = new Set(['ENOTFOUND', 'ENODATA', 'NXDOMAIN', 'NODATA']);

function make(servers?: string[]): DnsClient {
  const resolver = new Resolver({ timeout: 4000, tries: 2 });
  if (servers && servers.length) resolver.setServers(servers);

  // "No such name" and "no records of this type" are normal answers (an empty list); anything else is a real failure.
  async function run<T>(fn: () => Promise<T>, empty: T): Promise<T> {
    try {
      return await fn();
    } catch (e) {
      const code = (e as NodeJS.ErrnoException).code ?? 'EUNKNOWN';
      if (EMPTY.has(code)) return empty;
      throw new DnsError(code, `DNS ${code}`);
    }
  }

  return {
    txt: (n) => run(async () => (await resolver.resolveTxt(n)).map((parts) => parts.join('')), []),
    mx: (n) => run(() => resolver.resolveMx(n).then((r) => r.map((x) => ({ priority: x.priority, exchange: x.exchange.toLowerCase().replace(/\.$/, '') }))), []),
    a: (n) => run(() => resolver.resolve4(n), []),
    aaaa: (n) => run(() => resolver.resolve6(n), []),
    cname: (n) => run(() => resolver.resolveCname(n), []),
    ns: (n) => run(() => resolver.resolveNs(n), []),
    ptr: (n) => run(() => resolver.resolvePtr(n), []),
    soa: (n) => run(() => resolver.resolveSoa(n) as Promise<SoaRecord | null>, null),
    caa: (n) => run(() => resolver.resolveCaa(n) as Promise<CaaRecord[]>, []),
  };
}

/**
 * DNS over HTTPS. Plain DNS (UDP port 53) is often intercepted or rewritten by networks and ISPs, which made
 * some domains appear and disappear between runs; an encrypted lookup gets the same answer every checker sees.
 */
export function dohDns(): DnsClient {
  async function q(name: string, type: Parameters<typeof dohQuery>[1]): Promise<string[]> {
    const r = await dohQuery(name, type);
    if (r.status === 'error') throw new DnsError('EDOH', 'DNS over HTTPS failed');
    return r.records.map((x) => x.data);
  }
  const host = (s: string) => s.toLowerCase().replace(/\.$/, '');
  return {
    txt: (n) => q(n, 'TXT'),
    mx: async (n) =>
      (await q(n, 'MX')).map((d) => {
        const [p, ...rest] = d.split(/\s+/);
        return { priority: Number(p), exchange: host(rest.join(' ')) };
      }),
    a: (n) => q(n, 'A'),
    aaaa: (n) => q(n, 'AAAA'),
    cname: async (n) => (await q(n, 'CNAME')).map(host),
    ns: async (n) => (await q(n, 'NS')).map(host),
    ptr: async (n) => (await q(n, 'PTR')).map(host),
    soa: async (n) => {
      const [d] = await q(n, 'SOA');
      if (!d) return null;
      const [nsname, hostmaster, serial, refresh, retry, expire, minttl] = d.split(/\s+/);
      return { nsname: host(nsname), hostmaster: host(hostmaster), serial: Number(serial), refresh: Number(refresh), retry: Number(retry), expire: Number(expire), minttl: Number(minttl) };
    },
    caa: async (n) =>
      (await q(n, 'CAA')).map((d) => {
        const m = /^(\d+)\s+(\w+)\s+"?([^"]*)"?$/.exec(d);
        return m ? { critical: Number(m[1]), [m[2].toLowerCase()]: m[3] } : { critical: 0 };
      }),
  };
}

/** Use `primary`, and only when it fails outright (not "no such record") ask `fallback`. */
function withFallback(primary: DnsClient, fallback: DnsClient): DnsClient {
  const wrap = <K extends keyof DnsClient>(k: K) =>
    (async (n: string) => {
      try {
        return await (primary[k] as (n: string) => Promise<unknown>)(n);
      } catch {
        return (fallback[k] as (n: string) => Promise<unknown>)(n);
      }
    }) as DnsClient[K];
  return { txt: wrap('txt'), mx: wrap('mx'), a: wrap('a'), aaaa: wrap('aaaa'), cname: wrap('cname'), ns: wrap('ns'), ptr: wrap('ptr'), soa: wrap('soa'), caa: wrap('caa') };
}

let shared: DnsClient | null = null;

/**
 * The default resolver: DNS over HTTPS (DOH_URL, Cloudflare by default) with the system resolver as a fallback.
 * Set DNS_SERVERS (comma separated) to use specific plain DNS servers instead.
 */
export function defaultDns(): DnsClient {
  if (!shared) {
    const servers = (process.env.DNS_SERVERS ?? '').split(',').map((s) => s.trim()).filter(Boolean);
    shared = servers.length ? make(servers) : withFallback(dohDns(), make());
  }
  return shared;
}

/**
 * A dedicated resolver for blocklist queries. DNSBLs refuse large public resolvers (including DNS over HTTPS
 * services), so this uses plain DNS: the system's, or DNSBL_RESOLVERS when set.
 */
let blocklistClient: DnsClient | null = null;
export function blocklistDns(): DnsClient {
  if (!blocklistClient) {
    const servers = (process.env.DNSBL_RESOLVERS ?? '').split(',').map((s) => s.trim()).filter(Boolean);
    blocklistClient = make(servers);
  }
  return blocklistClient;
}

/** Runs a lookup and turns failures into `undefined` plus a note, so one failing record never breaks a whole report. */
export async function attempt<T>(fn: () => Promise<T>): Promise<{ ok: true; value: T } | { ok: false; error: string }> {
  try {
    return { ok: true, value: await fn() };
  } catch (e) {
    return { ok: false, error: e instanceof DnsError ? e.code : 'ERROR' };
  }
}

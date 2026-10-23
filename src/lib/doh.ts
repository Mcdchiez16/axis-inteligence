/**
 * Detailed DNS answers (with TTLs and CNAME chains) for the Lookup tool and the domain analysis.
 * Uses DNS-over-HTTPS JSON (Cloudflare by default, set DOH_URL to change). The node resolver used by
 * the checks does not expose TTLs for most record types, which is why this exists.
 */

export type RR = { name: string; type: string; ttl?: number; data: string };
export type Answer = { status: 'ok' | 'nxdomain' | 'error'; records: RR[]; chain: RR[] };

const TYPE_NUM: Record<string, number> = { A: 1, NS: 2, CNAME: 5, SOA: 6, PTR: 12, MX: 15, TXT: 16, AAAA: 28, SRV: 33, CAA: 257 };
const NUM_TYPE = Object.fromEntries(Object.entries(TYPE_NUM).map(([k, v]) => [v, k]));

/** TXT data arrives as one or more quoted strings; join them back into the record value. */
export function unquoteTxt(data: string): string {
  const parts = [...data.matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((m) => m[1].replace(/\\(\d{3})/g, (_, d) => String.fromCharCode(Number(d))).replace(/\\(.)/g, '$1'));
  return parts.length ? parts.join('') : data;
}

/** Some resolvers return CAA in RFC 3597 generic form: "\# 19 00 05 69 73 ...". */
export function decodeCaa(data: string): string {
  const m = /^\\#\s+\d+\s+([0-9a-f\s]+)$/i.exec(data.trim());
  if (!m) return data;
  const bytes = m[1].trim().split(/\s+/).join('').match(/../g)!.map((h) => parseInt(h, 16));
  const flags = bytes[0];
  const tagLen = bytes[1];
  const tag = String.fromCharCode(...bytes.slice(2, 2 + tagLen));
  const value = String.fromCharCode(...bytes.slice(2 + tagLen));
  return `${flags} ${tag} "${value}"`;
}

export async function dohQuery(name: string, type: keyof typeof TYPE_NUM): Promise<Answer> {
  const base = process.env.DOH_URL ?? 'https://cloudflare-dns.com/dns-query';
  try {
    const res = await fetch(`${base}?name=${encodeURIComponent(name)}&type=${type}`, { headers: { accept: 'application/dns-json' }, signal: AbortSignal.timeout(5000), cache: 'no-store' });
    if (!res.ok) return { status: 'error', records: [], chain: [] };
    const json = (await res.json()) as { Status: number; Answer?: { name: string; type: number; TTL: number; data: string }[] };
    if (json.Status === 3) return { status: 'nxdomain', records: [], chain: [] };
    if (json.Status !== 0) return { status: 'error', records: [], chain: [] };
    const all: RR[] = (json.Answer ?? []).map((a) => {
      const t = NUM_TYPE[a.type] ?? String(a.type);
      let data = a.data;
      if (t === 'TXT') data = unquoteTxt(data);
      if (t === 'CAA') data = decodeCaa(data);
      return { name: a.name.replace(/\.$/, ''), type: t, ttl: a.TTL, data: data.replace(/\.$/, t === 'TXT' ? '.' : '') };
    });
    return { status: 'ok', records: all.filter((r) => r.type === type), chain: type === 'CNAME' ? [] : all.filter((r) => r.type === 'CNAME') };
  } catch {
    return { status: 'error', records: [], chain: [] };
  }
}

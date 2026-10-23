import { COMMON_SELECTORS, parseDkimRecord } from './checks/dkim.ts';
import { parseMtaStsPolicy } from './checks/mtasts.ts';
import { QUALIFIER_TEXT, spfTree, type SpfTree } from './checks/spf.ts';
import type { DnsClient } from './dns.ts';
import { dohQuery, type Answer, type RR } from './doh.ts';
import { safeFetch } from './safe-fetch.ts';

export const LOOKUP_TYPES = ['dns', 'dmarc', 'spf', 'dkim', 'mta-sts', 'tls-rpt', 'bimi'] as const;
export type LookupType = (typeof LOOKUP_TYPES)[number];

export type RecordLookup = { name: string; redirect?: RR; records: RR[]; status: Answer['status'] };
export type LookupResult =
  | { type: 'dns'; domain: string; sections: { type: string; status: Answer['status']; records: RR[] }[] }
  | { type: 'dmarc' | 'tls-rpt' | 'bimi'; domain: string; lookup: RecordLookup }
  | { type: 'mta-sts'; domain: string; lookup: RecordLookup; policy?: { url: string; status: number; body: string; mode?: string; mx: string[]; maxAge?: number; error?: string } }
  | { type: 'spf'; domain: string; tree: SpfTree; allText?: string }
  | { type: 'dkim'; domain: string; selector?: string; requested?: RecordLookup; known: { selector: string; record: string; keyType: string; bits?: number }[]; ns: RR[] };

async function record(name: string, filter: RegExp): Promise<RecordLookup> {
  const a = await dohQuery(name, 'TXT');
  return { name, redirect: a.chain[0], records: a.records.filter((r) => filter.test(r.data)), status: a.status };
}

export async function lookup(type: LookupType, domain: string, dns: DnsClient, selector?: string): Promise<LookupResult> {
  switch (type) {
    case 'dns': {
      const types = ['A', 'AAAA', 'TXT', 'MX', 'NS', 'CNAME', 'CAA', 'SOA', 'SRV'] as const;
      const answers = await Promise.all(types.map((t) => dohQuery(domain, t)));
      return { type, domain, sections: types.map((t, i) => ({ type: t, status: answers[i].status, records: answers[i].records })) };
    }
    case 'dmarc':
      return { type, domain, lookup: await record(`_dmarc.${domain}`, /^v=DMARC1/i) };
    case 'tls-rpt':
      return { type, domain, lookup: await record(`_smtp._tls.${domain}`, /^v=TLSRPTv1/i) };
    case 'bimi':
      return { type, domain, lookup: await record(`default._bimi.${domain}`, /^v=BIMI1/i) };
    case 'mta-sts': {
      const rec = await record(`_mta-sts.${domain}`, /^v=STSv1/i);
      const url = `https://mta-sts.${domain}/.well-known/mta-sts.txt`;
      let policy: Extract<LookupResult, { type: 'mta-sts' }>['policy'];
      if (rec.records.length) {
        try {
          const r = await safeFetch(url, { maxBytes: 64 * 1024, accept: 'text/plain' });
          const p = parseMtaStsPolicy(r.body);
          policy = { url, status: r.status, body: r.body.slice(0, 4000), mode: p.mode, mx: p.mx, maxAge: p.maxAge };
        } catch (e) {
          policy = { url, status: 0, body: '', mx: [], error: e instanceof Error ? e.message : 'Could not fetch the policy' };
        }
      }
      return { type, domain, lookup: rec, policy };
    }
    case 'spf': {
      const tree = await spfTree(domain, dns);
      return { type, domain, tree, allText: tree.all ? QUALIFIER_TEXT[tree.all] : undefined };
    }
    case 'dkim': {
      const requested = selector ? await record(`${selector}._domainkey.${domain}`, /p=/i) : undefined;
      const probes = await Promise.all(COMMON_SELECTORS.map(async (s) => ({ s, a: await dohQuery(`${s}._domainkey.${domain}`, 'TXT') })));
      const known = probes.flatMap(({ s, a }) => a.records.map((r) => parseDkimRecord(s, r.data)).filter((k): k is NonNullable<typeof k> => !!k).map((k) => ({ selector: k.selector, record: k.record, keyType: k.keyType, bits: k.bits })));
      const ns = (await dohQuery(domain, 'NS')).records;
      return { type, domain, selector, requested, known, ns };
    }
  }
}

import { dohQuery, type RR } from './doh.ts';
import type { DomainReport } from './score.ts';

export type AnalysisDetail = {
  redirects: { dmarc?: RR; mtasts?: RR; tlsrpt?: RR; bimi?: RR };
  ns: RR[];
  mx: RR[];
  dnsAdmin?: string;
  mailSending: boolean;
};

/** SOA "rname" is an email address written with dots: hostmaster.example.com -> hostmaster@example.com */
export function soaAdmin(soaData: string): string | undefined {
  const rname = soaData.split(/\s+/)[1]?.replace(/\.$/, '');
  if (!rname) return undefined;
  const i = rname.search(/(?<!\\)\./);
  return i > 0 ? `${rname.slice(0, i).replace(/\\\./g, '.')}@${rname.slice(i + 1)}` : rname;
}

/** Extra facts for the Domain Analysis page: CNAME redirects (delegated records), TTLs and the DNS admin. */
export async function analysisDetail(report: DomainReport): Promise<AnalysisDetail> {
  const d = report.domain;
  const [dmarc, mtasts, tlsrpt, bimi, ns, mx, soa] = await Promise.all([
    dohQuery(`_dmarc.${d}`, 'TXT'),
    dohQuery(`_mta-sts.${d}`, 'TXT'),
    dohQuery(`_smtp._tls.${d}`, 'TXT'),
    dohQuery(`default._bimi.${d}`, 'TXT'),
    dohQuery(d, 'NS'),
    dohQuery(d, 'MX'),
    dohQuery(d, 'SOA'),
  ]);
  return {
    redirects: { dmarc: dmarc.chain[0], mtasts: mtasts.chain[0], tlsrpt: tlsrpt.chain[0], bimi: bimi.chain[0] },
    ns: ns.records,
    mx: mx.records,
    dnsAdmin: soa.records[0] ? soaAdmin(soa.records[0].data) : undefined,
    mailSending: report.mailMode === 'mail',
  };
}

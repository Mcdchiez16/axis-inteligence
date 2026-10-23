import { ttlCache } from './api.ts';
import { defaultDns } from './dns.ts';
import { analyseDomain, type DomainReport } from './score.ts';

const cache = ttlCache<DomainReport>(5 * 60_000);

/** One cached report per domain (and DKIM selector) for five minutes, shared by every route. */
export async function getReport(domain: string, selector?: string): Promise<DomainReport> {
  const key = `${domain}|${selector ?? ''}`;
  const hit = cache.get(key);
  if (hit) return hit;
  const report = await analyseDomain(domain, defaultDns(), { dkimSelector: selector || undefined });
  cache.set(key, report);
  return report;
}

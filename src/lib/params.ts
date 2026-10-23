import { InputError, normalizeDomain } from './domain.ts';

export function readDomainAndSelector(q: URLSearchParams) {
  const domain = normalizeDomain(q.get('domain') ?? '');
  const selector = (q.get('selector') ?? '').trim().toLowerCase();
  if (selector && !/^[a-z0-9]([a-z0-9._-]{0,62})$/.test(selector)) throw new InputError('The DKIM selector can only contain letters, numbers, dots, dashes and underscores');
  return { domain, selector: selector || undefined };
}

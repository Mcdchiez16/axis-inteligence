import { domainToASCII } from 'node:url';
import { getDomain } from 'tldts';

const LABEL = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/;

export class InputError extends Error {}

/** Lower-cases, strips schemes/paths/emails and converts IDNs to punycode. Throws InputError if it is not a valid hostname. */
export function normalizeDomain(input: string): string {
  let d = String(input ?? '').trim().toLowerCase();
  d = d.replace(/^[a-z][a-z0-9+.-]*:\/\//, '').replace(/^.*@/, '').replace(/[/?#].*$/, '').replace(/:\d+$/, '').replace(/\.$/, '');
  if (!d) throw new InputError('Enter a domain name, for example example.com');
  const ascii = domainToASCII(d);
  if (!ascii || ascii.length > 253) throw new InputError('That does not look like a valid domain name');
  const labels = ascii.split('.');
  if (labels.length < 2 || !labels.every((l) => LABEL.test(l))) throw new InputError('That does not look like a valid domain name');
  if (/^\d+$/.test(labels[labels.length - 1])) throw new InputError('Enter a domain name, not an IP address');
  return ascii;
}

/** The registrable ("organizational") domain, e.g. mail.example.co.uk -> example.co.uk. */
export function organizationalDomain(domain: string): string {
  return getDomain(domain) ?? domain;
}

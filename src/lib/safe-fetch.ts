import { lookup } from 'node:dns';
import { isIP } from 'node:net';
import { Agent, fetch } from 'undici';

import { isPrivateOrReserved, parseIp } from './net.ts';

export class UnsafeUrlError extends Error {}

export type SafeResponse = { status: number; contentType: string; body: string; finalUrl: string; truncated: boolean; redirected: boolean };

// Every connection goes through this lookup, so the address that is checked is the address that is used
// (no gap for a DNS-rebinding trick between "check" and "connect").
const agent = new Agent({
  connect: {
    lookup: (hostname, options, callback) => {
      lookup(hostname, { ...options, all: true }, (err, addresses) => {
        if (err) return callback(err, '', 0);
        const list = (addresses as { address: string; family: number }[]).filter((a) => {
          const ip = parseIp(a.address);
          return ip && !isPrivateOrReserved(ip);
        });
        if (!list.length) return callback(new UnsafeUrlError('Address is not allowed'), '', 0);
        const first = list[0];
        if ((options as { all?: boolean }).all) return (callback as unknown as (e: null, a: unknown) => void)(null, list);
        return callback(null, first.address, first.family);
      });
    },
  },
});

/**
 * Fetch a URL on behalf of a visitor, safely: https only, no private addresses, short timeout and a
 * hard cap on the size read. Redirects are not followed unless `maxRedirects` allows it, and every hop
 * goes through the same checks.
 */
export async function safeFetch(rawUrl: string, opts: { timeoutMs?: number; maxBytes?: number; accept?: string; maxRedirects?: number } = {}): Promise<SafeResponse> {
  const { timeoutMs = 5000, maxBytes = 96 * 1024, accept = '*/*', maxRedirects = 0 } = opts;
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new UnsafeUrlError('Not a valid URL');
  }
  if (url.protocol !== 'https:') throw new UnsafeUrlError('Only https URLs are fetched');
  if (url.username || url.password) throw new UnsafeUrlError('URLs with credentials are not fetched');
  if (url.port && url.port !== '443') throw new UnsafeUrlError('Only the standard https port is allowed');
  if (isIP(url.hostname) || url.hostname.startsWith('[')) throw new UnsafeUrlError('IP address URLs are not fetched');

  const res = await fetch(url, {
    dispatcher: agent,
    redirect: 'manual',
    signal: AbortSignal.timeout(timeoutMs),
    headers: { accept, 'user-agent': 'AxisIntelligence-DomainChecker/1.0' },
  });

  const location = res.headers.get('location');
  if (res.status >= 300 && res.status < 400 && location && maxRedirects > 0) {
    await res.body?.cancel();
    const next = await safeFetch(new URL(location, url).toString(), { ...opts, maxRedirects: maxRedirects - 1 });
    return { ...next, redirected: true };
  }

  const reader = res.body?.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  let truncated = false;
  if (reader) {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.length;
      if (size > maxBytes) {
        truncated = true;
        await reader.cancel();
        break;
      }
      chunks.push(value);
    }
  }
  return {
    status: res.status,
    contentType: res.headers.get('content-type') ?? '',
    body: Buffer.concat(chunks).toString('utf8'),
    finalUrl: url.toString(),
    truncated,
    redirected: false,
  };
}

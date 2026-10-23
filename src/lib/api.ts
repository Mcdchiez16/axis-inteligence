import { InputError } from './domain.ts';

type Bucket = { count: number; reset: number };
const buckets = new Map<string, Bucket>();

function clientKey(req: Request): string {
  const fwd = req.headers.get('x-forwarded-for')?.split(',')[0]?.trim();
  return fwd || req.headers.get('x-real-ip') || 'local';
}

/** A small per-visitor rate limit (in memory, per server instance). Returns a 429 response when exceeded. */
export function rateLimit(req: Request, scope: string, perMinute: number): Response | null {
  const key = `${scope}:${clientKey(req)}`;
  const now = Date.now();
  const b = buckets.get(key);
  if (!b || b.reset < now) {
    buckets.set(key, { count: 1, reset: now + 60_000 });
    if (buckets.size > 5000) for (const [k, v] of buckets) if (v.reset < now) buckets.delete(k);
    return null;
  }
  b.count += 1;
  if (b.count > perMinute) {
    return Response.json({ error: 'Too many requests. Please wait a minute and try again.' }, { status: 429, headers: { 'Retry-After': String(Math.ceil((b.reset - now) / 1000)) } });
  }
  return null;
}

export function fail(e: unknown): Response {
  if (e instanceof InputError) return Response.json({ error: e.message }, { status: 400 });
  console.error(e);
  return Response.json({ error: 'Something went wrong while running the check.' }, { status: 500 });
}

/** A tiny time-limited cache so repeated checks of the same domain do not hammer DNS. */
export function ttlCache<T>(ttlMs: number, max = 300) {
  const store = new Map<string, { at: number; value: T }>();
  return {
    get(key: string): T | undefined {
      const hit = store.get(key);
      if (!hit) return undefined;
      if (Date.now() - hit.at > ttlMs) {
        store.delete(key);
        return undefined;
      }
      return hit.value;
    },
    set(key: string, value: T) {
      if (store.size >= max) store.delete(store.keys().next().value as string);
      store.set(key, { at: Date.now(), value });
    },
  };
}

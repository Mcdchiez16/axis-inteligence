'use client';

import { useRouter, useSearchParams } from 'next/navigation';
import { useEffect, useState } from 'react';

import type { DomainReport } from '@/lib/score.ts';

import { getJson } from './ui';

/** Keeps the domain in the URL (so results can be shared) and loads data for it from `endpoint`. */
export function useDomainData<T>(path: string, endpoint: string) {
  const params = useSearchParams();
  const router = useRouter();
  const domain = params.get('domain') ?? '';
  const selector = params.get('selector') ?? '';
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!domain) {
      setData(null);
      return;
    }
    let alive = true;
    setBusy(true);
    setError(null);
    const q = new URLSearchParams({ domain });
    if (selector) q.set('selector', selector);
    getJson<T>(`${endpoint}?${q}`)
      .then((r) => alive && setData(r))
      .catch((e: Error) => alive && (setError(e.message), setData(null)))
      .finally(() => alive && setBusy(false));
    return () => {
      alive = false;
    };
  }, [domain, selector, endpoint]);

  const submit = (d: string, sel?: string) => {
    const q = new URLSearchParams({ domain: d.trim() });
    if (sel?.trim()) q.set('selector', sel.trim());
    router.push(`${path}?${q}`);
  };

  return { domain, selector, data, error, busy, submit };
}

export function useDomainReport(path: string) {
  const r = useDomainData<DomainReport>(path, '/api/score');
  return { ...r, report: r.data };
}

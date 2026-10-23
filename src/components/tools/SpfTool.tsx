'use client';

import { CheckCircle2, ExternalLink, MinusCircle, XCircle } from 'lucide-react';
import Link from 'next/link';
import { useState } from 'react';

import type { SpfNode } from '@/lib/checks/spf.ts';

import { Button, Card, Code, Container, ErrorNote, Field, getJson, inputClass, PageIntro } from '../ui';

type Result = { domain: string; sender: string; ip: string; result: string; explanation: string; matched?: string; lookups: number; voidLookups: number; record?: string; trace: { depth: number; text: string }[]; tree: { root: SpfNode } };

const HEADLINE: Record<string, string> = {
  pass: 'IP is a permitted sender',
  fail: 'IP is not permitted to send',
  softfail: 'IP is probably not permitted (soft fail)',
  neutral: 'The domain makes no statement about this IP',
  none: 'The domain has no SPF record',
  temperror: 'Temporary DNS error',
  permerror: 'The SPF record is broken',
};

function Tree({ node, depth = 0 }: { node: SpfNode; depth?: number }) {
  return (
    <div className={depth ? 'ml-4 border-l-2 border-axis-red/20 pl-4' : ''}>
      <div className="space-y-2 py-2">
        <p className="flex flex-wrap items-center gap-2 text-sm">
          <span className="rounded-md bg-ink px-2 py-0.5 text-xs font-bold text-white">SPF</span>
          <span className="font-semibold text-ink">{node.domain}</span>
          <Link href={`/lookup?type=spf&domain=${encodeURIComponent(node.domain)}`} className="inline-flex items-center gap-1 text-xs font-semibold text-axis-red hover:underline">Analyse <ExternalLink className="size-3" /></Link>
        </p>
        {node.record ? <Code>{node.record}</Code> : <p className="text-sm text-bad">{node.error}</p>}
      </div>
      {node.children.map((c, i) => <Tree key={`${c.domain}-${i}`} node={c} depth={depth + 1} />)}
    </div>
  );
}

export function SpfTool() {
  const [email, setEmail] = useState('');
  const [ip, setIp] = useState('');
  const [data, setData] = useState<Result | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const run = async () => {
    setBusy(true);
    setError(null);
    try {
      setData(await getJson<Result>(`/api/spf-test?${new URLSearchParams({ email, ip })}`));
    } catch (e) {
      setError((e as Error).message);
      setData(null);
    } finally {
      setBusy(false);
    }
  };

  const good = data?.result === 'pass';
  const bad = data && ['fail', 'permerror'].includes(data.result);
  return (
    <>
      <PageIntro title="SPF policy test">Check whether a sending IP address is authorised by looking up the sender’s SPF record and every record it includes.</PageIntro>
      <Container className="mt-6 space-y-6">
        <Card className="p-4 sm:p-6">
          <form onSubmit={(e) => { e.preventDefault(); if (email.trim() && ip.trim()) void run(); }} className="grid gap-4 md:grid-cols-[1fr_1fr_auto] md:items-start">
            <Field label="Email address" hint="The sender address, or just the domain."><input className={inputClass} value={email} onChange={(e) => setEmail(e.target.value)} placeholder="e.g. info@example.com" spellCheck={false} /></Field>
            <Field label="IP address" hint="The server that sends the email."><input className={inputClass} value={ip} onChange={(e) => setIp(e.target.value)} placeholder="e.g. 198.51.100.25" spellCheck={false} /></Field>
            <Button type="submit" busy={busy} className="h-[52px] md:mt-[24px]">Run SPF policy test</Button>
          </form>
        </Card>
        {error ? <ErrorNote>{error}</ErrorNote> : null}
        {data ? (
          <div className="grid gap-6 lg:grid-cols-[400px_1fr]">
            <div className="space-y-6">
              <Card className="p-4 sm:p-6">
                <div className="flex items-center gap-3">
                  {good ? <CheckCircle2 className="size-10 shrink-0 text-good" /> : bad ? <XCircle className="size-10 shrink-0 text-bad" /> : <MinusCircle className="size-10 shrink-0 text-warn" />}
                  <div>
                    <p className={`text-xl font-extrabold ${good ? 'text-good' : bad ? 'text-bad' : 'text-warn'}`}>{HEADLINE[data.result] ?? data.result}</p>
                    <p className="text-sm capitalize text-muted">SPF result: {data.result}</p>
                  </div>
                </div>
                <p className="mt-4 text-sm leading-relaxed text-ink/85">{data.explanation}</p>
                <dl className="mt-5 divide-y divide-line rounded-xl bg-mist text-sm">
                  {[['IP', data.ip], ['Sender', data.sender], ['Domain', data.domain], ['Matched', data.matched ?? '-'], ['DNS lookups', `${data.lookups} of 10`]].map(([k, v]) => (
                    <div key={k} className="flex justify-between gap-4 px-4 py-2.5"><dt className="text-muted">{k}</dt><dd className="break-all text-right font-semibold text-ink">{v}</dd></div>
                  ))}
                </dl>
              </Card>
              <Card className="p-4 sm:p-6">
                <h2 className="text-base font-bold text-ink">How the answer was reached</h2>
                <ol className="mt-3 space-y-2">
                  {data.trace.map((s, i) => (
                    <li key={i} className="flex gap-3 text-sm" style={{ paddingLeft: s.depth * 16 }}>
                      <span className="mt-1.5 size-2 shrink-0 rounded-full bg-axis-red" />
                      <span className="break-all font-mono text-[12.5px] leading-relaxed text-ink/85">{s.text}</span>
                    </li>
                  ))}
                </ol>
              </Card>
            </div>
            <Card className="p-4 sm:p-6">
              <h2 className="text-base font-bold text-ink">SPF policy</h2>
              <div className="mt-2"><Tree node={data.tree.root} /></div>
            </Card>
          </div>
        ) : null}
      </Container>
    </>
  );
}

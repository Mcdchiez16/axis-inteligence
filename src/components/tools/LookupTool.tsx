'use client';

import { ExternalLink } from 'lucide-react';
import Link from 'next/link';
import { useRouter, useSearchParams } from 'next/navigation';
import { useEffect, useState } from 'react';

import type { RR } from '@/lib/doh.ts';
import type { LookupResult, RecordLookup } from '@/lib/lookup.ts';
import type { SpfNode } from '@/lib/checks/spf.ts';

import { Button, Card, Code, Container, ErrorNote, Field, getJson, inputClass, PageIntro } from '../ui';

const TYPES = [
  ['dns', 'DNS'],
  ['dmarc', 'DMARC'],
  ['spf', 'SPF'],
  ['dkim', 'DKIM'],
  ['mta-sts', 'MTA-STS'],
  ['tls-rpt', 'TLS-RPT'],
  ['bimi', 'BIMI'],
] as const;

function Table({ head, rows, empty }: { head: string[]; rows: (string | number | undefined)[][]; empty: string }) {
  if (!rows.length) return <p className="text-sm text-muted">{empty}</p>;
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead><tr className="text-left text-xs uppercase tracking-wider text-muted">{head.map((h) => <th key={h} className="pb-2 pr-4 font-semibold">{h}</th>)}</tr></thead>
        <tbody>{rows.map((r, i) => <tr key={i} className="border-t border-line align-top">{r.map((c, j) => <td key={j} className="break-all py-2 pr-4 font-mono text-[13px] text-ink/90">{c ?? '-'}</td>)}</tr>)}</tbody>
      </table>
    </div>
  );
}

function Block({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <Card className="space-y-3 p-6">
      <h2 className="text-base font-bold text-ink">{title}</h2>
      {children}
    </Card>
  );
}

function RecordView({ l, label }: { l: RecordLookup; label: string }) {
  return (
    <>
      {l.redirect ? (
        <Block title="Redirect">
          <p className="text-sm text-muted">This record is delegated with a CNAME, usually to a service provider that manages it for you.</p>
          <Table head={['Type', 'TTL', 'Target']} rows={[[l.redirect.type, l.redirect.ttl, l.redirect.data]]} empty="" />
        </Block>
      ) : null}
      <Block title={`Results for ${l.name}`}>
        <Table head={['Type', 'TTL', 'Value']} rows={l.records.map((r) => [r.type, r.ttl, r.data])} empty={l.status === 'error' ? 'The lookup failed. Try again.' : `No ${label} record found.`} />
      </Block>
    </>
  );
}

function SpfTreeView({ node, depth = 0 }: { node: SpfNode; depth?: number }) {
  return (
    <div className={depth ? 'ml-4 border-l-2 border-axis-red/20 pl-4' : ''}>
      <div className="space-y-2 py-2">
        <div className="flex flex-wrap items-center gap-2 text-sm">
          <span className="rounded-md bg-ink px-2 py-0.5 text-xs font-bold text-white">{node.via === 'root' ? 'SPF' : node.via}</span>
          <span className="font-semibold text-ink">{node.domain}</span>
          {node.via !== 'root' ? <Link href={`/lookup?type=spf&domain=${encodeURIComponent(node.domain)}`} className="inline-flex items-center gap-1 text-xs font-semibold text-axis-red hover:underline">Analyse <ExternalLink className="size-3" /></Link> : null}
        </div>
        {node.record ? <Code copy>{node.record}</Code> : null}
        {node.error ? <p className="text-sm text-bad">{node.error}</p> : null}
      </div>
      {node.children.map((c, i) => <SpfTreeView key={`${c.domain}-${i}`} node={c} depth={depth + 1} />)}
    </div>
  );
}

const nsRows = (ns: RR[]) => ns.map((n) => [n.type, n.ttl, n.data]);

function Results({ r }: { r: LookupResult }) {
  switch (r.type) {
    case 'dns':
      return (
        <div className="grid gap-4 lg:grid-cols-2">
          {r.sections.map((s) => (
            <Block key={s.type} title={s.type}>
              {s.type === 'SOA' && s.records[0] ? (
                (() => {
                  const [ns, admin, serial, refresh, retry, expire, min] = s.records[0].data.split(/\s+/);
                  return <Table head={['Field', 'Value']} rows={[['TTL', s.records[0].ttl], ['Primary name server', ns], ['Admin', admin], ['Serial', serial], ['Refresh', refresh], ['Retry', retry], ['Expire', expire], ['Minimum TTL', min]]} empty="" />;
                })()
              ) : (
                <Table head={['Type', 'TTL', s.type === 'MX' ? 'Priority · host' : 'Value']} rows={s.records.map((x) => [x.type, x.ttl, x.data])} empty={s.status === 'error' ? 'The lookup failed.' : `No ${s.type} record for ${r.domain}.`} />
              )}
            </Block>
          ))}
        </div>
      );
    case 'dmarc':
      return <RecordView l={r.lookup} label="DMARC" />;
    case 'tls-rpt':
      return <RecordView l={r.lookup} label="TLS-RPT" />;
    case 'bimi':
      return <RecordView l={r.lookup} label="BIMI" />;
    case 'mta-sts':
      return (
        <>
          <RecordView l={r.lookup} label="MTA-STS" />
          {r.policy ? (
            <Block title="Policy file">
              <p className="break-all font-mono text-xs text-muted">{r.policy.url}</p>
              {r.policy.error ? <p className="text-sm text-bad">{r.policy.error}</p> : <>
                <Table head={['Mode', 'Max age', 'MX patterns', 'HTTP']} rows={[[r.policy.mode, r.policy.maxAge, r.policy.mx.join(', '), r.policy.status]]} empty="" />
                <Code>{r.policy.body}</Code>
              </>}
            </Block>
          ) : null}
        </>
      );
    case 'spf': {
      const t = r.tree;
      return (
        <>
          <Block title="Status">
            <dl className="grid grid-cols-2 gap-2.5 sm:grid-cols-3 sm:gap-3">
              {[
                ['Domain', r.domain],
                ['All', r.allText ?? 'No "all" mechanism'],
                ['DNS lookups', `${t.dnsLookups} of 10`],
                ['MX lookups', String(t.mxLookups)],
                ['Void lookups', `${t.voidLookups} of 2`],
                ['Root record size', `${t.rootSize} bytes`],
              ].map(([k, v]) => (
                <div key={k} className="rounded-xl bg-mist p-3">
                  <dt className="text-xs font-semibold uppercase tracking-wider text-muted">{k}</dt>
                  <dd className={`mt-1 text-sm font-semibold ${k === 'DNS lookups' && t.dnsLookups > 10 ? 'text-bad' : 'text-ink'}`}>{v}</dd>
                </div>
              ))}
            </dl>
            {t.errors.length ? <ul className="space-y-1 text-sm text-bad">{t.errors.map((e) => <li key={e}>{e}</li>)}</ul> : null}
          </Block>
          <Block title="Record tree"><SpfTreeView node={t.root} /></Block>
        </>
      );
    }
    case 'dkim':
      return (
        <>
          {r.selector && r.requested ? <RecordView l={r.requested} label={`DKIM (${r.selector})`} /> : null}
          <Block title="Known selectors">
            <p className="text-sm text-muted">Selectors cannot be listed in DNS, so we check the names common providers use.</p>
            {r.known.length ? r.known.map((k) => (
              <div key={k.selector} className="space-y-1.5">
                <p className="text-sm font-semibold text-ink">{k.selector}<span className="font-normal text-muted"> · {k.keyType}{k.bits ? ` ${k.bits}-bit` : ''}</span></p>
                <Code copy>{k.record}</Code>
              </div>
            )) : <p className="text-sm text-muted">None found.</p>}
          </Block>
          <Block title="Name servers"><Table head={['Type', 'TTL', 'Name server']} rows={nsRows(r.ns)} empty="No name servers found." /></Block>
        </>
      );
  }
}

export function LookupTool() {
  const params = useSearchParams();
  const router = useRouter();
  const qType = params.get('type') ?? 'dns';
  const qDomain = params.get('domain') ?? '';
  const qSelector = params.get('selector') ?? '';
  const [type, setType] = useState(qType);
  const [domain, setDomain] = useState(qDomain);
  const [selector, setSelector] = useState(qSelector);
  const [data, setData] = useState<LookupResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    setType(qType);
    setDomain(qDomain);
    setSelector(qSelector);
    if (!qDomain) {
      setData(null);
      return;
    }
    let alive = true;
    setBusy(true);
    setError(null);
    const q = new URLSearchParams({ type: qType, domain: qDomain });
    if (qSelector) q.set('selector', qSelector);
    getJson<LookupResult>(`/api/lookup?${q}`)
      .then((r) => alive && setData(r))
      .catch((e: Error) => alive && (setError(e.message), setData(null)))
      .finally(() => alive && setBusy(false));
    return () => {
      alive = false;
    };
  }, [qType, qDomain, qSelector]);

  const label = TYPES.find(([k]) => k === type)?.[1] ?? 'DNS';
  return (
    <>
      <PageIntro title={`${label} lookup`}>Look up a domain’s {label} records, with TTLs, redirects and the full chain of included records.</PageIntro>
      <Container className="mt-6 space-y-6">
        <Card className="p-4 sm:p-6">
          <form
            onSubmit={(e) => {
              e.preventDefault();
              if (!domain.trim()) return;
              const q = new URLSearchParams({ type, domain: domain.trim() });
              if (type === 'dkim' && selector.trim()) q.set('selector', selector.trim());
              router.push(`/lookup?${q}`);
            }}
            className={`grid gap-4 sm:items-end ${type === 'dkim' ? 'sm:grid-cols-[160px_200px_1fr_auto]' : 'sm:grid-cols-[160px_1fr_auto]'}`}>
            <Field label="Lookup">
              <select className={inputClass} value={type} onChange={(e) => { setType(e.target.value); setData(null); }}>
                {TYPES.map(([k, v]) => <option key={k} value={k}>{v}</option>)}
              </select>
            </Field>
            {type === 'dkim' ? <Field label="Selector"><input className={inputClass} value={selector} onChange={(e) => setSelector(e.target.value)} placeholder="e.g. selector1" spellCheck={false} /></Field> : null}
            <Field label="Domain name"><input className={inputClass} value={domain} onChange={(e) => setDomain(e.target.value)} placeholder="e.g. example.com" spellCheck={false} /></Field>
            <Button type="submit" busy={busy} className="h-[52px]">Lookup</Button>
          </form>
        </Card>
        {error ? <ErrorNote>{error}</ErrorNote> : null}
        {busy && !data ? <div className="h-64 animate-pulse rounded-2xl bg-mist" /> : null}
        {data ? <div className="space-y-4"><Results r={data} /></div> : null}
      </Container>
    </>
  );
}

'use client';

import { CheckCircle2, XCircle } from 'lucide-react';
import { useState } from 'react';

import { contains, describe, rangeToCidrs, subnets, type CidrInfo } from '@/lib/cidr.ts';

import { Button, Card, Container, CopyButton, ErrorNote, Field, inputClass, PageIntro } from '../ui';

const MODES = [
  ['check', 'IP address'],
  ['toRange', 'CIDR to IP range'],
  ['toCidr', 'IP range to CIDR'],
] as const;
type Mode = (typeof MODES)[number][0];

export function CidrTool() {
  const [mode, setMode] = useState<Mode>('check');
  const [ip, setIp] = useState('');
  const [cidr, setCidr] = useState('');
  const [first, setFirst] = useState('');
  const [last, setLast] = useState('');
  const [split, setSplit] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [check, setCheck] = useState<{ ip: string; cidr: string; found: boolean } | null>(null);
  const [info, setInfo] = useState<CidrInfo | null>(null);
  const [list, setList] = useState<string[] | null>(null);

  const reset = (m: Mode) => {
    setMode(m);
    setError(null);
    setCheck(null);
    setInfo(null);
    setList(null);
  };

  const run = () => {
    setError(null);
    try {
      if (mode === 'check') setCheck({ ip: ip.trim(), cidr: cidr.trim(), found: contains(cidr.trim(), ip.trim()) });
      if (mode === 'toRange') setInfo(describe(cidr.trim()));
      if (mode === 'toCidr') setList(rangeToCidrs(first.trim(), last.trim()));
    } catch (e) {
      setError((e as Error).message);
      setCheck(null);
      setInfo(null);
      setList(null);
    }
  };

  let subs: ReturnType<typeof subnets> | null = null;
  if (info && split) {
    try {
      subs = subnets(cidr.trim(), Number(split));
    } catch {
      subs = null;
    }
  }

  const rows: [string, string][] = info
    ? [
        ['CIDR range', `${info.network}/${info.prefix}`],
        ['CIDR base', info.network],
        ...(info.netmask ? ([['Netmask', info.netmask], ['Host mask', info.wildcard!]] as [string, string][]) : []),
        ['Bitmask', String(info.prefix)],
        [info.family === 4 ? 'Broadcast' : 'Last address', info.lastAddress],
        ['Block size', info.totalAddresses],
        ['First usable IP', info.firstUsable],
        ['Last usable IP', info.lastUsable],
        ['Usable hosts', info.usableHosts],
      ]
    : [];

  return (
    <>
      <PageIntro title="CIDR calculator">Check whether an address is inside a range, expand a CIDR block into its addresses, or turn a start and end address into CIDR blocks. Works for IPv4 and IPv6.</PageIntro>
      <Container className="mt-6 space-y-6">
        <Card className="p-4 sm:p-6">
          <div role="tablist" aria-label="Calculator mode" className="mb-6 inline-flex flex-wrap gap-1 rounded-xl bg-mist p-1">
            {MODES.map(([k, label]) => (
              <button key={k} role="tab" aria-selected={mode === k} type="button" onClick={() => reset(k)} className={`rounded-lg px-4 py-2 text-sm font-semibold transition ${mode === k ? 'bg-white text-ink shadow-sm' : 'text-muted hover:text-ink'}`}>{label}</button>
            ))}
          </div>
          <form onSubmit={(e) => { e.preventDefault(); run(); }} className="grid gap-4 md:grid-cols-[1fr_1fr_auto] md:items-end">
            {mode === 'check' ? <>
              <Field label="IP address"><input className={`${inputClass} font-mono`} value={ip} onChange={(e) => setIp(e.target.value)} placeholder="e.g. 192.168.1.77" spellCheck={false} /></Field>
              <Field label="CIDR"><input className={`${inputClass} font-mono`} value={cidr} onChange={(e) => setCidr(e.target.value)} placeholder="e.g. 192.168.1.0/24" spellCheck={false} /></Field>
            </> : mode === 'toRange' ? <>
              <Field label="CIDR"><input className={`${inputClass} font-mono`} value={cidr} onChange={(e) => setCidr(e.target.value)} placeholder="e.g. 10.0.0.0/22 or 2001:db8::/48" spellCheck={false} /></Field>
              <Field label="Split into subnets (optional)">
                <select className={inputClass} value={split} onChange={(e) => setSplit(e.target.value)}>
                  <option value="">Do not split</option>
                  {info ? Array.from({ length: Math.min(16, (info.family === 4 ? 32 : 128) - info.prefix) }, (_, i) => info.prefix + i + 1).map((p) => <option key={p} value={p}>/{p}</option>) : null}
                </select>
              </Field>
            </> : <>
              <Field label="First IP address"><input className={`${inputClass} font-mono`} value={first} onChange={(e) => setFirst(e.target.value)} placeholder="e.g. 10.0.0.0" spellCheck={false} /></Field>
              <Field label="Last IP address"><input className={`${inputClass} font-mono`} value={last} onChange={(e) => setLast(e.target.value)} placeholder="e.g. 10.0.3.255" spellCheck={false} /></Field>
            </>}
            <Button type="submit" className="h-[52px]">{mode === 'check' ? 'Check' : 'Calculate'}</Button>
          </form>
        </Card>

        {error ? <ErrorNote>{error}</ErrorNote> : null}

        {check ? (
          <Card className={`flex items-center gap-4 p-6 ${check.found ? 'border-good/30' : 'border-bad/30'}`}>
            {check.found ? <CheckCircle2 className="size-10 shrink-0 text-good" /> : <XCircle className="size-10 shrink-0 text-bad" />}
            <div>
              <p className="text-xl font-extrabold text-ink">{check.found ? 'IP address found' : 'IP address not found'}</p>
              <p className="text-sm text-muted">{check.ip} is {check.found ? '' : 'not '}inside {check.cidr}.</p>
            </div>
          </Card>
        ) : null}

        {info ? (
          <Card className="divide-y divide-line">
            {rows.map(([k, v]) => (
              <div key={k} className="flex items-center justify-between gap-4 px-6 py-3.5">
                <span className="text-sm text-muted">{k}</span>
                <span className="flex items-center gap-3"><span className="break-all text-right font-mono text-sm font-semibold text-ink">{v}</span><CopyButton text={v} /></span>
              </div>
            ))}
          </Card>
        ) : null}

        {subs ? (
          <Card className="overflow-x-auto">
            <table className="w-full min-w-[480px] text-sm">
              <thead className="bg-mist/70 text-left text-xs uppercase tracking-wider text-muted"><tr><th className="px-6 py-3">Subnet</th><th className="px-6 py-3">First</th><th className="px-6 py-3">Last</th></tr></thead>
              <tbody>{subs.map((s) => <tr key={s.cidr} className="border-t border-line font-mono text-[13px]"><td className="px-6 py-2.5 font-semibold">{s.cidr}</td><td className="px-6 py-2.5">{s.first}</td><td className="px-6 py-2.5">{s.last}</td></tr>)}</tbody>
            </table>
          </Card>
        ) : null}

        {list ? (
          <Card className="space-y-3 p-6">
            <p className="text-sm text-muted">The CIDR blocks that exactly cover {first} to {last}:</p>
            <div className="flex flex-wrap gap-2">
              {list.map((c) => <span key={c} className="rounded-lg bg-mist px-3 py-1.5 font-mono text-sm font-semibold text-ink">{c}</span>)}
            </div>
            <CopyButton text={list.join('\n')} label="Copy all" />
          </Card>
        ) : null}
      </Container>
    </>
  );
}

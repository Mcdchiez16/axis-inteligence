'use client';

import { CheckCircle2, ExternalLink, HelpCircle, XCircle } from 'lucide-react';
import { useState } from 'react';

import { Button, Card, Container, ErrorNote, Field, getJson, inputClass, PageIntro } from '../ui';

type ZoneResult = { zone: string; name: string; target: string; status: 'listed' | 'clear' | 'error' | 'refused'; codes: string[]; reason?: string; info: string };
type Result = { target: string; ips: string[]; results: ZoneResult[] };

export function BlocklistTool() {
  const [target, setTarget] = useState('');
  const [data, setData] = useState<Result | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const run = async () => {
    setBusy(true);
    setError(null);
    try {
      setData(await getJson<Result>(`/api/blocklist?${new URLSearchParams({ target })}`));
    } catch (e) {
      setError((e as Error).message);
      setData(null);
    } finally {
      setBusy(false);
    }
  };

  const listed = data?.results.filter((r) => r.status === 'listed') ?? [];
  return (
    <>
      <PageIntro title="Blocklist lookup">Check an IP address or domain against well-known spam blocklists. A listing can send your email straight to spam.</PageIntro>
      <Container className="mt-6 space-y-6">
        <Card className="p-4 sm:p-6">
          <form onSubmit={(e) => { e.preventDefault(); if (target.trim()) void run(); }} className="grid gap-4 sm:grid-cols-[1fr_auto] sm:items-start">
            <Field label="IP address or domain" hint="For a domain we also check the addresses it points to."><input className={inputClass} value={target} onChange={(e) => setTarget(e.target.value)} placeholder="198.51.100.25 or example.com" spellCheck={false} /></Field>
            <Button type="submit" busy={busy} className="h-[52px] sm:mt-[24px]">Check lists</Button>
          </form>
        </Card>
        {error ? <ErrorNote>{error}</ErrorNote> : null}
        {data ? (
          <>
            <Card className={`flex items-center gap-4 p-6 ${listed.length ? 'border-bad/30' : 'border-good/30'}`}>
              {listed.length ? <XCircle className="size-10 text-bad" aria-hidden /> : <CheckCircle2 className="size-10 text-good" aria-hidden />}
              <div>
                <p className="text-xl font-extrabold text-ink">{listed.length ? `${data.target} is listed on ${listed.length} blocklist${listed.length > 1 ? 's' : ''}` : `${data.target} is not blocklisted`}</p>
                <p className="text-sm text-muted">{data.target}{data.ips.length && data.ips[0] !== data.target ? ` · ${data.ips.join(', ')}` : ''} · {data.results.length} checks</p>
              </div>
            </Card>
            <Card className="overflow-x-auto">
              <table className="w-full min-w-[560px] text-sm">
                <thead className="bg-mist/70 text-left text-xs uppercase tracking-wider text-muted">
                  <tr><th className="px-6 py-3">Blocklist</th><th className="px-6 py-3">Checked</th><th className="px-6 py-3">Result</th><th className="px-6 py-3" /></tr>
                </thead>
                <tbody>
                  {data.results.map((r) => (
                    <tr key={`${r.zone}-${r.target}`} className="border-t border-line align-top">
                      <td className="px-6 py-3"><p className="font-semibold text-ink">{r.name}</p><p className="font-mono text-xs text-muted">{r.zone}</p></td>
                      <td className="px-6 py-3 font-mono text-[13px]">{r.target}</td>
                      <td className="px-6 py-3">
                        {r.status === 'listed' ? <span className="inline-flex items-center gap-1.5 font-semibold text-bad"><XCircle className="size-4" />Listed</span> : r.status === 'clear' ? <span className="inline-flex items-center gap-1.5 font-semibold text-good"><CheckCircle2 className="size-4" />Clear</span> : <span className="inline-flex items-center gap-1.5 text-muted"><HelpCircle className="size-4" />{r.status === 'refused' ? 'Query refused' : 'No answer'}</span>}
                        {r.reason ? <p className="mt-1 max-w-sm text-xs text-muted">{r.reason}</p> : null}
                      </td>
                      <td className="px-6 py-3 text-right"><a href={r.info} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-xs font-semibold text-axis-red hover:underline">Details <ExternalLink className="size-3" /></a></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Card>
            {data.results.some((r) => r.status === 'refused') ? <p className="text-sm text-muted">Some lists refuse queries from shared public DNS resolvers. Ask your administrator to set DNSBL_RESOLVERS to your own resolver for complete results.</p> : null}
          </>
        ) : null}
      </Container>
    </>
  );
}

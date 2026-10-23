'use client';

import { ExternalLink } from 'lucide-react';
import Link from 'next/link';
import type { ReactNode } from 'react';

import type { AnalysisDetail } from '@/lib/analysis.ts';
import type { CheckResult } from '@/lib/checks/types.ts';
import { RISK_LABEL } from '@/lib/risk.ts';
import type { DomainReport } from '@/lib/score.ts';

import { DomainForm } from './DomainForm';
import { Card, Code, Container, ErrorNote, FindingList, PageIntro, StatusPill } from './ui';
import { useDomainData } from './useDomainReport';

type Data = { report: DomainReport; detail: AnalysisDetail };

function Badge({ tone, children }: { tone: 'good' | 'warn' | 'bad' | 'neutral'; children: ReactNode }) {
  const cls = { good: 'bg-good-50 text-good', warn: 'bg-warn-50 text-warn', bad: 'bg-bad-50 text-bad', neutral: 'bg-mist text-ink' }[tone];
  return <span className={`rounded-lg px-2.5 py-1 text-xs font-semibold ${cls}`}>{children}</span>;
}

function Protocol({ title, check, badges, records, domain, type, children }: { title: string; check: CheckResult; badges: ReactNode; records: string[]; domain: string; type: string; children?: ReactNode }) {
  return (
    <div className="space-y-3 border-t border-line px-6 py-5 first:border-t-0">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h3 className="text-base font-bold text-ink">{title}</h3>
        <div className="flex items-center gap-3">
          <StatusPill status={check.status} />
          <Link href={`/lookup?type=${type}&domain=${encodeURIComponent(domain)}`} className="inline-flex items-center gap-1 text-xs font-semibold text-axis-red hover:underline">Lookup <ExternalLink className="size-3" /></Link>
        </div>
      </div>
      <div className="flex flex-wrap gap-2">{badges}</div>
      {records.map((r, i) => <Code key={i} copy>{r}</Code>)}
      {children}
      <details className="group">
        <summary className="cursor-pointer select-none text-sm font-semibold text-muted hover:text-ink">Findings and advice</summary>
        <div className="mt-3"><FindingList items={check.findings} /></div>
      </details>
    </div>
  );
}

function Section({ title, rating, children }: { title: string; rating?: number; children: ReactNode }) {
  return (
    <Card className="overflow-hidden">
      <div className="flex items-center justify-between border-b border-line bg-page px-6 py-4">
        <h2 className="text-lg font-extrabold text-ink">{title}</h2>
        {rating !== undefined ? <span className="text-sm font-bold text-muted">{rating}/5</span> : null}
      </div>
      {children}
    </Card>
  );
}

function Table({ head, rows }: { head: string[]; rows: (string | number)[][] }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead><tr className="text-left text-xs uppercase tracking-wider text-muted">{head.map((h) => <th key={h} className="pb-2 pr-4">{h}</th>)}</tr></thead>
        <tbody>{rows.map((r, i) => <tr key={i} className="border-t border-line">{r.map((c, j) => <td key={j} className="py-2 pr-4 font-mono text-[13px]">{c}</td>)}</tr>)}</tbody>
      </table>
    </div>
  );
}

export function AnalysisTool() {
  const { domain, selector, data, error, busy, submit } = useDomainData<Data>('/domain-analysis', '/api/analysis');
  const r = data?.report;
  const x = data?.detail;
  const cat = (id: string) => r?.categories.find((c) => c.id === id)?.rating;

  return (
    <>
      <PageIntro title="Domain analysis">
        A record-by-record breakdown of how your domain handles email, with the exact DNS values and what to change. Add your DKIM selector if your provider uses an unusual one.
      </PageIntro>
      <Container className="mt-6 space-y-6">
        <DomainForm initial={domain} initialSelector={selector} busy={busy} onSubmit={submit} withSelector submitLabel="Analyse domain" />
        {error ? <ErrorNote>{error}</ErrorNote> : null}
        {busy && !data ? <div className="h-96 animate-pulse rounded-2xl bg-mist" /> : null}
        {r && x ? (
          <>
            <div className="flex flex-wrap items-baseline justify-between gap-2">
              <h2 className="text-2xl font-extrabold tracking-tight text-ink">{r.domain}</h2>
              <p className="text-sm text-muted">Score <span className="font-bold text-ink">{r.score}</span> · <span>{RISK_LABEL[r.risk]} risk</span></p>
            </div>

            <div className="grid gap-6 xl:grid-cols-[1fr_380px]">
              <div className="space-y-6">
                <Section title="Impersonation" rating={cat('impersonation')}>
                  {(() => {
                    const c = r.checks.dmarc;
                    const d = c.data as { policy?: string; pct?: number; rua?: string[] } | undefined;
                    return (
                      <Protocol title="DMARC" check={c} domain={r.domain} type="dmarc" records={c.record ? [c.record] : []}
                        badges={c.status === 'missing' ? <Badge tone="bad">Record not found</Badge> : <>
                          <Badge tone={d?.policy === 'reject' ? 'good' : d?.policy === 'quarantine' ? 'warn' : 'bad'}>Policy on {d?.policy ?? 'none'}</Badge>
                          {d?.policy && d.policy !== 'none' ? <Badge tone={d.pct === 100 ? 'good' : 'warn'}>{d.pct === 100 ? 'Policy fully enforced' : `Policy applied to ${d.pct}%`}</Badge> : null}
                          <Badge tone={d?.rua?.length ? 'good' : 'warn'}>{d?.rua?.length ? 'Reporting address specified' : 'No reporting address'}</Badge>
                          {x.redirects.dmarc ? <Badge tone="neutral">Redirect → {x.redirects.dmarc.data}</Badge> : null}
                        </>} />
                    );
                  })()}
                  {(() => {
                    const c = r.checks.spf;
                    const s = c.data as { lookups?: number; allQualifier?: string; records?: string[]; record?: string } | undefined;
                    const redirect = /redirect=([^\s]+)/i.exec(s?.record ?? '')?.[1];
                    const allLabel = { '-': 'Fail', '~': 'Soft fail', '?': 'Neutral', '+': 'Pass (unsafe)' }[s?.allQualifier ?? ''] ?? 'Missing';
                    return (
                      <Protocol title="SPF" check={c} domain={r.domain} type="spf" records={c.record ? c.record.split('\n') : []}
                        badges={c.status === 'missing' ? <Badge tone="bad">Record not found</Badge> : <>
                          <Badge tone={(s?.lookups ?? 0) > 10 ? 'bad' : (s?.lookups ?? 0) >= 8 ? 'warn' : 'good'}>{s?.lookups ?? 0} lookups</Badge>
                          <Badge tone={s?.allQualifier === '-' ? 'good' : s?.allQualifier === '~' ? 'warn' : 'bad'}>&quot;All&quot; {allLabel}</Badge>
                          {redirect ? <Badge tone="neutral">Redirect → {redirect}</Badge> : null}
                        </>} />
                    );
                  })()}
                  {(() => {
                    const c = r.checks.dkim;
                    const keys = ((c.data as { keys?: { selector: string; record: string; bits?: number; keyType: string; revoked: boolean }[] } | undefined)?.keys ?? []).filter((k) => !k.revoked);
                    return (
                      <Protocol title="DKIM" check={c} domain={r.domain} type="dkim" records={[]}
                        badges={keys.length ? <Badge tone="good">{keys.length} selector{keys.length > 1 ? 's' : ''}</Badge> : <Badge tone="warn">No selector found</Badge>}>
                        {keys.map((k) => (
                          <div key={k.selector} className="space-y-1.5">
                            <p className="text-sm font-semibold text-ink">{k.selector} <span className="font-normal text-muted">· {k.keyType}{k.bits ? ` ${k.bits}-bit` : ''}</span></p>
                            <Code copy>{k.record}</Code>
                          </div>
                        ))}
                      </Protocol>
                    );
                  })()}
                </Section>

                {r.mailMode === 'mail' ? (
                  <Section title="Privacy" rating={cat('privacy')}>
                    <Protocol title="TLS-RPT" check={r.checks.tlsrpt} domain={r.domain} type="tls-rpt" records={r.checks.tlsrpt.record ? [r.checks.tlsrpt.record] : []}
                      badges={r.checks.tlsrpt.status === 'missing' ? <Badge tone="bad">Record not found</Badge> : <>
                        <Badge tone={r.checks.tlsrpt.status === 'pass' ? 'good' : 'warn'}>{r.checks.tlsrpt.status === 'pass' ? 'Reporting address specified' : 'Reporting address invalid'}</Badge>
                        {x.redirects.tlsrpt ? <Badge tone="neutral">Redirect → {x.redirects.tlsrpt.data}</Badge> : null}
                      </>} />
                    {(() => {
                      const c = r.checks.mtasts;
                      const mode = (c.data as { policy?: { mode?: string } } | undefined)?.policy?.mode;
                      return (
                        <Protocol title="MTA-STS" check={c} domain={r.domain} type="mta-sts" records={c.record ? [c.record] : []}
                          badges={c.status === 'missing' ? <Badge tone="bad">Record not found</Badge> : <>
                            <Badge tone={mode === 'enforce' ? 'good' : mode === 'testing' ? 'warn' : 'bad'}>Policy {mode ? mode[0].toUpperCase() + mode.slice(1) : 'unavailable'}</Badge>
                            {x.redirects.mtasts ? <Badge tone="neutral">Redirect → {x.redirects.mtasts.data}</Badge> : null}
                          </>} />
                      );
                    })()}
                  </Section>
                ) : null}

                {r.mailMode === 'mail' ? (
                  <Section title="Branding" rating={cat('branding')}>
                    <Protocol title="BIMI" check={r.checks.bimi} domain={r.domain} type="bimi" records={r.checks.bimi.record ? [r.checks.bimi.record] : []}
                      badges={r.checks.bimi.status === 'missing' ? <Badge tone="bad">Record not found</Badge> : <>
                        <Badge tone={(r.checks.bimi.data as { logoValid?: boolean })?.logoValid ? 'good' : 'warn'}>Image</Badge>
                        <Badge tone={(r.checks.bimi.data as { certValid?: boolean })?.certValid ? 'good' : 'warn'}>Certificate</Badge>
                      </>} />
                  </Section>
                ) : null}
              </div>

              <div className="space-y-6">
                <Card className="divide-y divide-line">
                  {[
                    ['Authority domain', r.organizationalDomain],
                    ['Mail-sending domain', x.mailSending ? 'Yes' : 'No (null MX or no mail servers)'],
                    ['DNS admin email', x.dnsAdmin ?? 'Unknown'],
                  ].map(([k, v]) => (
                    <div key={k} className="flex items-center justify-between gap-4 px-6 py-4">
                      <span className="text-sm text-muted">{k}</span>
                      <span className="break-all text-right text-sm font-semibold text-ink">{v}</span>
                    </div>
                  ))}
                </Card>
                <Card className="space-y-3 p-6">
                  <div className="flex items-center justify-between"><h3 className="font-bold text-ink">DNS provider</h3><span className="text-sm font-semibold text-axis-red">{r.common.dnsProvider}</span></div>
                  <Table head={['Type', 'TTL', 'Name server']} rows={x.ns.map((n) => [n.type, n.ttl ?? '-', n.data])} />
                </Card>
                <Card className="space-y-3 p-6">
                  <div className="flex items-center justify-between"><h3 className="font-bold text-ink">Email provider</h3><span className="text-sm font-semibold text-axis-red">{r.common.emailProvider}</span></div>
                  <Table head={['Pref', 'TTL', 'Hostname']} rows={x.mx.map((m) => { const [pref, host] = m.data.split(/\s+/); return [pref, m.ttl ?? '-', host]; })} />
                </Card>
              </div>
            </div>
          </>
        ) : null}
      </Container>
    </>
  );
}

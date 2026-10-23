'use client';

import { Check, CheckCircle2, ChevronDown, Download, ExternalLink, Fingerprint, Lock, Mail, Minus, MinusCircle, ShieldCheck, X, XCircle } from 'lucide-react';
import Link from 'next/link';
import { useState, type ReactNode } from 'react';

import type { CheckResult } from '@/lib/checks/types.ts';
import { RISK_LABEL } from '@/lib/risk.ts';
import type { DomainReport } from '@/lib/score.ts';

import { DomainForm } from './DomainForm';
import { LeadForm } from './LeadForm';
import { Modal } from './Modal';
import { useCountUp, useMounted } from './motion';
import { buttonClass, Card, Container, ErrorNote, PageIntro } from './ui';
import { useDomainReport } from './useDomainReport';

type Risk = 'low' | 'medium' | 'high';
// one colour family per risk level: a bright face, a darker pressed edge and a soft tint
const TONE: Record<Risk, { face: string; edge: string; text: string; tint: string; track: string }> = {
  low: { face: '#58cc02', edge: '#46a302', text: '#3f9302', tint: '#effbe4', track: '#e3f5d3' },
  medium: { face: '#ff9600', edge: '#d97a00', text: '#c96f00', tint: '#fff4e0', track: '#ffe8c4' },
  high: { face: '#e5172f', edge: '#9a0314', text: '#c8102e', tint: '#fff0ee', track: '#ffdcd7' },
};
const CATEGORY_ICON = { impersonation: Fingerprint, privacy: Lock, branding: ShieldCheck } as const;

const FULL_NAME: Record<string, string> = {
  dmarc: 'DMARC (Domain-based Message Authentication, Reporting and Conformance)',
  spf: 'SPF (Sender Policy Framework)',
  dkim: 'DKIM (DomainKeys Identified Mail)',
  tlsrpt: 'TLS-RPT (SMTP TLS Reporting)',
  mtasts: 'MTA-STS (Mail Transfer Agent Strict Transport Security)',
  bimi: 'BIMI (Brand Indicators for Message Identification)',
};
const LOOKUP_TYPE: Record<string, string> = { dmarc: 'dmarc', spf: 'spf', dkim: 'dkim', tlsrpt: 'tls-rpt', mtasts: 'mta-sts', bimi: 'bimi' };
const ALL_TEXT: Record<string, string> = {
  '-': "'-all': email from unlisted senders fails authentication",
  '~': "'~all': email from unlisted senders is marked suspicious",
  '?': "'?all': no statement about unlisted senders",
  '+': "'+all': anyone may send, which offers no protection",
};

/** good, bad, or "n/a": a record that is not needed here (SPF and DKIM without MX records). */
type State = 'good' | 'bad' | 'na';
type Chip = { label: string; state: State };
const state = (ok: boolean): State => (ok ? 'good' : 'bad');

function chipsFor(r: DomainReport, id: string): Chip[] {
  const c = r.checks[id];
  if (c.notRequired) return [{ label: c.title, state: 'na' }];
  if (id !== 'bimi') return [{ label: c.title, state: state(c.status === 'pass' || c.status === 'warn') }];
  const d = c.data as { logoValid?: boolean; certValid?: boolean } | undefined;
  return [
    { label: 'BIMI', state: state(c.status !== 'missing' && c.status !== 'unknown') },
    { label: 'Certificate', state: state(!!d?.certValid) },
    { label: 'Image', state: state(!!d?.logoValid) },
  ];
}

const STATE_CLS: Record<State, string> = { good: 'bg-good-50 text-good ring-good/25', bad: 'bg-bad-50 text-bad ring-bad/20', na: 'bg-mist text-muted ring-line-dark' };
const STATE_ICON = { good: CheckCircle2, bad: XCircle, na: MinusCircle } as const;
const STATE_TEXT: Record<State, string> = { good: 'passed', bad: 'missing', na: 'not required' };

/** A thick dial that sweeps round to the score, with the number counting up in the middle. */
function ScoreDonut({ score, risk }: { score: number; risk: Risk }) {
  const t = TONE[risk];
  const r = 88;
  const c = 2 * Math.PI * r;
  const mounted = useMounted(80);
  const shown = useCountUp(score, 1400, 150);
  return (
    <div className="relative mx-auto size-[200px]" role="img" aria-label={`Overall score ${score} out of 100`}>
      <svg viewBox="0 0 200 200" className="size-full -rotate-90">
        <circle cx="100" cy="100" r={r} fill="none" stroke={t.track} strokeWidth="14" />
        <circle
          cx="100"
          cy="100"
          r={r}
          fill="none"
          stroke={t.face}
          strokeWidth="14"
          strokeLinecap="round"
          strokeDasharray={c}
          strokeDashoffset={mounted ? c * (1 - Math.max(score, 1) / 100) : c}
          style={{ transition: 'stroke-dashoffset 1500ms cubic-bezier(0.34,1.2,0.64,1) 150ms' }}
        />
      </svg>
      <div className="absolute inset-0 grid place-items-center">
        <span className="text-center leading-none">
          <span className="block text-[52px] font-black tabular-nums" style={{ color: t.text }}>{shown}</span>
          <span className="mt-1.5 block text-sm font-bold text-muted">out of 100</span>
        </span>
      </div>
    </div>
  );
}

/** A chunky rating badge sitting on a darker edge: it pops in and the number counts up. */
function RatingTile({ rating, risk, delay, size = 'lg' }: { rating: number; risk: Risk; delay: number; size?: 'lg' | 'sm' }) {
  const t = TONE[risk];
  const shown = useCountUp(rating, 700, delay + 150);
  const lg = size === 'lg';
  return (
    <span
      className={`inline-flex items-baseline justify-center font-black text-white ${lg ? 'size-[72px] rounded-[20px] pt-3.5' : 'rounded-2xl px-3 py-1.5'}`}
      style={{ background: t.face, boxShadow: `0 ${lg ? 5 : 4}px 0 ${t.edge}`}}>
      <span className={`${lg ? 'text-[32px]' : 'text-xl'} leading-none tabular-nums`}>{shown}</span>
      <span className={`${lg ? 'text-base' : 'text-sm'} opacity-85`}>/5</span>
    </span>
  );
}

/** A progress bar that fills to rating/5 with a glossy sweep. */
function RatingBar({ rating, risk, delay }: { rating: number; risk: Risk; delay: number }) {
  const t = TONE[risk];
  const mounted = useMounted(delay);
  return (
    <div className="relative h-3.5 w-full overflow-hidden rounded-full bg-[#efe9e4]" aria-hidden>
      <div className="relative h-full overflow-hidden rounded-full" style={{ width: mounted ? `${Math.max(rating, 0.25) * 20}%` : '0%', background: t.face, transition: 'width 1000ms cubic-bezier(0.34,1.2,0.64,1)' }}>
      </div>
    </div>
  );
}

export function ScoreTool() {
  const { domain, report, error, busy, submit } = useDomainReport('/');
  const [detail, setDetail] = useState(false);
  const [emailOpen, setEmailOpen] = useState(false);

  return (
    <>
      <PageIntro title="Know your score">
        We check DMARC, SPF, DKIM and the overall state of your domain, then rate how easily someone could send phishing email in your name.
      </PageIntro>

      <Container className="mt-6 space-y-6">
        <DomainForm initial={domain} busy={busy} onSubmit={(d) => { setDetail(false); submit(d); }} />
        {error ? <ErrorNote>{error}</ErrorNote> : null}
        {busy && !report ? <div className="h-80 animate-pulse rounded-3xl bg-mist" /> : null}

        {report ? (
          <>
            <ScorePanel key={report.checkedAt + report.domain} report={report} detail={detail} onToggle={() => setDetail((d) => !d)} onEmail={() => setEmailOpen(true)} />

            <div className={`grid transition-[grid-template-rows,opacity] duration-500 ease-out ${detail ? 'grid-rows-[1fr] opacity-100' : 'grid-rows-[0fr] opacity-0'}`} aria-hidden={!detail}>
              <div className="overflow-hidden">
                <DetailedReport report={report} onEmail={() => setEmailOpen(true)} />
              </div>
            </div>

            <Modal open={emailOpen} onClose={() => setEmailOpen(false)} title="Email the detailed report">
              <LeadForm endpoint="/api/report/email" extra={{ domain: report.domain }} submitLabel="Send report" intro={`Get the full report for ${report.domain} as a PDF in your inbox. If your domain is at risk, an Axis Solutions specialist can help you fix it.`} />
            </Modal>
          </>
        ) : null}

        {!report && !busy ? <HowItWorks /> : null}
      </Container>
    </>
  );
}

function ScorePanel({ report, detail, onToggle, onEmail }: { report: DomainReport; detail: boolean; onToggle: () => void; onEmail: () => void }) {
  const t = TONE[report.risk];
  return (
    <section aria-label="Domain score" className="card-3d anim-fade relative overflow-hidden rounded-3xl bg-white p-5 sm:p-8">
      {/*
        Phone: everything stacks. Tablet: summary and dial side by side, the three ratings below.
        Wide: one row. Every column starts on the same top line, so headings and cards line up.
      */}
      <div className="relative grid gap-8 md:grid-cols-[minmax(0,1fr)_auto] xl:grid-cols-[minmax(0,1fr)_auto_minmax(0,1.9fr)] xl:gap-7">
        <div className="md:self-center xl:self-start xl:pt-5">
          <p className="text-lg font-bold text-muted">Domain score for <span className="break-all font-black text-ink">{report.domain}</span></p>
          <p className="mt-1 text-[34px] font-black leading-tight tracking-tight sm:text-[40px]" style={{ color: t.text }}>{RISK_LABEL[report.risk]} Risk</p>
          <p className="mt-3 max-w-md font-semibold leading-relaxed text-ink/75">{report.summary}</p>
          <div className="mt-4 flex flex-wrap gap-2">
            {([
              ['NS', state(report.common.ns.length > 0)],
              ['MX', report.mailMode === 'no-mail' ? 'na' : state(report.common.mx.length > 0)],
              ['A', state(report.common.a.length > 0)],
            ] as const).map(([k, st], i) => (
              <Chip key={k} label={k} state={st} />
            ))}
          </div>
          <div className="mt-6 grid gap-3 sm:flex sm:flex-wrap xl:grid xl:w-fit">
            {/* stacked on wide screens, so both buttons share one width */}
            <button type="button" onClick={onToggle} aria-expanded={detail} className={`${buttonClass('secondary')} whitespace-nowrap px-5`}>
              <ChevronDown className={`size-4 transition duration-300 ${detail ? 'rotate-180' : ''}`} strokeWidth={2} />
              {detail ? 'Hide detailed report' : 'View detailed report'}
            </button>
            <button type="button" onClick={onEmail} className={`${buttonClass('primary')} whitespace-nowrap px-5`}>
              <Mail className="size-4" strokeWidth={2} />
              Email report
            </button>
          </div>
        </div>

        <div className="text-center xl:pt-[22px]">
          <p className="mb-3 flex sm:mb-4 h-6 items-center justify-center text-base font-black text-ink">Overall score</p>
          <ScoreDonut score={report.score} risk={report.risk} />
        </div>

        <div className="grid gap-4 sm:grid-cols-3 md:col-span-2 xl:col-span-1">
          {report.categories.map((c, i) => {
            const ct = TONE[c.risk];
            const Icon = CATEGORY_ICON[c.id];
            return (
              <div key={c.id} className="card-3d grid grid-cols-[auto_minmax(0,1fr)] items-center gap-x-4 gap-y-1.5 rounded-3xl bg-white p-4 text-left sm:flex sm:flex-col sm:items-center sm:px-4 sm:pb-4 sm:pt-5 sm:text-center">
                <p className="col-start-2 row-start-1 flex h-6 items-center gap-1.5 text-base font-black text-ink"><Icon className="size-4 shrink-0 text-muted" strokeWidth={1.75} aria-hidden />{c.title}</p>
                <div className="col-start-1 row-span-3 row-start-1 sm:my-4"><RatingTile rating={c.rating} risk={c.risk} delay={450 + i * 140} /></div>
                <div className="col-start-2 row-start-2 w-full"><RatingBar rating={c.rating} risk={c.risk} delay={600 + i * 140} /></div>
                <p className="col-start-2 row-start-3 text-sm font-extrabold sm:mt-2.5" style={{ color: ct.text }}>{RISK_LABEL[c.risk]} Risk</p>
                <ul className="col-span-2 mt-3 w-full space-y-1.5 sm:mt-4">
                  {c.checks.flatMap((id) => chipsFor(report, id)).map((ch, j) => (
                    <CheckRow key={ch.label} label={ch.label} state={ch.state} />
                  ))}
                </ul>
              </div>
            );
          })}
        </div>
      </div>
    </section>
  );
}

/** A small pill for the NS, MX and A records: a tick, a cross, or a dash when it does not apply. */
function Chip({ label, state: st }: { label: string; state: State }) {
  return (
    <span className={`inline-flex items-center gap-1 rounded-full px-2.5 py-1 text-xs font-extrabold ring-2 ring-inset ${STATE_CLS[st]}`} title={STATE_TEXT[st]}>
      {st === 'good' ? <Check className="size-3" strokeWidth={2.5} aria-hidden /> : st === 'bad' ? <X className="size-3" strokeWidth={2.5} aria-hidden /> : <Minus className="size-3" strokeWidth={2.5} aria-hidden />}
      {label}
    </span>
  );
}

/** One check inside a rating card: full width, so the rows line up across the three cards. */
function CheckRow({ label, state: st }: { label: string; state: State }) {
  const Icon = STATE_ICON[st];
  return (
    <li className={`flex items-center justify-between gap-2 rounded-xl px-3 py-1.5 text-xs font-extrabold ${STATE_CLS[st].replace(/ ring-\S+/, '')}`}>
      <span className="truncate">{label}</span>
      <Icon className="size-4 shrink-0" strokeWidth={2} aria-label={STATE_TEXT[st]} />
    </li>
  );
}

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid gap-1 border-t border-line py-3 sm:grid-cols-[180px_1fr]">
      <dt className="text-sm font-semibold text-ink">{label}</dt>
      <dd className="text-sm leading-relaxed text-ink/80">{children}</dd>
    </div>
  );
}

function RecordStatus({ check, domain, type }: { check: CheckResult; domain: string; type: string }) {
  if (check.notRequired) return <span className="text-muted">{check.summary}</span>;
  const found = check.status !== 'missing' && check.status !== 'unknown';
  const errors = check.findings.some((f) => f.level === 'bad');
  return (
    <span className="flex flex-wrap items-center gap-x-2">
      <span className={found ? (errors ? 'text-warn' : 'text-good') : 'text-bad'}>{found ? (errors ? 'Record found, with problems' : 'Record found without errors') : check.status === 'unknown' ? 'Could not be checked' : 'No record found'}</span>
      {found ? (
        <Link href={`/lookup?type=${type}&domain=${encodeURIComponent(domain)}`} className="inline-flex items-center gap-1 font-semibold text-axis-red hover:underline">
          Analyse <ExternalLink className="size-3" />
        </Link>
      ) : null}
    </span>
  );
}

function DetailedReport({ report, onEmail }: { report: DomainReport; onEmail: () => void }) {
  const d = report.checks.dmarc.data as { policy?: string; subdomainPolicy?: string; pct?: number; rua?: string[]; ruf?: string[]; unauthorisedReports?: string[] } | undefined;
  const spf = report.checks.spf.data as { lookups?: number; allQualifier?: string } | undefined;
  const dkim = report.checks.dkim.data as { keys?: { selector: string; revoked: boolean }[] } | undefined;
  const sts = report.checks.mtasts.data as { policy?: { mode?: string } } | undefined;
  const bimi = report.checks.bimi.data as { logoValid?: boolean; certValid?: boolean; logoUrl?: string; vmcUrl?: string } | undefined;
  const selfManaged = report.providers.dmarc.includes('Self-managed');
  const live = (dkim?.keys ?? []).filter((k) => !k.revoked);

  const rows: Record<string, ReactNode> = {
    dmarc: (
      <>
        <Row label="Policy">{d?.policy ? `Policy set to '${d.policy}'${d.policy === 'reject' ? ': failing email is refused' : d.policy === 'quarantine' ? ': failing email goes to spam' : ': monitoring only, failing email is still delivered'}` : 'No policy published'}</Row>
        {d?.subdomainPolicy ? <Row label="Subdomain policy">{`Subdomain policy set to '${d.subdomainPolicy}'${d.subdomainPolicy === d.policy ? '' : d.subdomainPolicy === 'none' ? ': subdomains can still be spoofed' : d.subdomainPolicy === 'quarantine' ? ': spoofed subdomain email goes to spam rather than being refused' : ''}`}</Row> : null}
        <Row label="Percentage">{d?.policy ? `The policy applies to ${d.pct ?? 100}% of email` : '-'}</Row>
        <Row label="Aggregate reporting">
          {d?.rua?.length ? <>Reports go to {d.rua.join(', ')}{selfManaged ? '. Raw reports sent to your own mailbox are hard to read without a reporting service.' : '.'}</> : 'No reporting address, so you cannot see who sends email as this domain.'}
          {d?.unauthorisedReports?.length ? <span className="block text-bad">{d.unauthorisedReports.join(', ')} has not authorised receiving reports for this domain, so they will not arrive.</span> : null}
        </Row>
        <Row label="Failure reporting">{d?.ruf?.length ? `Failure reports go to ${d.ruf.join(', ')}` : 'Not set'}</Row>
        <Row label="Providers">{report.providers.dmarc.length ? report.providers.dmarc.join(', ') : 'None detected'}</Row>
      </>
    ),
    spf: (
      <>
        <Row label="Lookups">{spf?.lookups !== undefined ? `${spf.lookups} of 10 DNS lookups used` : '-'}</Row>
        <Row label="All">{spf?.allQualifier ? ALL_TEXT[spf.allQualifier] : 'No "all" mechanism'}</Row>
      </>
    ),
    dkim: <Row label="Selectors">{live.length ? `${live.length} selector${live.length > 1 ? 's' : ''} found: ${live.map((k) => k.selector).join(', ')}` : 'No selector found among common names. Check your provider’s selector in Domain Analysis.'}</Row>,
    tlsrpt: <Row label="Providers">{report.providers.tlsrpt.length ? report.providers.tlsrpt.join(', ') : 'None detected'}</Row>,
    mtasts: <Row label="Policy">{sts?.policy?.mode ? `Policy set to '${sts.policy.mode}'${sts.policy.mode === 'enforce' ? ': encryption enforced' : sts.policy.mode === 'testing' ? ': problems are reported but not enforced' : ''}` : 'No policy available'}</Row>,
    bimi: (
      <>
        <Row label="Image">{bimi?.logoUrl ? (bimi.logoValid ? 'Valid SVG Tiny PS logo' : 'Logo found, but it does not meet the BIMI format') : 'No logo published'}</Row>
        <Row label="Certificate">{bimi?.vmcUrl ? (bimi.certValid ? 'Valid mark certificate' : 'Certificate could not be validated') : 'No mark certificate (VMC/CMC)'}</Row>
      </>
    ),
  };

  return (
    <div className="space-y-6">
      {report.categories.map((c) => {
        const Icon = CATEGORY_ICON[c.id];
        return (
          <Card key={c.id} className="overflow-hidden">
            <div className="flex flex-col gap-4 border-b border-line bg-page p-6 sm:flex-row sm:items-center">
              <RatingTile rating={c.rating} risk={c.risk} delay={0} size="sm" />
              <div>
                <h2 className="flex items-center gap-2 text-lg font-bold text-ink"><Icon className="size-5 text-axis-red" />{c.title} rating</h2>
                <p className="mt-1 text-sm leading-relaxed text-muted">{c.explanation}</p>
              </div>
            </div>
            <div className="divide-y divide-line">
              {c.checks.map((id) => (
                <section key={id} className="px-6 py-5">
                  <h3 className="font-bold text-ink">{FULL_NAME[id]}</h3>
                  <dl className="mt-2">
                    <Row label="DNS record"><RecordStatus check={report.checks[id]} domain={report.domain} type={LOOKUP_TYPE[id]} /></Row>
                    {report.checks[id].status !== 'missing' && !report.checks[id].notRequired ? rows[id] : null}
                  </dl>
                </section>
              ))}
            </div>
          </Card>
        );
      })}

      <Card className="p-4 sm:p-6">
        <h2 className="text-lg font-bold text-ink">Common records</h2>
        <dl className="mt-2">
          <Row label="NS record">DNS provider: {report.common.dnsProvider}{report.common.ns.length ? <span className="text-muted"> ({report.common.ns.join(', ')})</span> : null}</Row>
          <Row label="MX record">Email provider: {report.common.emailProvider}{report.common.mx.length ? <span className="text-muted"> ({report.common.mx.join(', ')})</span> : null}</Row>
          <Row label="A record">{report.common.website ? 'Website presence found' : 'No website address found'}{report.common.a.length ? <span className="text-muted"> ({report.common.a.join(', ')})</span> : null}</Row>
        </dl>
      </Card>

      {report.recommendations.length ? (
        <Card className="p-4 sm:p-6">
          <h2 className="text-lg font-bold text-ink">What to fix first</h2>
          <ol className="mt-4 space-y-3">
            {report.recommendations.map((r, i) => (
              <li key={i} className="flex gap-3 text-sm leading-relaxed text-ink/85">
                <span className="grid size-7 shrink-0 place-items-center rounded-xl bg-axis-red text-xs font-black text-white shadow-[0_3px_0_#9a0314]">{i + 1}</span>
                <span>{r}</span>
              </li>
            ))}
          </ol>
        </Card>
      ) : null}

      <div className="flex flex-wrap gap-3">
        <button type="button" onClick={onEmail} className={buttonClass('primary')}><Mail className="size-4" />Email report</button>
        <a href={`/api/report/pdf?domain=${encodeURIComponent(report.domain)}`} className={buttonClass('secondary')}><Download className="size-4" />Download report</a>
        <Link href={`/domain-analysis?domain=${encodeURIComponent(report.domain)}`} className={buttonClass('secondary')}>Analyse domain</Link>
      </div>
    </div>
  );
}

function HowItWorks() {
  const items = [
    { t: 'Impersonation', w: 80, d: 'DMARC, SPF and DKIM decide whether someone else can send email that looks like it came from you.' },
    { t: 'Privacy', w: 15, d: 'MTA-STS and TLS-RPT make sure email sent to you is encrypted in transit, and tell you when it is not.' },
    { t: 'Branding', w: 5, d: 'BIMI shows your verified logo next to your messages in inboxes that support it.' },
  ];
  return (
    <Card className="p-5 sm:p-7">
      <h2 className="text-lg font-extrabold text-ink">What the score covers</h2>
      <dl className="mt-4 grid gap-5 md:grid-cols-3 md:gap-8">
        {items.map(({ t, w, d }) => (
          <div key={t} className="border-t-2 border-line pt-4">
            <dt className="flex items-baseline justify-between gap-3 font-extrabold text-ink">
              {t}
              <span className="text-sm font-bold text-muted">{w} points</span>
            </dt>
            <dd className="mt-1.5 text-[15px] font-semibold leading-relaxed text-muted">{d}</dd>
          </div>
        ))}
      </dl>
    </Card>
  );
}

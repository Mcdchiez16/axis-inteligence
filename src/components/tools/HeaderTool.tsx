'use client';

import { ArrowDown, Clock, FileUp, ShieldCheck, X } from 'lucide-react';
import { useMemo, useRef, useState } from 'react';

import { analyseHeaders, headersFromFile, MAX_FILE_BYTES, type HeaderReport } from '@/lib/headers.ts';

import { Button, Card, Container, ErrorNote, FindingList, inputClass, PageIntro } from '../ui';

const fmtDelay = (s?: number) => (s === undefined ? '' : s < 60 ? `${s}s` : s < 3600 ? `${Math.round(s / 60)} min` : `${(s / 3600).toFixed(1)} h`);

export function HeaderTool() {
  const [raw, setRaw] = useState('');
  const [report, setReport] = useState<HeaderReport | null>(null);
  const [fileName, setFileName] = useState<string | null>(null);
  const [fileError, setFileError] = useState<string | null>(null);
  const [dragging, setDragging] = useState(false);
  const picker = useRef<HTMLInputElement>(null);

  // Files are read here in the browser; nothing is sent to the server.
  const loadFile = async (file?: File | null) => {
    if (!file) return;
    setFileError(null);
    if (file.size > MAX_FILE_BYTES) return setFileError('That file is larger than 25 MB.');
    try {
      const { text } = headersFromFile(await file.arrayBuffer());
      setRaw(text);
      setFileName(file.name);
      setReport(analyseHeaders(text));
    } catch (e) {
      setFileError(e instanceof Error ? e.message : 'That file could not be read.');
    }
  };
  const chips = useMemo(() => report?.auth.filter((a) => ['spf', 'dkim', 'dmarc', 'arc'].includes(a.method)) ?? [], [report]);

  return (
    <>
      <PageIntro title="Header analysis">Upload an email file or paste its headers to see the servers it passed through, the delays and whether it passed SPF, DKIM and DMARC. Analysis runs in your browser; nothing is uploaded.</PageIntro>
      <Container className="mt-6 space-y-6">
        <Card className="p-4 sm:p-6">
          <form onSubmit={(e) => { e.preventDefault(); setReport(analyseHeaders(raw)); }} className="space-y-4">
            <div
              onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
              onDragLeave={() => setDragging(false)}
              onDrop={(e) => { e.preventDefault(); setDragging(false); void loadFile(e.dataTransfer.files?.[0]); }}
              className={`flex flex-col items-center justify-center gap-2 rounded-xl border-2 border-dashed px-4 py-6 text-center transition ${dragging ? 'border-axis-red bg-axis-red-50' : 'border-line bg-mist/50'}`}>
              <FileUp className="size-6 text-axis-red" aria-hidden />
              <p className="text-sm text-ink">
                Drop an email file here or{' '}
                <button type="button" onClick={() => picker.current?.click()} className="font-semibold text-axis-red hover:underline">choose a file</button>
              </p>
              <p className="text-xs text-muted">.eml, .msg (Outlook), .emlx, .mbox, .ics or .txt, up to 25 MB. Read in your browser, never uploaded.</p>
              <input ref={picker} type="file" accept=".eml,.msg,.txt,.emlx,.ics,.mbox,message/rfc822,text/plain,text/calendar,application/mbox" className="hidden" onChange={(e) => { void loadFile(e.target.files?.[0]); e.target.value = ''; }} />
              {fileName ? (
                <span className="mt-1 inline-flex items-center gap-2 rounded-lg bg-white px-3 py-1.5 text-xs font-semibold text-ink ring-1 ring-line">
                  {fileName}
                  <button type="button" aria-label="Clear file" onClick={() => { setFileName(null); setRaw(''); setReport(null); }}><X className="size-3.5 text-muted" /></button>
                </span>
              ) : null}
            </div>
            {fileError ? <ErrorNote>{fileError}</ErrorNote> : null}
            <p className="text-center text-xs font-semibold uppercase tracking-[0.14em] text-muted">or paste the headers</p>
            <textarea value={raw} onChange={(e) => { setRaw(e.target.value); setFileName(null); }} rows={10} spellCheck={false} aria-label="Email headers" placeholder={'Received: from …\nAuthentication-Results: …\nFrom: …'} className={`${inputClass} font-mono text-[13px]`} />
            <div className="flex flex-wrap items-center justify-between gap-3">
              <p className="text-xs text-muted">In Gmail: ⋮ → Show original. In Outlook: File → Properties → Internet headers.</p>
              <Button type="submit" disabled={!raw.trim()}>Analyse headers</Button>
            </div>
          </form>
        </Card>

        {report ? (
          <div className="grid gap-6 lg:grid-cols-[1fr_380px]">
            <div className="space-y-6">
              <Card className="p-4 sm:p-6">
                <h2 className="flex items-center gap-2 text-lg font-bold text-ink"><ShieldCheck className="size-5 text-axis-red" />Authentication</h2>
                <div className="mt-4 flex flex-wrap gap-2">
                  {chips.length ? chips.map((a, i) => (
                    <span key={i} className={`rounded-lg px-3 py-1.5 text-sm font-semibold ${a.result === 'pass' ? 'bg-good-50 text-good' : a.result === 'fail' ? 'bg-bad-50 text-bad' : 'bg-warn-50 text-warn'}`}>{a.method.toUpperCase()}: {a.result}</span>
                  )) : <span className="text-sm text-muted">No Authentication-Results header found.</span>}
                </div>
                <div className="mt-5"><FindingList items={report.findings} /></div>
              </Card>

              <Card className="p-4 sm:p-6">
                <div className="flex items-center justify-between">
                  <h2 className="flex items-center gap-2 text-lg font-bold text-ink"><Clock className="size-5 text-axis-red" />Route ({report.hops.length} hops)</h2>
                  {report.totalDelaySeconds !== undefined ? <span className="text-sm text-muted">Total {fmtDelay(report.totalDelaySeconds)}</span> : null}
                </div>
                <ol className="mt-5 space-y-1">
                  {report.hops.map((h, i) => (
                    <li key={h.index}>
                      {i > 0 ? <div className="flex items-center gap-2 py-1 pl-4 text-xs text-muted"><ArrowDown className="size-3.5" />{h.delaySeconds !== undefined ? `${fmtDelay(h.delaySeconds)} later` : ''}</div> : null}
                      <div className={`rounded-xl border px-4 py-3 ${(h.delaySeconds ?? 0) > 300 ? 'border-warn/40 bg-warn-50' : 'border-line bg-mist/50'}`}>
                        <p className="text-sm font-semibold text-ink">{h.index}. {h.by ?? 'unknown server'}</p>
                        <p className="mt-0.5 font-mono text-xs text-muted">from {h.from ?? '?'}{h.ip ? ` [${h.ip}]` : ''}{h.with ? ` · ${h.with}` : ''}</p>
                        {h.date ? <p className="mt-0.5 text-xs text-muted">{h.date.toUTCString()}</p> : null}
                      </div>
                    </li>
                  ))}
                </ol>
              </Card>
            </div>

            <div className="space-y-6">
              <Card className="p-4 sm:p-6">
                <h2 className="text-lg font-bold text-ink">Message</h2>
                <dl className="mt-4 space-y-3 text-sm">
                  {Object.entries(report.summary).filter(([, v]) => v).map(([k, v]) => (
                    <div key={k}>
                      <dt className="text-xs font-semibold uppercase tracking-wider text-muted">{k}</dt>
                      <dd className="mt-0.5 break-words text-ink">{v}</dd>
                    </div>
                  ))}
                </dl>
              </Card>
              {report.dkim.length ? (
                <Card className="p-4 sm:p-6">
                  <h2 className="text-lg font-bold text-ink">DKIM signatures</h2>
                  <ul className="mt-3 space-y-2 text-sm">
                    {report.dkim.map((d, i) => <li key={i} className="font-mono text-[13px]">d={d.domain} s={d.selector} a={d.algorithm}</li>)}
                  </ul>
                </Card>
              ) : null}
            </div>
          </div>
        ) : null}
      </Container>
    </>
  );
}

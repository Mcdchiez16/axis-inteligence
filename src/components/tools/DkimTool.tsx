'use client';

import { Download, KeyRound, ShieldAlert } from 'lucide-react';
import { useState } from 'react';

import { generateDkimKey, type DkimKeyPair } from '@/lib/dkim-gen.ts';

import { Button, Card, Code, Container, ErrorNote, Field, inputClass, PageIntro } from '../ui';

export function DkimTool() {
  const [domain, setDomain] = useState('');
  const [selector, setSelector] = useState('');
  const [bits, setBits] = useState<1024 | 2048 | 4096>(2048);
  const [key, setKey] = useState<DkimKeyPair | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const run = async () => {
    const d = domain.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
    if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(d)) return setError('Enter a valid domain, for example example.com');
    if (!selector.trim()) return setError(`Enter a selector, for example s${new Date().getFullYear()}`);
    if (!/^[a-z0-9][a-z0-9_-]{0,62}$/i.test(selector.trim())) return setError('The selector can contain letters, numbers, dashes and underscores');
    setError(null);
    setBusy(true);
    try {
      setKey(await generateDkimKey(d, selector.trim().toLowerCase(), bits));
    } catch {
      setError('Your browser could not generate the key.');
    } finally {
      setBusy(false);
    }
  };

  const download = () => {
    if (!key) return;
    const url = URL.createObjectURL(new Blob([key.privatePem], { type: 'application/x-pem-file' }));
    const a = document.createElement('a');
    a.href = url;
    a.download = `${key.selector}._domainkey.${key.domain}.private.pem`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <>
      <PageIntro title="DKIM key generator">Generates a key pair in your browser and gives you the DNS record to publish. The private key is created on your device and is never sent to us.</PageIntro>
      <Container className="mt-6 space-y-6">
        <Card className="p-4 sm:p-6">
          <form onSubmit={(e) => { e.preventDefault(); void run(); }} className="grid gap-4 md:grid-cols-[1fr_200px_180px_auto] md:items-end">
            <Field label="Domain"><input className={inputClass} value={domain} onChange={(e) => setDomain(e.target.value)} placeholder="example.com" spellCheck={false} /></Field>
            <Field label="Selector"><input className={inputClass} value={selector} onChange={(e) => setSelector(e.target.value)} placeholder={`e.g. s${new Date().getFullYear()}`} spellCheck={false} /></Field>
            <Field label="Key size">
              <select className={inputClass} value={bits} onChange={(e) => setBits(Number(e.target.value) as 1024 | 2048 | 4096)}>
                <option value={2048}>2048 bit (recommended)</option>
                <option value={1024}>1024 bit</option>
              </select>
            </Field>
            <Button type="submit" busy={busy} className="h-[52px]"><KeyRound className="size-4" />Generate</Button>
          </form>
        </Card>
        {error ? <ErrorNote>{error}</ErrorNote> : null}
        {key ? (
          <div className="grid gap-6 lg:grid-cols-2">
            <Card className="space-y-4 p-6">
              <h2 className="text-lg font-bold text-ink">1. Publish this DNS record</h2>
              <dl className="grid gap-3 text-sm sm:grid-cols-[110px_1fr]">
                <dt className="text-muted">Type</dt><dd className="font-mono font-semibold">TXT</dd>
                <dt className="text-muted">Host / name</dt><dd className="break-all font-mono font-semibold">{key.host}</dd>
              </dl>
              <div className="space-y-2">
                <p className="text-xs font-semibold uppercase tracking-[0.14em] text-muted">Value</p>
                <Code copy>{key.record}</Code>
              </div>
              {key.recordChunks.length > 1 ? (
                <div className="space-y-2">
                  <p className="text-xs text-muted">If your DNS provider limits TXT values to 255 characters, enter it as these quoted strings:</p>
                  <Code copy>{key.recordChunks.map((c) => `"${c}"`).join(' ')}</Code>
                </div>
              ) : null}
            </Card>
            <Card className="space-y-4 p-6">
              <h2 className="text-lg font-bold text-ink">2. Install the private key on your mail server</h2>
              <p className="flex gap-2 rounded-xl bg-axis-red-50 p-3 text-sm text-axis-red-700"><ShieldAlert className="mt-0.5 size-4 shrink-0" />Keep this secret. Anyone with it can sign email as {key.domain}. It is shown only now.</p>
              <Code copy>{key.privatePem}</Code>
              <Button type="button" onClick={download} className="w-full"><Download className="size-4" />Download private key</Button>
              <div className="space-y-2 pt-2">
                <p className="text-xs font-semibold uppercase tracking-[0.14em] text-muted">Public key (X.509 / SPKI)</p>
                <Code copy>{key.publicPem}</Code>
              </div>
            </Card>
          </div>
        ) : null}
      </Container>
    </>
  );
}

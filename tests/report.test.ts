import assert from 'node:assert/strict';
import { test } from 'node:test';

import { checkDmarc } from '../src/lib/checks/dmarc.ts';
import { mxMatches, parseMtaStsPolicy } from '../src/lib/checks/mtasts.ts';
import { checkSvgTinyPs } from '../src/lib/checks/bimi.ts';
import { analyzeSpf } from '../src/lib/checks/spf.ts';
import { normalizeDomain } from '../src/lib/domain.ts';
import { analyseHeaders, headersFromFile } from '../src/lib/headers.ts';
import { analyseDomain, gradeFor } from '../src/lib/score.ts';
import { fakeDns } from './fake-dns.ts';

test('normalises domain input', () => {
  assert.equal(normalizeDomain('  HTTPS://Mail.Example.COM/path?x '), 'mail.example.com');
  assert.equal(normalizeDomain('bob@example.org'), 'example.org');
  assert.equal(normalizeDomain('bücher.de'), 'xn--bcher-kva.de');
  assert.throws(() => normalizeDomain('192.0.2.1'));
  assert.throws(() => normalizeDomain('nodot'));
  assert.throws(() => normalizeDomain('-bad-.com'));
});

test('DMARC policies score in order, with organizational fallback', async () => {
  const dns = fakeDns({
    txt: {
      '_dmarc.reject.test': ['v=DMARC1; p=reject; rua=mailto:d@reject.test'],
      '_dmarc.quar.test': ['v=DMARC1; p=quarantine; pct=50; rua=mailto:d@quar.test'],
      '_dmarc.none.test': ['v=DMARC1; p=none'],
      '_dmarc.example.co.uk': ['v=DMARC1; p=reject; sp=none; rua=mailto:x@example.co.uk'],
    },
  });
  const r = await checkDmarc('reject.test', dns);
  const q = await checkDmarc('quar.test', dns);
  const n = await checkDmarc('none.test', dns);
  const m = await checkDmarc('missing.test', dns);
  assert.ok(r.points > q.points && q.points > n.points && n.points > m.points, `${r.points} ${q.points} ${n.points} ${m.points}`);
  assert.equal(r.status, 'pass');
  assert.equal(m.status, 'missing');
  const sub = await checkDmarc('mail.example.co.uk', dns);
  assert.equal(sub.data?.foundAt, 'example.co.uk');
  assert.ok(sub.findings.some((f) => f.text.includes('sp=none')));
});

test('MTA-STS policy parsing and MX wildcard matching', () => {
  const p = parseMtaStsPolicy('version: STSv1\nmode: enforce\nmx: mail.example.com\nmx: *.mx.example.net\nmax_age: 604800\n');
  assert.equal(p.mode, 'enforce');
  assert.equal(p.maxAge, 604800);
  assert.ok(mxMatches('a.mx.example.net', '*.mx.example.net'));
  assert.ok(!mxMatches('a.b.mx.example.net', '*.mx.example.net'));
  assert.ok(mxMatches('mail.example.com.', 'mail.example.com'));
});

test('BIMI SVG checks', () => {
  assert.deepEqual(checkSvgTinyPs('<svg version="1.2" baseProfile="tiny-ps"><title>x</title></svg>'), []);
  assert.ok(checkSvgTinyPs('<svg><script>alert(1)</script></svg>').length >= 2);
});

test('a well-configured domain scores higher than a bare one', async () => {
  const good = fakeDns({
    txt: {
      'good.test': ['v=spf1 ip4:192.0.2.0/24 -all'],
      '_dmarc.good.test': ['v=DMARC1; p=reject; rua=mailto:d@good.test'],
      'selector1._domainkey.good.test': ['v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo='],
      '_smtp._tls.good.test': ['v=TLSRPTv1; rua=mailto:tls@good.test'],
    },
    mx: { 'good.test': [{ priority: 10, exchange: 'mx.good.test' }] },
    a: { 'mx.good.test': ['192.0.2.10'] },
  });
  const bare = fakeDns({ mx: { 'bare.test': [{ priority: 10, exchange: 'mx.bare.test' }] }, a: { 'mx.bare.test': ['192.0.2.11'] } });
  const g = await analyseDomain('good.test', good);
  const b = await analyseDomain('bare.test', bare);
  assert.ok(g.score > b.score, `${g.score} vs ${b.score}`);
  const imp = g.categories.find((c) => c.id === 'impersonation')!;
  assert.equal(imp.rating, 5);
  assert.equal(imp.risk, 'low');
  assert.equal(g.categories.find((c) => c.id === 'privacy')?.rating, 2, 'TLS-RPT only, no MTA-STS');
  assert.equal(g.score, 80 + 7, 'impersonation 80 + TLS-RPT 7');
  assert.equal(b.score, 0);
  assert.equal(b.risk, 'high');
  assert.ok(b.recommendations.length > 0);
  assert.equal(g.providers.dmarc[0], 'Self-managed');
  assert.equal(gradeFor(95), 'A');
});

test('impersonation points follow the DMARC and SPF gaps', async () => {
  const mk = (dmarc: string, spf = 'v=spf1 -all') => fakeDns({
    txt: { 'd.test': spf ? [spf] : [], '_dmarc.d.test': dmarc ? [dmarc] : [], 's1._domainkey.d.test': ['v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo='] },
    mx: { 'd.test': [{ priority: 10, exchange: 'mx.d.test' }] }, a: { 'mx.d.test': ['192.0.2.1'] },
  });
  const run = async (dmarc: string, spf?: string) => {
    const r = await analyseDomain('d.test', mk(dmarc, spf), { dkimSelector: 's1' });
    return `${r.score} ${r.categories[0].rating}`;
  };
  const rua = 'rua=mailto:d@d.test';
  assert.equal(await run(`v=DMARC1; p=reject; ${rua}`), '80 5');
  assert.equal(await run('v=DMARC1; p=reject'), '72 4', 'no reporting address');
  assert.equal(await run(`v=DMARC1; p=quarantine; ${rua}`), '72 4');
  assert.equal(await run('v=DMARC1; p=quarantine'), '64 4');
  assert.equal(await run(`v=DMARC1; p=quarantine; pct=50; ${rua}`), '64 4');
  assert.equal(await run(`v=DMARC1; p=reject; sp=none; ${rua}`), '56 3');
  assert.equal(await run(`v=DMARC1; p=none; ${rua}`), '56 3');
  assert.equal(await run(`v=DMARC1; p=none; sp=quarantine; ${rua}`), '48 3');
  assert.equal(await run('v=DMARC1; p=none'), '48 3');
  assert.equal(await run(''), '40 2', 'no DMARC at all');
  assert.equal(await run(`v=DMARC1; p=reject; ${rua}`, 'v=spf1 ?all'), '72 4');
  assert.equal(await run(`v=DMARC1; p=reject; ${rua}`, ''), '40 2', 'no SPF at all');
  assert.equal(await run('', ''), '0 0');
});

test('DMARC reports to another domain need its permission', async () => {
  const zone = { txt: { 'd.test': ['v=spf1 -all'], '_dmarc.d.test': ['v=DMARC1; p=reject; rua=mailto:r@reports.example'] as string[] }, mx: { 'd.test': [{ priority: 10, exchange: 'mx.d.test' }] }, a: { 'mx.d.test': ['192.0.2.1'] } };
  const denied = await analyseDomain('d.test', fakeDns(zone));
  assert.deepEqual((denied.checks.dmarc.data as { unauthorisedReports?: string[] }).unauthorisedReports, ['reports.example']);
  assert.equal(denied.score, 72);
  const allowed = await analyseDomain('d.test', fakeDns({ ...zone, txt: { ...zone.txt, 'd.test._report._dmarc.reports.example': ['v=DMARC1'] } }));
  assert.equal(allowed.score, 80);
});

test('a domain without email only needs SPF -all and DMARC reject', async () => {
  const txt = { 'parked.test': ['v=spf1 -all'], '_dmarc.parked.test': ['v=DMARC1; p=reject; rua=mailto:d@parked.test'] };
  const nullMx = await analyseDomain('parked.test', fakeDns({ txt, mx: { 'parked.test': [{ priority: 0, exchange: '' }] } }));
  assert.equal(nullMx.mailMode, 'no-mail');
  assert.equal(nullMx.score, 100);
  assert.equal(nullMx.checks.dkim.status, 'pass', 'DKIM is not required');

  // no MX at all, only a website address: also treated as a domain that sends no email
  const noMx = await analyseDomain('parked.test', fakeDns({ txt: { ...txt, '_dmarc.parked.test': ['v=DMARC1; p=reject'] }, a: { 'parked.test': ['192.0.2.7'] } }));
  assert.equal(noMx.mailMode, 'no-mail');
  assert.equal(noMx.score, 80, 'each gap costs 20 points without email');
  assert.equal(noMx.categories.length, 3);
});

test('without MX records SPF is not required and name servers come from the parent zone', async () => {
  const dns = fakeDns({ txt: { '_dmarc.icu.test': ['v=DMARC1; p=none'] }, a: { 'research.icu.test': ['192.0.2.9'] } });
  const ns = { ...dns, ns: async (n: string) => (n === 'icu.test' ? ['ns1.cloudflare.com'] : []) };
  const r = await analyseDomain('research.icu.test', ns);
  assert.equal(r.mailMode, 'no-mail');
  assert.equal(r.checks.spf.notRequired, true);
  assert.equal(r.score, 20, 'p=none (3) and no rua (1): four gaps');
  assert.deepEqual(r.common.ns, ['ns1.cloudflare.com']);
});

test('SPF includes that use macros are counted but not followed', async () => {
  const dns = fakeDns({ txt: { 'm.test': ['v=spf1 include:%{i}._ip.%{h}._ehlo.%{d}._spf.vali.example include:_spf.m.test ~all'], '_spf.m.test': ['v=spf1 ip4:192.0.2.0/24 -all'] } });
  const a = await analyzeSpf('m.test', dns);
  assert.equal(a.status, 'valid');
  assert.equal(a.lookups, 2);
});

test('header analysis', () => {
  const raw = [
    'Received: from mx.out.test (mx.out.test [198.51.100.9]) by mx.in.test with ESMTPS id abc; Tue, 2 Jan 2024 10:00:30 +0000',
    'Received: from laptop (unknown [203.0.113.5])',
    '\tby mx.out.test with ESMTPSA id xyz; Tue, 2 Jan 2024 10:00:00 +0000',
    'Authentication-Results: mx.in.test; spf=pass smtp.mailfrom=out.test; dkim=fail header.d=other.test; dmarc=fail header.from=bank.test',
    'DKIM-Signature: v=1; a=rsa-sha256; d=other.test; s=s1; b=abc',
    'From: "Bank" <alerts@bank.test>',
    'Reply-To: <help@evil.test>',
    'Return-Path: <bounce@out.test>',
    'Subject: Urgent',
    '',
    'body here',
  ].join('\n');
  const r = analyseHeaders(raw);
  assert.equal(r.hops.length, 2);
  assert.equal(r.hops[0].ip, '203.0.113.5', 'oldest hop first');
  assert.equal(r.hops[1].delaySeconds, 30);
  assert.equal(r.auth.find((a) => a.method === 'dmarc')?.result, 'fail');
  assert.ok(r.findings.some((f) => f.text.includes('Replies go to a different domain')));
  assert.ok(r.findings.some((f) => f.level === 'bad' && f.text.startsWith('DMARC')));
  assert.equal(r.summary.Subject, 'Urgent');
});

test('reads headers from .eml and Outlook .msg files', () => {
  const eml = 'Received: from a by b; Tue, 2 Jan 2024 10:00:00 +0000\nFrom: x@y.test\nSubject: Hi\n\nbody';
  const e = headersFromFile(new TextEncoder().encode(eml).buffer as ArrayBuffer);
  assert.equal(e.kind, 'eml');
  assert.equal(analyseHeaders(e.text).summary.Subject, 'Hi');

  // a fake .msg: OLE signature, binary junk, then UTF-16LE transport headers
  const hdr = 'Received: from mx.test by mx2.test; Tue, 2 Jan 2024 10:00:00 +0000\r\nFrom: a@b.test\r\nSubject: Outlook\r\n';
  const utf16 = new Uint8Array(hdr.length * 2);
  for (let i = 0; i < hdr.length; i++) utf16[i * 2] = hdr.charCodeAt(i);
  const msg = new Uint8Array([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1, ...new Array(64).fill(7), ...utf16, 0, 0, 0, 0]);
  const m = headersFromFile(msg.buffer);
  assert.equal(m.kind, 'msg');
  assert.equal(analyseHeaders(m.text).summary.Subject, 'Outlook');
  assert.throws(() => headersFromFile(new Uint8Array([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1, 1, 2, 3, 4, 5, 6, 7, 8]).buffer));
});

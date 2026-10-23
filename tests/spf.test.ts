import assert from 'node:assert/strict';
import { test } from 'node:test';

import { analyzeSpf, evaluateSpf, expandMacros, parseSpf, spfTree } from '../src/lib/checks/spf.ts';
import { parseIp } from '../src/lib/net.ts';
import { fakeDns } from './fake-dns.ts';

const dns = fakeDns({
  txt: {
    'example.com': ['v=spf1 ip4:192.0.2.0/24 include:_spf.mail.test mx a:web.example.com -all', 'google-site-verification=abc'],
    '_spf.mail.test': ['v=spf1 ip6:2001:db8:aa::/48 ip4:203.0.113.10 ~all'],
    'soft.test': ['v=spf1 ~all'],
    'redir.test': ['v=spf1 redirect=example.com'],
    'two.test': ['v=spf1 -all', 'v=spf1 ~all'],
    'loop.test': ['v=spf1 include:l1.test include:l2.test include:l3.test include:l4.test include:l5.test include:l6.test -all'],
    'l1.test': ['v=spf1 include:l7.test include:l8.test -all'], 'l2.test': ['v=spf1 include:l9.test -all'], 'l3.test': ['v=spf1 include:l10.test include:l11.test -all'], 'l10.test': ['v=spf1 -all'], 'l11.test': ['v=spf1 -all'], 'l4.test': ['v=spf1 -all'],
    'l5.test': ['v=spf1 -all'], 'l6.test': ['v=spf1 -all'], 'l7.test': ['v=spf1 -all'], 'l8.test': ['v=spf1 -all'], 'l9.test': ['v=spf1 -all'],
    'missinginc.test': ['v=spf1 include:nothing.test -all'],
    'plus.test': ['v=spf1 +all'],
  },
  mx: { 'example.com': [{ priority: 10, exchange: 'mx1.example.com' }] },
  a: { 'mx1.example.com': ['198.51.100.25'], 'web.example.com': ['198.51.100.80'] },
});

test('parses mechanisms, qualifiers and prefixes', () => {
  const { terms, errors } = parseSpf('v=spf1 -ip4:10.0.0.0/8 a/24 mx:mail.x//64 ~all redirect=x.test');
  assert.deepEqual(errors, []);
  assert.equal(terms[0].kind === 'mechanism' && terms[0].value, '10.0.0.0/8');
  assert.equal(terms[1].kind === 'mechanism' && terms[1].cidr4, 24);
  assert.equal(terms[2].kind === 'mechanism' && terms[2].cidr6, 64);
  assert.equal(terms[4].kind, 'modifier');
});

test('evaluates pass, fail and softfail', async () => {
  assert.equal((await evaluateSpf({ domain: 'example.com', ip: '192.0.2.44' }, dns)).result, 'pass');
  assert.equal((await evaluateSpf({ domain: 'example.com', ip: '203.0.113.10' }, dns)).result, 'pass', 'via include');
  assert.equal((await evaluateSpf({ domain: 'example.com', ip: '2001:db8:aa::9' }, dns)).result, 'pass', 'IPv6 via include');
  assert.equal((await evaluateSpf({ domain: 'example.com', ip: '198.51.100.25' }, dns)).result, 'pass', 'mx');
  assert.equal((await evaluateSpf({ domain: 'example.com', ip: '198.51.100.80' }, dns)).result, 'pass', 'a:host');
  assert.equal((await evaluateSpf({ domain: 'example.com', ip: '8.8.8.8' }, dns)).result, 'fail');
  assert.equal((await evaluateSpf({ domain: 'soft.test', ip: '8.8.8.8' }, dns)).result, 'softfail');
  assert.equal((await evaluateSpf({ domain: 'redir.test', ip: '192.0.2.1' }, dns)).result, 'pass', 'redirect');
});

test('error cases', async () => {
  assert.equal((await evaluateSpf({ domain: 'nospf.test', ip: '8.8.8.8' }, dns)).result, 'none');
  assert.equal((await evaluateSpf({ domain: 'two.test', ip: '8.8.8.8' }, dns)).result, 'permerror');
  assert.equal((await evaluateSpf({ domain: 'missinginc.test', ip: '8.8.8.8' }, dns)).result, 'permerror');
  const loop = await evaluateSpf({ domain: 'loop.test', ip: '8.8.8.8' }, dns);
  assert.equal(loop.result, 'permerror');
  assert.match(loop.explanation, /Too many DNS lookups/);
});

test('macro expansion', () => {
  const ctx = { ip: parseIp('192.0.2.3')!, sender: 'alice@example.com', helo: 'mx.example.com', domain: 'example.com' };
  assert.equal(expandMacros('%{ir}.%{v}._spf.%{d2}', ctx), '3.2.0.192.in-addr._spf.example.com');
  assert.equal(expandMacros('%{l}', ctx), 'alice');
});

test('static analysis counts lookups and flags weak policies', async () => {
  const a = await analyzeSpf('example.com', dns);
  assert.equal(a.status, 'valid');
  assert.equal(a.allQualifier, '-');
  assert.equal(a.lookups, 3);
  assert.equal((await analyzeSpf('redir.test', dns)).allQualifier, '-', 'all is read through redirect=');
  const plus = await analyzeSpf('plus.test', dns);
  assert.ok(plus.issues.some((i) => i.includes('+all')));
  const loop = await analyzeSpf('loop.test', dns);
  assert.equal(loop.status, 'invalid');
  assert.ok(loop.lookups > 10);
});

test('record tree follows includes and redirects and counts lookups', async () => {
  const t = await spfTree('redir.test', dns);
  assert.equal(t.root.children[0].via, 'redirect');
  assert.equal(t.root.children[0].domain, 'example.com');
  assert.equal(t.all, '-');
  assert.equal(t.dnsLookups, 4, 'redirect + include + mx + a:host');
  assert.equal(t.mxLookups, 1);
  assert.ok(t.rootSize > 0);
});

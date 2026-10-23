import assert from 'node:assert/strict';
import { test } from 'node:test';

import { soaAdmin } from '../src/lib/analysis.ts';
import { contains, rangeToCidrs } from '../src/lib/cidr.ts';
import { decodeCaa, unquoteTxt } from '../src/lib/doh.ts';
import { headersFromFile } from '../src/lib/headers.ts';
import { dnsProvider, emailProvider, reportProviders } from '../src/lib/providers.ts';

test('IP in CIDR', () => {
  assert.ok(contains('192.168.1.0/24', '192.168.1.77'));
  assert.ok(!contains('192.168.1.0/24', '192.168.2.1'));
  assert.ok(contains('2001:db8::/32', '2001:db8:ffff::1'));
  assert.ok(!contains('10.0.0.0/8', '2001:db8::1'));
});

test('IP range to CIDR blocks', () => {
  assert.deepEqual(rangeToCidrs('10.0.0.0', '10.0.3.255'), ['10.0.0.0/22']);
  assert.deepEqual(rangeToCidrs('192.168.1.10', '192.168.1.20'), ['192.168.1.10/31', '192.168.1.12/30', '192.168.1.16/30', '192.168.1.20/32']);
  assert.deepEqual(rangeToCidrs('1.1.1.1', '1.1.1.1'), ['1.1.1.1/32']);
  assert.deepEqual(rangeToCidrs('2001:db8::', '2001:db8::ffff'), ['2001:db8::/112']);
  assert.throws(() => rangeToCidrs('10.0.0.5', '10.0.0.1'));
});

test('provider detection', () => {
  assert.equal(emailProvider(['axissolafrica-com.mail.protection.outlook.com']), 'Microsoft 365 Exchange');
  assert.equal(emailProvider(['aspmx.l.google.com']), 'Google Workspace');
  assert.equal(emailProvider([]), 'None');
  assert.equal(dnsProvider(['x.ns.joker.com']), 'Joker');
  assert.equal(dnsProvider(['ns1.example.net']), 'Unknown');
  assert.deepEqual(reportProviders(['mailto:a.nf5tbrka@sdmarc.net', 'mailto:domain@axissolafrica.com'], 'axissolafrica.com', 'axissolafrica.com'), ['Sendmarc', 'Self-managed']);
});

test('DNS answer decoding', () => {
  assert.equal(unquoteTxt('"v=DKIM1; k=rsa; " "p=MIGf"'), 'v=DKIM1; k=rsa; p=MIGf');
  assert.equal(unquoteTxt('"a\\"b"'), 'a"b');
  assert.equal(decodeCaa('\\# 19 00 05 69 73 73 75 65 6c 65 74 73 65 6e 63 72 79 70 74'), '0 issue "letsencrypt"');
  assert.equal(soaAdmin('x.ns.joker.com. hostmaster.joker.com. 2026060457 14400 3600 1209600 300'), 'hostmaster@joker.com');
  assert.equal(soaAdmin('ns1.example. john\\.smith.example.com. 1 2 3 4 5'), 'john.smith@example.com');
});

test('mbox files use the first message', () => {
  const mbox = 'From alice@example.com Tue Jan  2 10:00:00 2024\nSubject: First\nFrom: a@example.com\n\nbody\nFrom bob@example.com Tue Jan  2 11:00:00 2024\nSubject: Second\n\nx';
  const { text } = headersFromFile(new TextEncoder().encode(mbox).buffer as ArrayBuffer);
  assert.match(text, /Subject: First/);
  assert.doesNotMatch(text, /Second/);
});

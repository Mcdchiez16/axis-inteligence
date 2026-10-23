import assert from 'node:assert/strict';
import { test } from 'node:test';

import { describe as cidr, subnets } from '../src/lib/cidr.ts';
import { dnsblLabel, formatIPv6, inCidr, isPrivateOrReserved, parseIp } from '../src/lib/net.ts';

test('parses and formats IPv4 and IPv6', () => {
  assert.equal(parseIp('192.0.2.1')?.family, 4);
  assert.equal(parseIp('256.1.1.1'), null);
  assert.equal(parseIp('01.2.3.4'), null);
  assert.equal(formatIPv6(parseIp('2001:0db8:0000:0000:0000:0000:0000:0001')!.value), '2001:db8::1');
  assert.equal(parseIp('::ffff:198.51.100.7')?.family, 4, 'IPv4-mapped is treated as IPv4');
  assert.equal(parseIp('2001:db8::1::2'), null);
});

test('CIDR membership', () => {
  assert.ok(inCidr(parseIp('10.1.2.3')!, parseIp('10.0.0.0')!, 8));
  assert.ok(!inCidr(parseIp('11.0.0.1')!, parseIp('10.0.0.0')!, 8));
  assert.ok(inCidr(parseIp('2001:db8:1::5')!, parseIp('2001:db8::')!, 32));
});

test('private ranges are blocked for outbound fetches', () => {
  for (const ip of ['127.0.0.1', '10.0.0.5', '192.168.1.1', '169.254.169.254', '::1', 'fd00::1', '100.64.0.1']) assert.ok(isPrivateOrReserved(parseIp(ip)!), ip);
  for (const ip of ['8.8.8.8', '2606:4700::1111']) assert.ok(!isPrivateOrReserved(parseIp(ip)!), ip);
});

test('DNSBL labels', () => {
  assert.equal(dnsblLabel(parseIp('192.0.2.99')!), '99.2.0.192');
  assert.equal(dnsblLabel(parseIp('2001:db8::1')!).split('.').length, 32);
});

test('CIDR calculator', () => {
  const c = cidr('192.168.10.77/26');
  assert.equal(c.network, '192.168.10.64');
  assert.equal(c.lastAddress, '192.168.10.127');
  assert.equal(c.firstUsable, '192.168.10.65');
  assert.equal(c.usableHosts, '62');
  assert.equal(c.netmask, '255.255.255.192');
  assert.equal(cidr('10.0.0.1 255.255.255.0').network, '10.0.0.0');
  assert.equal(cidr('10.0.0.0/31').usableHosts, '2');
  assert.equal(cidr('2001:db8::/48').lastAddress, '2001:db8:0:ffff:ffff:ffff:ffff:ffff');
  assert.equal(subnets('10.0.0.0/24', 26).length, 4);
  assert.throws(() => cidr('10.0.0.0/33'));
});

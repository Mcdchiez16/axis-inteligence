/** IP address helpers built on BigInt, so IPv4 and IPv6 share one code path. */

export type IpFamily = 4 | 6;
export type ParsedIp = { family: IpFamily; value: bigint };

export function parseIPv4(s: string): bigint | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s.trim());
  if (!m) return null;
  let v = 0n;
  for (let i = 1; i <= 4; i++) {
    const n = Number(m[i]);
    if (n > 255 || (m[i].length > 1 && m[i].startsWith('0'))) return null;
    v = (v << 8n) | BigInt(n);
  }
  return v;
}

export function parseIPv6(input: string): bigint | null {
  let s = input.trim().toLowerCase();
  const zone = s.indexOf('%');
  if (zone >= 0) s = s.slice(0, zone);
  if (!s.includes(':')) return null;
  // embedded IPv4 tail, e.g. ::ffff:192.0.2.1
  const tail = /(\d+\.\d+\.\d+\.\d+)$/.exec(s);
  if (tail) {
    const v4 = parseIPv4(tail[1]);
    if (v4 === null) return null;
    s = s.slice(0, -tail[1].length) + ((v4 >> 16n) & 0xffffn).toString(16) + ':' + (v4 & 0xffffn).toString(16);
  }
  const halves = s.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':') : [];
  const rest = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const missing = 8 - head.length - rest.length;
  if ((halves.length === 1 && head.length !== 8) || (halves.length === 2 && missing < 1)) return null;
  const groups = [...head, ...Array(halves.length === 2 ? missing : 0).fill('0'), ...rest];
  if (groups.length !== 8) return null;
  let v = 0n;
  for (const g of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
    v = (v << 16n) | BigInt(parseInt(g, 16));
  }
  return v;
}

export function parseIp(s: string): ParsedIp | null {
  const v4 = parseIPv4(s);
  if (v4 !== null) return { family: 4, value: v4 };
  const v6 = parseIPv6(s);
  if (v6 === null) return null;
  // IPv4-mapped IPv6 (::ffff:a.b.c.d) behaves as IPv4
  if (v6 >> 32n === 0xffffn) return { family: 4, value: v6 & 0xffffffffn };
  return { family: 6, value: v6 };
}

export function formatIPv4(v: bigint): string {
  return [24n, 16n, 8n, 0n].map((sh) => Number((v >> sh) & 0xffn)).join('.');
}

/** Canonical (compressed) IPv6 text. */
export function formatIPv6(v: bigint): string {
  const groups = Array.from({ length: 8 }, (_, i) => Number((v >> BigInt((7 - i) * 16)) & 0xffffn));
  let bestStart = -1;
  let bestLen = 0;
  for (let i = 0; i < 8; ) {
    if (groups[i] !== 0) {
      i++;
      continue;
    }
    let j = i;
    while (j < 8 && groups[j] === 0) j++;
    if (j - i > bestLen && j - i > 1) {
      bestStart = i;
      bestLen = j - i;
    }
    i = j;
  }
  const hex = groups.map((g) => g.toString(16));
  if (bestStart < 0) return hex.join(':');
  const left = hex.slice(0, bestStart).join(':');
  const right = hex.slice(bestStart + bestLen).join(':');
  return `${left}::${right}`;
}

export function format(ip: ParsedIp): string {
  return ip.family === 4 ? formatIPv4(ip.value) : formatIPv6(ip.value);
}

export function bits(family: IpFamily): number {
  return family === 4 ? 32 : 128;
}

/** Does `ip` fall inside network/prefix? Families must match. */
export function inCidr(ip: ParsedIp, network: ParsedIp, prefix: number): boolean {
  if (ip.family !== network.family) return false;
  const total = bits(ip.family);
  if (prefix < 0 || prefix > total) return false;
  const shift = BigInt(total - prefix);
  return ip.value >> shift === network.value >> shift;
}

/** Addresses an outbound request must never reach: loopback, private, link-local, CGNAT, multicast, etc. */
export function isPrivateOrReserved(ip: ParsedIp): boolean {
  const blocks4: [string, number][] = [
    ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16], ['172.16.0.0', 12],
    ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24],
    ['224.0.0.0', 4], ['240.0.0.0', 4],
  ];
  const blocks6: [string, number][] = [['::', 128], ['::1', 128], ['fc00::', 7], ['fe80::', 10], ['ff00::', 8], ['2001:db8::', 32], ['64:ff9b::', 96], ['100::', 64]];
  const list = ip.family === 4 ? blocks4 : blocks6;
  return list.some(([net, p]) => inCidr(ip, parseIp(net)!, p));
}

/** Reverse-DNS name for an address: 1.2.3.4 -> 4.3.2.1.in-addr.arpa, IPv6 -> nibble format. */
export function reverseName(ip: ParsedIp): string {
  if (ip.family === 4) return formatIPv4(ip.value).split('.').reverse().join('.') + '.in-addr.arpa';
  const hex = ip.value.toString(16).padStart(32, '0');
  return hex.split('').reverse().join('.') + '.ip6.arpa';
}

/** The DNSBL query label: IPv4 reversed octets, IPv6 reversed nibbles (no suffix). */
export function dnsblLabel(ip: ParsedIp): string {
  if (ip.family === 4) return formatIPv4(ip.value).split('.').reverse().join('.');
  return ip.value.toString(16).padStart(32, '0').split('').reverse().join('.');
}

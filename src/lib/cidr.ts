import { bits, format, parseIp, type ParsedIp } from './net.ts';

export type CidrInfo = {
  family: 4 | 6;
  input: string;
  prefix: number;
  network: string;
  lastAddress: string;
  firstUsable: string;
  lastUsable: string;
  netmask?: string;
  wildcard?: string;
  totalAddresses: string;
  usableHosts: string;
  isHost: boolean;
};

export class CidrError extends Error {}

/** Accepts "192.168.1.10/24", "192.168.1.10 255.255.255.0" or "2001:db8::/48". */
export function parseCidr(input: string): { ip: ParsedIp; prefix: number } {
  const s = input.trim();
  let addr = s;
  let prefix: number | undefined;
  const slash = s.split('/');
  if (slash.length === 2) {
    addr = slash[0];
    if (!/^\d{1,3}$/.test(slash[1])) throw new CidrError('The prefix after "/" must be a number');
    prefix = Number(slash[1]);
  } else {
    const parts = s.split(/\s+/);
    if (parts.length === 2) {
      addr = parts[0];
      const mask = parseIp(parts[1]);
      if (!mask || mask.family !== 4) throw new CidrError('The netmask is not valid');
      const bin = mask.value.toString(2).padStart(32, '0');
      if (!/^1*0*$/.test(bin)) throw new CidrError('The netmask is not contiguous');
      prefix = bin.indexOf('0') === -1 ? 32 : bin.indexOf('0');
    }
  }
  const ip = parseIp(addr);
  if (!ip) throw new CidrError('That is not a valid IP address');
  const max = bits(ip.family);
  prefix ??= max;
  if (prefix < 0 || prefix > max) throw new CidrError(`The prefix must be between 0 and ${max}`);
  return { ip, prefix };
}

export function describe(input: string): CidrInfo {
  const { ip, prefix } = parseCidr(input);
  const total = bits(ip.family);
  const hostBits = BigInt(total - prefix);
  const size = 1n << hostBits;
  const mask = ((1n << BigInt(total)) - 1n) ^ (size - 1n);
  const network = ip.value & mask;
  const last = network + size - 1n;
  const v = (n: bigint): ParsedIp => ({ family: ip.family, value: n });
  const isV4 = ip.family === 4;
  // IPv4 reserves the network and broadcast address except in /31 and /32; IPv6 has no broadcast.
  const reserves = isV4 && prefix < 31;
  return {
    family: ip.family,
    input,
    prefix,
    network: format(v(network)),
    lastAddress: format(v(last)),
    firstUsable: format(v(reserves ? network + 1n : network)),
    lastUsable: format(v(reserves ? last - 1n : last)),
    netmask: isV4 ? format(v(mask)) : undefined,
    wildcard: isV4 ? format(v((size - 1n) & 0xffffffffn)) : undefined,
    totalAddresses: size.toLocaleString('en-US'),
    usableHosts: (reserves ? size - 2n : size).toLocaleString('en-US'),
    isHost: ip.value !== network,
  };
}

/** Split a network into equal smaller subnets (capped so the browser stays responsive). */
export function subnets(input: string, newPrefix: number, limit = 256): { cidr: string; first: string; last: string }[] {
  const { ip, prefix } = parseCidr(input);
  const total = bits(ip.family);
  if (newPrefix <= prefix || newPrefix > total) throw new CidrError(`Choose a prefix between ${prefix + 1} and ${total}`);
  const size = 1n << BigInt(total - newPrefix);
  const mask = ((1n << BigInt(total)) - 1n) ^ ((1n << BigInt(total - prefix)) - 1n);
  const start = ip.value & mask;
  const count = 1n << BigInt(newPrefix - prefix);
  const out = [];
  for (let i = 0n; i < count && i < BigInt(limit); i++) {
    const net = start + i * size;
    out.push({ cidr: `${format({ family: ip.family, value: net })}/${newPrefix}`, first: format({ family: ip.family, value: net }), last: format({ family: ip.family, value: net + size - 1n }) });
  }
  return out;
}

/** Is `ip` inside `cidr`? */
export function contains(cidr: string, ip: string): boolean {
  const net = parseCidr(cidr);
  const addr = parseIp(ip);
  if (!addr) throw new CidrError('That is not a valid IP address');
  if (addr.family !== net.ip.family) return false;
  const total = bits(addr.family);
  const shift = BigInt(total - net.prefix);
  return addr.value >> shift === net.ip.value >> shift;
}

/** The smallest list of CIDR blocks that exactly covers first..last. */
export function rangeToCidrs(first: string, last: string): string[] {
  const a = parseIp(first);
  const b = parseIp(last);
  if (!a || !b) throw new CidrError('Enter two valid IP addresses');
  if (a.family !== b.family) throw new CidrError('Both addresses must be IPv4, or both IPv6');
  if (a.value > b.value) throw new CidrError('The first address must not be after the last');
  const total = bits(a.family);
  const out: string[] = [];
  let cur = a.value;
  while (cur <= b.value && out.length < 512) {
    // largest block aligned at `cur` that does not run past `last`
    let size = 0;
    while (size < total && ((cur >> BigInt(size)) & 1n) === 0n && cur + (1n << BigInt(size + 1)) - 1n <= b.value) size++;
    out.push(`${format({ family: a.family, value: cur })}/${total - size}`);
    cur += 1n << BigInt(size);
  }
  return out;
}

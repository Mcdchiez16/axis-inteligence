/**
 * Email header analysis. Runs in the browser: pasted headers never leave the visitor's machine.
 */

export type Header = { name: string; value: string };
export type Hop = { index: number; from?: string; by?: string; with?: string; ip?: string; date?: Date; delaySeconds?: number; raw: string };
export type AuthResult = { method: string; result: string; detail: string };
export type DkimSig = { domain?: string; selector?: string; algorithm?: string };
export type HeaderFinding = { level: 'ok' | 'info' | 'warn' | 'bad'; text: string };

export type HeaderReport = {
  headers: Header[];
  summary: Record<string, string | undefined>;
  hops: Hop[];
  totalDelaySeconds?: number;
  auth: AuthResult[];
  dkim: DkimSig[];
  findings: HeaderFinding[];
};

export function splitHeaders(raw: string): Header[] {
  // headers end at the first blank line; continuation lines start with whitespace
  const block = raw.replace(/\r\n/g, '\n').split(/\n\s*\n/)[0];
  const out: Header[] = [];
  for (const line of block.split('\n')) {
    if (/^[ \t]/.test(line) && out.length) out[out.length - 1].value += ' ' + line.trim();
    else {
      const i = line.indexOf(':');
      if (i > 0 && /^[!-9;-~]+$/.test(line.slice(0, i))) out.push({ name: line.slice(0, i).trim(), value: line.slice(i + 1).trim() });
    }
  }
  return out;
}

const get = (hs: Header[], name: string) => hs.find((h) => h.name.toLowerCase() === name.toLowerCase())?.value;
const all = (hs: Header[], name: string) => hs.filter((h) => h.name.toLowerCase() === name.toLowerCase()).map((h) => h.value);

export function addressDomain(v?: string): string | undefined {
  const m = /<([^>]+)>/.exec(v ?? '') ?? /([^\s<>"]+@[^\s<>"]+)/.exec(v ?? '');
  const addr = m?.[1];
  return addr?.includes('@') ? addr.split('@').pop()!.toLowerCase().replace(/[>\s]/g, '') : undefined;
}

export function parseReceived(value: string, index: number): Hop {
  const semi = value.lastIndexOf(';');
  const dateText = semi >= 0 ? value.slice(semi + 1).trim() : undefined;
  const body = semi >= 0 ? value.slice(0, semi) : value;
  const from = /\bfrom\s+([^\s(;]+)/i.exec(body)?.[1];
  const by = /\bby\s+([^\s(;]+)/i.exec(body)?.[1];
  const withP = /\bwith\s+([^\s(;]+)/i.exec(body)?.[1];
  const ip = /\[(?:IPv6:)?([0-9a-f.:]+)\]/i.exec(body)?.[1] ?? /\(([0-9]{1,3}(?:\.[0-9]{1,3}){3})\)/.exec(body)?.[1];
  const d = dateText ? new Date(dateText.replace(/\s*\([^)]*\)\s*$/, '')) : undefined;
  return { index, from, by, with: withP, ip, date: d && !Number.isNaN(d.getTime()) ? d : undefined, raw: value };
}

export function parseAuthResults(value: string): AuthResult[] {
  // "mx.google.com; spf=pass (...) smtp.mailfrom=x; dkim=pass header.i=@d; dmarc=pass ..."
  return value
    .split(';')
    .slice(1)
    .map((part) => part.trim())
    .map((part) => {
      const m = /^([a-z0-9-]+)\s*=\s*([a-z]+)\s*(.*)$/i.exec(part);
      return m ? { method: m[1].toLowerCase(), result: m[2].toLowerCase(), detail: m[3].trim() } : null;
    })
    .filter((x): x is AuthResult => !!x);
}

export function analyseHeaders(raw: string): HeaderReport {
  const headers = splitHeaders(raw);
  const from = get(headers, 'From');
  const returnPath = get(headers, 'Return-Path');
  const replyTo = get(headers, 'Reply-To');
  const summary = {
    From: from,
    To: get(headers, 'To'),
    Subject: get(headers, 'Subject'),
    Date: get(headers, 'Date'),
    'Message-ID': get(headers, 'Message-ID'),
    'Return-Path': returnPath,
    'Reply-To': replyTo,
    'X-Mailer': get(headers, 'X-Mailer') ?? get(headers, 'User-Agent'),
  };

  // Received headers are prepended by each server, so the oldest is last; show them in travel order.
  const received = all(headers, 'Received').reverse();
  const hops = received.map((v, i) => parseReceived(v, i + 1));
  for (let i = 1; i < hops.length; i++) {
    const a = hops[i - 1].date;
    const b = hops[i].date;
    if (a && b) hops[i].delaySeconds = Math.round((b.getTime() - a.getTime()) / 1000);
  }
  const dated = hops.filter((h) => h.date);
  const totalDelaySeconds = dated.length > 1 ? Math.round((dated[dated.length - 1].date!.getTime() - dated[0].date!.getTime()) / 1000) : undefined;

  const auth = all(headers, 'Authentication-Results').flatMap(parseAuthResults);
  const dkim = all(headers, 'DKIM-Signature').map((v) => {
    const t: Record<string, string> = {};
    for (const p of v.split(';')) {
      const i = p.indexOf('=');
      if (i > 0) t[p.slice(0, i).trim().toLowerCase()] = p.slice(i + 1).trim();
    }
    return { domain: t.d, selector: t.s, algorithm: t.a };
  });

  const findings: HeaderFinding[] = [];
  if (!headers.length) findings.push({ level: 'bad', text: 'No headers were recognised. Paste the full original message source.' });
  const fromDomain = addressDomain(from);
  const rpDomain = addressDomain(returnPath);
  const rtDomain = addressDomain(replyTo);
  for (const method of ['spf', 'dkim', 'dmarc']) {
    const r = auth.find((a) => a.method === method);
    if (!r) findings.push({ level: 'info', text: `No ${method.toUpperCase()} result was recorded by the receiving server.` });
    else if (r.result === 'pass') findings.push({ level: 'ok', text: `${method.toUpperCase()} passed.` });
    else findings.push({ level: r.result === 'fail' ? 'bad' : 'warn', text: `${method.toUpperCase()} result: ${r.result}.` });
  }
  if (fromDomain && rpDomain && fromDomain !== rpDomain && !rpDomain.endsWith('.' + fromDomain)) findings.push({ level: 'info', text: `The envelope sender (${rpDomain}) differs from the visible From domain (${fromDomain}). Common for mailing services, but check it is expected.` });
  if (fromDomain && rtDomain && rtDomain !== fromDomain) findings.push({ level: 'warn', text: `Replies go to a different domain (${rtDomain}) than the sender (${fromDomain}). This is a common phishing trick.` });
  if (dkim.length && fromDomain && !dkim.some((d) => d.domain && (d.domain === fromDomain || fromDomain.endsWith('.' + d.domain)))) findings.push({ level: 'warn', text: `No DKIM signature is aligned with the From domain (${fromDomain}).` });
  const slow = hops.filter((h) => (h.delaySeconds ?? 0) > 300);
  if (slow.length) findings.push({ level: 'warn', text: `${slow.length} hop${slow.length > 1 ? 's' : ''} took more than five minutes.` });
  if (hops.some((h) => (h.delaySeconds ?? 0) < -60)) findings.push({ level: 'info', text: 'Some server clocks disagree, so a few delays are negative.' });

  return { headers, summary, hops, totalDelaySeconds, auth, dkim, findings };
}

export const MAX_FILE_BYTES = 25 * 1024 * 1024;

// Inside a .msg the headers follow binary data, so match the first strong header name anywhere.
const HEADER_START = /(Received|Return-Path|Delivered-To|Authentication-Results|ARC-Seal|DKIM-Signature|MIME-Version):/;

/**
 * Turn an uploaded message file into header text. Handles .eml/.txt (plain text) and Outlook .msg,
 * whose transport headers are stored as UTF-16 text inside a binary container. Runs in the browser.
 */
export function headersFromFile(buf: ArrayBuffer): { text: string; kind: 'eml' | 'msg' } {
  const bytes = new Uint8Array(buf);
  const isMsg = bytes.length > 8 && bytes[0] === 0xd0 && bytes[1] === 0xcf && bytes[2] === 0x11 && bytes[3] === 0xe0;
  if (!isMsg) {
    let text = new TextDecoder('utf-8').decode(bytes);
    // mbox: several messages separated by "From " lines; analyse the first one
    if (/^From \S+/.test(text)) text = text.replace(/^From [^\n]*\n/, '').split(/\nFrom [^\n]*\n/)[0];
    return { text, kind: 'eml' };
  }

  // .msg: the "transport message headers" property is a UTF-16LE string; find the block that looks like headers.
  for (const offset of [0, 1]) {
    const text = new TextDecoder('utf-16le').decode(bytes.subarray(offset, bytes.length - ((bytes.length - offset) % 2)));
    const m = HEADER_START.exec(text);
    if (!m) continue;
    const start = m.index;
    const rest = text.slice(start);
    const end = rest.search(/\u0000|[�]{2}/);
    const block = (end > 0 ? rest.slice(0, end) : rest.slice(0, 200_000)).replace(/\r\n/g, '\n');
    if (/^[\w-]+:/m.test(block) && block.length > 40) return { text: block, kind: 'msg' };
  }
  throw new Error('No email headers were found in this Outlook file. Open the message and copy its Internet headers instead.');
}

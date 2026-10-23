import { attempt, type DnsClient } from '../dns.ts';
import { inCidr, parseIp, type ParsedIp } from '../net.ts';

/**
 * SPF (RFC 7208): parsing, a full evaluator for "would this IP pass for this domain?", and a static
 * analyser used by the domain report (lookup count, qualifier, problems).
 */

export type SpfResult = 'pass' | 'fail' | 'softfail' | 'neutral' | 'none' | 'temperror' | 'permerror';
export type Qualifier = '+' | '-' | '~' | '?';

export type SpfTerm =
  | { kind: 'mechanism'; qualifier: Qualifier; name: string; value?: string; cidr4?: number; cidr6?: number; raw: string }
  | { kind: 'modifier'; name: string; value: string; raw: string };

export const MAX_LOOKUPS = 10;
export const MAX_VOID_LOOKUPS = 2;
const DNS_MECHANISMS = new Set(['include', 'a', 'mx', 'ptr', 'exists']);

export function isSpfRecord(txt: string): boolean {
  return /^v=spf1(\s|$)/i.test(txt.trim());
}

export function parseSpf(record: string): { terms: SpfTerm[]; errors: string[] } {
  const errors: string[] = [];
  const terms: SpfTerm[] = [];
  const parts = record.trim().split(/\s+/).slice(1);
  for (const raw of parts) {
    const mod = /^([a-z][a-z0-9_.-]*)=(.*)$/i.exec(raw);
    if (mod && !/^[+\-~?]?(a|mx|ptr|include|exists|ip4|ip6|all)[:/]?/i.test(raw)) {
      terms.push({ kind: 'modifier', name: mod[1].toLowerCase(), value: mod[2], raw });
      continue;
    }
    const m = /^([+\-~?])?([a-z0-9]+)(?::([^/\s]*))?(?:\/(\d{1,3}))?(?:\/\/(\d{1,3}))?$/i.exec(raw);
    if (!m) {
      errors.push(`Cannot read "${raw}"`);
      continue;
    }
    const name = m[2].toLowerCase();
    if (!['all', 'include', 'a', 'mx', 'ptr', 'ip4', 'ip6', 'exists'].includes(name)) {
      errors.push(`Unknown mechanism "${raw}"`);
      continue;
    }
    let value = m[3];
    let cidr4 = m[4] !== undefined ? Number(m[4]) : undefined;
    const cidr6 = m[5] !== undefined ? Number(m[5]) : undefined;
    // ip4:1.2.3.0/24 and ip6:2001:db8::/32 carry their prefix inside the value
    if (name === 'ip4' || name === 'ip6') {
      const v = /^(ip[46]):(.+)$/i.exec(raw.replace(/^[+\-~?]/, ''));
      value = v ? v[2] : value;
      cidr4 = undefined;
    }
    terms.push({ kind: 'mechanism', qualifier: (m[1] as Qualifier) ?? '+', name, value, cidr4, cidr6, raw });
  }
  return { terms, errors };
}

// ── macros (RFC 7208 section 7) ───────────────────────────────────────────────────────────────

export type MacroContext = { ip: ParsedIp; sender: string; helo: string; domain: string };

function ipToMacro(ip: ParsedIp): string {
  if (ip.family === 4) return [24n, 16n, 8n, 0n].map((s) => Number((ip.value >> s) & 0xffn)).join('.');
  return ip.value.toString(16).padStart(32, '0').split('').join('.');
}

export function expandMacros(spec: string, ctx: MacroContext): string {
  return spec.replace(/%\{([slodiphcrtv])(\d*)(r?)([.\-+,/_=]*)\}|%%|%_|%-/gi, (match, letter: string, digits: string, rev: string, delims: string) => {
    if (match === '%%') return '%';
    if (match === '%_') return ' ';
    if (match === '%-') return '%20';
    const [local, dom] = ctx.sender.includes('@') ? [ctx.sender.split('@')[0], ctx.sender.split('@')[1]] : ['postmaster', ctx.sender];
    const map: Record<string, string> = {
      s: ctx.sender,
      l: local,
      o: dom,
      d: ctx.domain,
      i: ipToMacro(ctx.ip),
      p: 'unknown',
      h: ctx.helo,
      v: ctx.ip.family === 4 ? 'in-addr' : 'ip6',
      c: ctx.ip.family === 4 ? ipToMacro(ctx.ip) : ipToMacro(ctx.ip),
      r: 'unknown',
      t: String(Math.floor(Date.now() / 1000)),
    };
    let value = map[letter.toLowerCase()] ?? '';
    let parts = value.split(new RegExp(`[${(delims || '.').replace(/[\]\\^-]/g, '\\$&')}]`));
    if (rev) parts = parts.reverse();
    if (digits) parts = parts.slice(-Number(digits));
    value = parts.join('.');
    return letter === letter.toUpperCase() ? encodeURIComponent(value) : value;
  });
}

// ── evaluation ──────────────────────────────────────────────────────────────────────────────────

export type TraceStep = { depth: number; text: string };
export type SpfEvaluation = {
  result: SpfResult;
  explanation: string;
  matched?: string;
  lookups: number;
  voidLookups: number;
  trace: TraceStep[];
  record?: string;
};

class SpfAbort extends Error {
  result: SpfResult;
  constructor(result: SpfResult, message: string) {
    super(message);
    this.result = result;
  }
}

type State = { lookups: number; voids: number; trace: TraceStep[]; ctx: MacroContext; dns: DnsClient };

const RESULT_FOR: Record<Qualifier, SpfResult> = { '+': 'pass', '-': 'fail', '~': 'softfail', '?': 'neutral' };

function count(state: State, what: string) {
  state.lookups += 1;
  if (state.lookups > MAX_LOOKUPS) throw new SpfAbort('permerror', `Too many DNS lookups (more than ${MAX_LOOKUPS}) while resolving ${what}`);
}

function voidHit(state: State, what: string) {
  state.voids += 1;
  if (state.voids > MAX_VOID_LOOKUPS) throw new SpfAbort('permerror', `Too many lookups that returned nothing (more than ${MAX_VOID_LOOKUPS}), at ${what}`);
}

async function addresses(state: State, host: string, family: 4 | 6): Promise<string[]> {
  const r = await attempt(() => (family === 4 ? state.dns.a(host) : state.dns.aaaa(host)));
  if (!r.ok) throw new SpfAbort('temperror', `DNS lookup for ${host} failed (${r.error})`);
  if (!r.value.length) voidHit(state, host);
  return r.value;
}

function prefixOf(term: Extract<SpfTerm, { kind: 'mechanism' }>, family: 4 | 6) {
  return family === 4 ? (term.cidr4 ?? 32) : (term.cidr6 ?? 128);
}

async function checkHost(state: State, domain: string, depth: number): Promise<{ result: SpfResult; matched?: string; record?: string }> {
  const t = (text: string) => state.trace.push({ depth, text });
  const txt = await attempt(() => state.dns.txt(domain));
  if (!txt.ok) {
    t(`Looking up TXT records for ${domain} failed (${txt.error})`);
    throw new SpfAbort('temperror', `Could not read the DNS records for ${domain}`);
  }
  const records = txt.value.filter(isSpfRecord);
  if (records.length === 0) {
    t(`${domain} publishes no SPF record`);
    return { result: 'none' };
  }
  if (records.length > 1) {
    t(`${domain} publishes ${records.length} SPF records; only one is allowed`);
    throw new SpfAbort('permerror', `${domain} publishes more than one SPF record`);
  }
  const record = records[0];
  t(`Found SPF record for ${domain}: ${record}`);
  const { terms, errors } = parseSpf(record);
  if (errors.length) throw new SpfAbort('permerror', `The SPF record for ${domain} has a syntax error: ${errors[0]}`);

  const ctx: MacroContext = { ...state.ctx, domain };
  const ip = state.ctx.ip;

  for (const term of terms) {
    if (term.kind !== 'mechanism') continue;
    if (DNS_MECHANISMS.has(term.name)) count(state, term.raw);
    let hit = false;

    switch (term.name) {
      case 'all':
        hit = true;
        break;
      case 'ip4':
      case 'ip6': {
        const [addr, pfx] = (term.value ?? '').split('/');
        const net = parseIp(addr);
        const want = term.name === 'ip4' ? 4 : 6;
        if (!net || net.family !== want) throw new SpfAbort('permerror', `Invalid address in ${term.raw}`);
        hit = inCidr(ip, net, pfx === undefined ? (want === 4 ? 32 : 128) : Number(pfx));
        break;
      }
      case 'a':
      case 'mx': {
        const target = term.value ? expandMacros(term.value, ctx) : domain;
        const family = ip.family;
        if (term.name === 'a') {
          const list = await addresses(state, target, family);
          hit = list.some((x) => {
            const p = parseIp(x);
            return p ? inCidr(ip, p, prefixOf(term, family)) : false;
          });
        } else {
          const mx = await attempt(() => state.dns.mx(target));
          if (!mx.ok) throw new SpfAbort('temperror', `DNS lookup for MX of ${target} failed (${mx.error})`);
          if (!mx.value.length) voidHit(state, target);
          if (mx.value.length > MAX_LOOKUPS) throw new SpfAbort('permerror', `${target} has more than ${MAX_LOOKUPS} MX hosts`);
          for (const host of mx.value) {
            count(state, `address of ${host.exchange}`);
            const list = await addresses(state, host.exchange, family);
            if (list.some((x) => { const p = parseIp(x); return p ? inCidr(ip, p, prefixOf(term, family)) : false; })) {
              hit = true;
              break;
            }
          }
        }
        break;
      }
      case 'exists': {
        const target = expandMacros(term.value ?? '', ctx);
        const list = await addresses(state, target, 4);
        hit = list.length > 0;
        break;
      }
      case 'ptr':
        // RFC 7208 says "SHOULD NOT use"; it is treated as a non-match here (and flagged by the analyser).
        t('ptr is discouraged and is not evaluated');
        hit = false;
        break;
      case 'include': {
        const target = expandMacros(term.value ?? '', ctx);
        t(`include:${target}, checking its policy`);
        const inner = await checkHost(state, target, depth + 1);
        if (inner.result === 'none') throw new SpfAbort('permerror', `include:${target} has no SPF record`);
        if (inner.result === 'permerror' || inner.result === 'temperror') throw new SpfAbort(inner.result, `include:${target} failed`);
        hit = inner.result === 'pass';
        t(`include:${target} returned ${inner.result}${hit ? ', so this mechanism matches' : ''}`);
        break;
      }
    }

    if (hit) {
      const result = RESULT_FOR[term.qualifier];
      t(`Matched "${term.raw}" → ${result}`);
      return { result, matched: term.raw, record };
    }
  }

  const redirect = terms.find((x) => x.kind === 'modifier' && x.name === 'redirect');
  if (redirect && redirect.kind === 'modifier') {
    count(state, `redirect=${redirect.value}`);
    const target = expandMacros(redirect.value, ctx);
    t(`No mechanism matched; following redirect=${target}`);
    const inner = await checkHost(state, target, depth + 1);
    if (inner.result === 'none') throw new SpfAbort('permerror', `redirect=${target} has no SPF record`);
    return inner;
  }

  t('No mechanism matched and there is no redirect → neutral');
  return { result: 'neutral', record };
}

/** The answer to "does this IP pass SPF for this domain?", with a plain-English trace of how it was decided. */
export async function evaluateSpf(input: { domain: string; ip: string; sender?: string; helo?: string }, dns: DnsClient): Promise<SpfEvaluation> {
  const ip = parseIp(input.ip);
  if (!ip) {
    return { result: 'permerror', explanation: 'The IP address is not valid', lookups: 0, voidLookups: 0, trace: [] };
  }
  const sender = input.sender?.includes('@') ? input.sender : `postmaster@${input.domain}`;
  const state: State = { lookups: 0, voids: 0, trace: [], ctx: { ip, sender, helo: input.helo || input.domain, domain: input.domain }, dns };
  try {
    const r = await checkHost(state, input.domain, 0);
    return { result: r.result, explanation: explain(r.result, r.matched), matched: r.matched, lookups: state.lookups, voidLookups: state.voids, trace: state.trace, record: r.record };
  } catch (e) {
    if (e instanceof SpfAbort) {
      state.trace.push({ depth: 0, text: e.message });
      return { result: e.result, explanation: e.message, lookups: state.lookups, voidLookups: state.voids, trace: state.trace };
    }
    throw e;
  }
}

function explain(result: SpfResult, matched?: string): string {
  switch (result) {
    case 'pass':
      return `The IP is authorised to send for this domain (matched ${matched ?? 'a mechanism'}).`;
    case 'fail':
      return 'The domain says this IP is NOT allowed to send its email (hard fail). Receivers should reject the message.';
    case 'softfail':
      return 'The domain says this IP is probably not allowed to send its email (soft fail). Receivers usually accept but mark it as suspicious.';
    case 'neutral':
      return 'The domain does not say whether this IP is allowed.';
    case 'none':
      return 'The domain does not publish an SPF record, so nothing can be checked.';
    case 'temperror':
      return 'A temporary DNS problem stopped the check. Try again.';
    case 'permerror':
      return 'The SPF record is broken and cannot be evaluated.';
  }
}

// ── static analysis for the domain report ──────────────────────────────────────────────────────────

export type SpfAnalysis = {
  present: boolean;
  records: string[];
  record?: string;
  /** 'pass' | 'softfail' | 'fail' | 'neutral' | 'permissive' (+all) | undefined when no "all" term */
  allQualifier?: Qualifier;
  lookups: number;
  voidLookups: number;
  includes: string[];
  issues: string[];
  status: 'missing' | 'multiple' | 'invalid' | 'valid';
  unreachable?: string;
};

/** Counts the DNS lookups a record would cause (the 10-lookup limit) by walking its includes and redirects. */
export async function analyzeSpf(domain: string, dns: DnsClient): Promise<SpfAnalysis> {
  const txt = await attempt(() => dns.txt(domain));
  if (!txt.ok) return { present: false, records: [], lookups: 0, voidLookups: 0, includes: [], issues: [], status: 'missing', unreachable: txt.error };
  const records = txt.value.filter(isSpfRecord);
  if (records.length === 0) return { present: false, records, lookups: 0, voidLookups: 0, includes: [], issues: [], status: 'missing' };
  if (records.length > 1) return { present: true, records, lookups: 0, voidLookups: 0, includes: [], issues: [`${records.length} SPF records are published; receivers treat this as an error. Merge them into one.`], status: 'multiple' };

  const record = records[0];
  const issues: string[] = [];
  const { terms, errors } = parseSpf(record);
  issues.push(...errors);

  let lookups = 0;
  let voids = 0;
  const includes: string[] = [];
  const seen = new Set<string>();

  async function walk(rec: string, name: string, depth: number) {
    const { terms: ts } = parseSpf(rec);
    for (const term of ts) {
      if (term.kind === 'mechanism' && DNS_MECHANISMS.has(term.name)) {
        lookups += 1;
        if (term.name === 'ptr') issues.push('The "ptr" mechanism is slow and discouraged; remove it.');
        if (term.name === 'mx') lookups += 0; // the MX host address lookups are counted when evaluated for a real IP
        // a macro include (%{i}, %{d}, ...) can only be resolved for a real message, so it is counted but not followed
        if (term.name === 'include' && term.value && !term.value.includes('%') && depth < 8 && !seen.has(term.value.toLowerCase())) {
          seen.add(term.value.toLowerCase());
          includes.push(term.value.toLowerCase());
          const inner = await attempt(() => dns.txt(term.value!));
          const innerRec = inner.ok ? inner.value.filter(isSpfRecord) : [];
          if (!inner.ok || innerRec.length === 0) {
            voids += 1;
            issues.push(`include:${term.value} has no SPF record, which makes the whole policy invalid.`);
          } else await walk(innerRec[0], term.value, depth + 1);
        }
      } else if (term.kind === 'modifier' && term.name === 'redirect' && !term.value.includes('%') && depth < 8 && !seen.has(term.value.toLowerCase())) {
        lookups += 1;
        seen.add(term.value.toLowerCase());
        const inner = await attempt(() => dns.txt(term.value));
        const innerRec = inner.ok ? inner.value.filter(isSpfRecord) : [];
        if (innerRec.length) await walk(innerRec[0], term.value, depth + 1);
        else issues.push(`redirect=${term.value} has no SPF record.`);
      }
    }
    void name;
  }
  await walk(record, domain, 0);

  // the effective "all" may live in a record reached through redirect=
  let all = terms.find((x) => x.kind === 'mechanism' && x.name === 'all');
  const hasRedirect = terms.some((x) => x.kind === 'modifier' && x.name === 'redirect');
  let cursor = terms;
  for (let hop = 0; !all && hop < 5; hop++) {
    const r = cursor.find((x) => x.kind === 'modifier' && x.name === 'redirect');
    if (!r || r.kind !== 'modifier') break;
    const next = await attempt(() => dns.txt(r.value));
    const rec = next.ok ? next.value.filter(isSpfRecord)[0] : undefined;
    if (!rec) break;
    cursor = parseSpf(rec).terms;
    all = cursor.find((x) => x.kind === 'mechanism' && x.name === 'all');
  }
  const allQualifier = all && all.kind === 'mechanism' ? all.qualifier : undefined;
  if (!all) issues.push(hasRedirect ? 'The redirected policy does not end with an "all" mechanism, so unlisted senders are not covered.' : 'The record does not end with an "all" mechanism, so unlisted senders are not covered.');
  if (allQualifier === '+') issues.push('"+all" lets anyone on the internet send as this domain. Change it to "-all" or "~all".');
  if (allQualifier === '?') issues.push('"?all" gives no protection. Use "-all" (or "~all" while testing).');
  if (allQualifier === '~') issues.push('"~all" is a soft fail. Move to "-all" once all legitimate senders are listed.');
  if (lookups > MAX_LOOKUPS) issues.push(`The record needs ${lookups} DNS lookups; the limit is ${MAX_LOOKUPS}. Receivers will return a permanent error. Remove includes or flatten the record.`);
  else if (lookups >= 8) issues.push(`${lookups} of ${MAX_LOOKUPS} allowed DNS lookups are used; there is little room left.`);
  if (terms.some((x) => x.kind === 'mechanism' && x.name === 'a' && !x.value && all && all.kind === 'mechanism' && all.qualifier === '+')) issues.push('The "a" mechanism combined with "+all" authorises every address.');

  const invalid = errors.length > 0 || lookups > MAX_LOOKUPS || voids > 0;
  return { present: true, records, record, allQualifier, lookups, voidLookups: voids, includes, issues, status: invalid ? 'invalid' : 'valid' };
}

// ── record tree for the Lookup tool and the SPF test ─────────────────────────────────────────────

export type SpfNode = { domain: string; via: 'root' | 'include' | 'redirect'; record?: string; error?: string; children: SpfNode[] };
export type SpfTree = { root: SpfNode; all?: Qualifier; dnsLookups: number; mxLookups: number; voidLookups: number; rootSize: number; errors: string[] };

/** Expands includes and redirects into a tree and counts lookups the way receivers do. */
export async function spfTree(domain: string, dns: DnsClient): Promise<SpfTree> {
  const errors: string[] = [];
  let dnsLookups = 0;
  let mxLookups = 0;
  let voidLookups = 0;
  let all: Qualifier | undefined;
  const seen = new Set<string>();

  async function visit(name: string, via: SpfNode['via'], depth: number): Promise<SpfNode> {
    const node: SpfNode = { domain: name, via, children: [] };
    if (depth > 10 || seen.has(name.toLowerCase())) {
      node.error = 'Loop or excessive nesting';
      errors.push(node.error);
      return node;
    }
    seen.add(name.toLowerCase());
    const txt = await attempt(() => dns.txt(name));
    if (!txt.ok) {
      node.error = `Lookup failed (${txt.error})`;
      return node;
    }
    const recs = txt.value.filter(isSpfRecord);
    if (recs.length === 0) {
      if (via !== 'root') voidLookups += 1;
      node.error = 'No SPF record';
      if (via !== 'root') errors.push(`${name} has no SPF record`);
      return node;
    }
    if (recs.length > 1) {
      node.error = 'More than one SPF record';
      errors.push(`${name} publishes more than one SPF record`);
    }
    node.record = recs[0];
    const { terms } = parseSpf(recs[0]);
    for (const t of terms) {
      if (t.kind === 'mechanism' && DNS_MECHANISMS.has(t.name)) {
        dnsLookups += 1;
        if (t.name === 'mx') {
          const target = t.value ?? name;
          const mx = await attempt(() => dns.mx(target));
          const n = mx.ok ? mx.value.length : 0;
          mxLookups += n;
          if (mx.ok && n === 0) voidLookups += 1;
        }
        if (t.name === 'include' && t.value && !t.value.includes('%')) node.children.push(await visit(t.value, 'include', depth + 1));
      }
    }
    const redirect = terms.find((t) => t.kind === 'modifier' && t.name === 'redirect');
    const ownAll = terms.find((t) => t.kind === 'mechanism' && t.name === 'all');
    if (via !== 'include' && ownAll && ownAll.kind === 'mechanism' && all === undefined) all = ownAll.qualifier;
    if (redirect && redirect.kind === 'modifier' && !ownAll) {
      dnsLookups += 1;
      node.children.push(await visit(redirect.value, 'redirect', depth + 1));
    }
    return node;
  }

  const root = await visit(domain, 'root', 0);
  if (dnsLookups > MAX_LOOKUPS) errors.push(`${dnsLookups} DNS lookups; the limit is ${MAX_LOOKUPS}`);
  return { root, all, dnsLookups, mxLookups, voidLookups, rootSize: root.record ? new TextEncoder().encode(root.record).length : 0, errors };
}

export const QUALIFIER_TEXT: Record<Qualifier, string> = {
  '-': 'Fail (-all): unlisted senders fail authentication',
  '~': 'Soft fail (~all): unlisted senders are marked as suspicious',
  '?': 'Neutral (?all): no statement about unlisted senders',
  '+': 'Pass (+all): anyone may send, which offers no protection',
};

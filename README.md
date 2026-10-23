# Axis Intelligence

Free email and domain security tools by Axis Solutions, in the Axis colours.

| Tool | What it does | Where it runs |
|---|---|---|
| Know Your Score | 0–100 score, grade and risk; Impersonation / Privacy / Branding ratings (0–5); NS/MX/A chips; detailed report; Email report and Download report (PDF) | Server (DNS) |
| Domain Analysis | Every protocol with badges, records, CNAME redirects, authority domain, DNS and email provider with TTLs, DNS admin | Server (DNS) |
| Lookup | DNS, DMARC, SPF (record tree and lookup counts), DKIM (known selectors), MTA-STS (with policy file), TLS-RPT, BIMI | Server (DNS) |
| Blocklist Lookup | IP or domain against Spamhaus, Barracuda, SpamCop and others | Server (DNS) |
| Header Analysis | Route, delays, SPF/DKIM/DMARC results and phishing signs from pasted headers | Browser only |
| SPF Policy Test | Email address + IP: full RFC 7208 evaluation, record tree and step-by-step trace | Server (DNS) |
| CIDR Calculator | IP-in-range check, CIDR to IP range (with subnet split), IP range to CIDR blocks | Browser only |
| DKIM Key Generator | RSA key pair plus the TXT record to publish | Browser only (key never leaves the device) |

## Run it

```bash
npm install
npm run dev        # http://localhost:3200
npm test           # engine tests (in-memory DNS)
npm run build && npm start
```

## Settings (environment variables)

- `DNS_SERVERS`: comma-separated resolvers for lookups (default: the system resolver).
- `DOH_URL`: DNS-over-HTTPS JSON endpoint for the Lookup and analysis TTLs (default Cloudflare).
- `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `SMTP_FROM`: turn on "Email report" delivery (the PDF is attached).
- `SALES_EMAIL`: where report requests and "Contact us" enquiries are forwarded.
- `DNSBL_RESOLVERS`: resolvers for blocklist queries. Spamhaus and others refuse queries from big public
  resolvers (8.8.8.8, 1.1.1.1); point this at your own recursive resolver for complete blocklist results.

## How the score works

The score is out of 100: Impersonation 80, Privacy 15, Branding 5. It was calibrated against the public
results of tools.sendmarc.com for 37 domains (36 identical; the odd one out uses an SPF macro include,
which can only be resolved for a real message).

- Impersonation starts at 80 and loses 8 points per gap: no DMARC record 5, no SPF record 5, p=none 3,
  sp=none 3, more than 10 SPF lookups 2, and 1 each for p=quarantine, sp=quarantine, pct below 100, no
  rua address, a rua address on another domain that has not authorised reports, and SPF `?all` or no
  `all`. DKIM is shown but not scored, because selectors cannot be listed from DNS. Rating: 0 gaps
  → 5, 1–2 → 4, 3–4 → 3, 5–6 → 2, 7–8 → 1, more → 0.
- Privacy: TLS-RPT 7, plus MTA-STS 8 in enforce mode or 6 in testing. Rating: points ÷ 3, rounded down.
- Branding: 5 for a valid SVG Tiny PS logo served directly, with no broken certificate and DMARC
  enforced; 2 for a valid logo with a problem around it; otherwise 0.

Risk: score 80+ low, 50+ moderate, otherwise high. A category is low risk at 5/5 and moderate at 4/5.
A domain without MX records (or with a null MX) does not send email: its score is 100 minus 20 per
impersonation gap, and DKIM is not required. Entering `www.` suggests the main domain, where email is
set up. Rules: `src/lib/score.ts`.

## Leads

"Email report" and "Contact us" store the form in `data/leads.jsonl` (git-ignored, readable only by the
server user). It contains names, phone numbers and email addresses: treat it as personal data.

## Safety

- MTA-STS and BIMI files are fetched over https only, without redirects, with a timeout and size cap, and
  never from private or internal addresses (checked at connection time to block DNS rebinding).
- Per-visitor rate limits on every API route, and a 5-minute cache for domain reports.
- Header, CIDR and DKIM tools run entirely in the browser.

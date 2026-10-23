# Deploying Axis Intelligence on Coolify

The app ships as a self-contained Docker image (built from the `Dockerfile`). It was built and
tested locally: the pages load, live scoring works, the PDF report generates, and leads are
written to `/app/data`.

## 1. Put the code in a Git repository
Coolify deploys from Git. This folder is not a repo yet, so once:

```bash
cd "Axis Intelligence"
git init
git add .
git commit -m "Axis Intelligence"
# create an empty private repo on GitHub/GitLab/Gitea, then:
git remote add origin <your-repo-url>
git push -u origin main
```

`.gitignore` already excludes `node_modules`, `.next`, `data/` and any `.env*` files, so no
secrets or build output are committed.

## 2. Create the application in Coolify
1. **New Resource → Application → Private/Public Repository**, and connect the repo above.
2. **Build Pack: `Dockerfile`** (Coolify finds the `Dockerfile` in the repo root).
3. **Port: `3200`** (the container listens on 3200).
4. Deploy once to confirm it builds and the page loads.

## 3. Domain and HTTPS
- Set the domain, e.g. `tools.axissolafrica.com`.
- Point that hostname's DNS (an A record) at the server's IP.
- Coolify issues and renews the HTTPS certificate automatically.

## 4. Environment variables
Add these in the app's **Environment Variables** panel (no quotes needed). All are optional —
without them, email features fall back to "download the report" and DNS still works.

| Variable | Example | Purpose |
|---|---|---|
| `SMTP_HOST` | `smtp.office365.com` | Mail server that sends report/contact emails |
| `SMTP_PORT` | `587` | 587 (STARTTLS) or 465 (SSL) |
| `SMTP_USER` | `reports@axissolafrica.com` | SMTP login |
| `SMTP_PASS` | `••••••••` | SMTP password / app password |
| `SMTP_FROM` | `Axis Intelligence <reports@axissolafrica.com>` | From address on sent mail |
| `SALES_EMAIL` | `sales@axissolafrica.com` | Where enquiries and report requests are sent |
| `DOH_URL` | `https://cloudflare-dns.com/dns-query` | DNS-over-HTTPS endpoint (default is fine) |
| `DNS_SERVERS` | `1.1.1.1,8.8.8.8` | Only if you prefer plain DNS over DoH |
| `DNSBL_RESOLVERS` | `1.1.1.1` | Resolver for blocklist checks (optional) |

DNS checks use DNS-over-HTTPS (port 443) by default, so they work even if the server blocks
normal DNS traffic. No extra setup needed.

## 5. Persist the leads (recommended)
Leads from "Email report" and "Contact us" are appended to `/app/data/leads.jsonl`. To keep them
across redeploys, add a **Persistent Storage / Volume** in Coolify:

- **Mount path:** `/app/data`

Without this, the file is recreated empty on every deploy. (If you'd rather store leads in a
database, say so and it can be switched.)

## 6. Redeploys
Push to the repo and Coolify rebuilds. The `data` volume and environment variables are kept.

---

### Notes
- Node 22 is pinned in the `Dockerfile`.
- The PDF report uses pdfkit's built-in fonts; the image copies the pdfkit package so these work.
- These email settings cover the **report/contact** emails only. The authorised spoof-demo
  feature (if built later) needs its own dedicated sending server, separate from this.

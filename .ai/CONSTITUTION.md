# certs.lol — Project Constitution

> Stable identity, architecture, and red lines. Changes here are rare and require discussion.

## What certs.lol Is

Fast, API-first TLS scanning tool at [certs.lol](https://certs.lol). Users enter a domain or IP → get a comprehensive TLS analysis with letter grade (A+ through F, T for trust errors). Part of the .lol family alongside [ns.lol](https://ns.lol) (DNS) and [yoke.lol](https://yoke.lol) (full domain intelligence).

## Architecture

| Layer | Technology | Location |
|-------|-----------|----------|
| Worker | Cloudflare Workers (TypeScript, zero-framework) | `src/` |
| SPA | Inline HTML/CSS/JS generated in `src/spa.ts` | `src/spa.ts` |
| Probe | Go binary on Fly.io (TLS scanning via uTLS + stdlib) | `probe/` (in yoke repo as `fly-proxy/`) |
| CLI | Go binary, goreleaser, Homebrew tap | `cli/` |
| Enrichment | Go compliance evaluation | `enrich/` |

### How It Works

1. **CF Worker** receives all requests. Content negotiation routes to JSON (curl/API) or HTML SPA (browsers). Security headers applied to all responses.
2. **Probe call** — the Worker calls the Fly.io probe at `PROBE_URL` (`https://yoke-probe.fly.dev`) with `FLY_AUTH_SECRET` auth. The probe performs the actual TLS handshake, cipher enumeration, and certificate chain inspection. The probe is **shared with Yoke** (the `fly-proxy/` in the yoke repo).
3. **Enrichment** runs in parallel with the probe: HSTS (direct HEAD request from Worker), HTTP/3 (via probe's `/probe-protocols` endpoint), DNS security (DNSSEC/CAA/DANE via Cloudflare DoH JSON API).
4. **Compliance mapping** evaluates the scan against PCI DSS 4.0, NIST SP 800-52r2, and HIPAA transport requirements via `evaluateCompliance()` in `src/compliance.ts`.
5. **Grade computation** happens in the Go probe (`probe/grade.go`) using a deductive model from A+ (perfect TLS 1.3 + forward secrecy + no weak ciphers) down to F (no TLS 1.2+).
6. **SPA** is a single function `html()` in `src/spa.ts` that returns complete HTML with embedded scan data. Same .lol family aesthetic: dark-mode, Inter + JetBrains Mono, terminal vibe.

### Storage

- **KV `CACHE`** — scan result caching (6h TTL), usage statistics (global, daily, top domains, error log).
- **Durable Object `RateLimiterDO`** — per-IP rate limiting (60 requests/hour). Sliding window counter with alarm-based cleanup.
- **No D1.** All state is KV + DO.

### Endpoints

| Endpoint | Purpose |
|----------|---------|
| `GET /:domain` | Scan a domain's TLS configuration |
| `GET /:ip` | Scan an IP address (DNS-dependent fields omitted) |
| `GET /:target?force` | Bypass cache, force fresh scan |
| `GET /` | Service info (JSON for API clients, SPA for browsers) |
| `GET /api/docs` | API documentation page |
| `GET /usage?key=ADMIN_KEY` | Usage dashboard (admin-only) |
| `GET /cli` | CLI installation and documentation page |
| `GET /install.sh` | CLI installer script |
| `GET /about` | About page |
| `GET /privacy` | Privacy policy |
| `GET /terms` | Terms of service |
| `GET /llms.txt` | LLM-friendly plain text description |
| `GET /robots.txt` | Search engine directives |
| `GET /sitemap.xml` | Sitemap |
| `GET /.well-known/security.txt` | Security contact |

### Content Negotiation

Same URL serves two formats based on `Accept` header and User-Agent:
- **JSON** — `Accept: application/json`, or CLI user agents (curl, httpie, wget, node, python, Go-http, axios)
- **HTML SPA** — browsers (`Accept: text/html`)

No plain-text output mode (unlike ns.lol).

### CLI

Go binary at `cli/` with same TLS scanning engine as the probe:
- **Pretty mode** (TTY) — colored tree output for humans
- **JSON mode** (piped / `--json`) — machine-readable, matches certs.lol API response shape
- **Assert mode** (`--assert` / `--profile`) — CI/CD gating with pass/fail exit codes
- **MX mode** (`--mx`) — resolve MX records and scan mail server TLS (port 25 STARTTLS)
- **Compare mode** (`compare a b`) — side-by-side comparison of two targets
- **Bulk mode** (stdin) — scan multiple targets from a file/pipe

Built with goreleaser, distributed via Homebrew tap (`yokedotlol/tap/certs`) and GitHub Releases.

## Cost Awareness

### Cloudflare ($5/mo Workers Paid plan)
- **Uncached scan:** 1 DO check (rate limit), 1 fetch to probe, 1 HEAD to target (HSTS), 1 fetch to probe (HTTP/3), 3 DoH fetches (DNSSEC/CAA/DANE), 1 KV write (cache), ~4 KV writes (stats)
- **Cached scan:** 1 DO check, 1 KV read (cache hit), ~2 KV writes (stats)

### Fly Probe
- **Shared with Yoke** — no separate Fly app for certs.lol. Probe is `yoke-probe.fly.dev`.

## Red Lines

- **No accounts, no signup.** API-first, open access, rate-limited only.
- **No tracking, no analytics, no cookies.** Privacy policy says "we collect nothing" — keep it that way.
- **No framework, no build tool beyond tsc.** SPA is a TypeScript template literal.
- **No external JS dependencies in the SPA.** Everything is inline in `spa.ts`.
- **No `--no-verify` on commits.**
- **Secrets never in code or wrangler.toml.** `FLY_AUTH_SECRET` and `ADMIN_KEY` are set via `wrangler secret put`.
- **Probe auth is required.** All probe endpoints require `Authorization: Bearer <FLY_AUTH_SECRET>`.
- **SSRF protection in the probe.** `CheckSSRF()` in `probe/ssrf.go` blocks connections to private/reserved IPs unless `AllowPrivate` is set (CLI only).

## Module Boundaries

- **Request handler:** `src/handler.ts` — routing, scan orchestration, static pages
- **Enrichment:** `src/enrich.ts` — HSTS, HTTP/3, DNS security (DNSSEC/CAA/DANE)
- **Compliance:** `src/compliance.ts` — PCI DSS 4.0, NIST 800-52r2, HIPAA evaluation
- **Rate limiter:** `src/rate-limiter.ts` — Durable Object with sliding window
- **Usage tracking:** `src/usage.ts` — KV-based stats (global, daily, top domains, errors)
- **SPA renderer:** `src/spa.ts` — full HTML/CSS/JS generation
- **Worker entry:** `src/worker.ts` — type definitions, worker export
- **Probe — TLS scanning:** `probe/tls.go` — core `Scan()` function
- **Probe — grading:** `probe/grade.go` — `ComputeGrade()` letter grade
- **Probe — cipher enumeration:** `probe/ciphers.go` — per-cipher probing
- **Probe — SSRF protection:** `probe/ssrf.go` — `CheckSSRF()` IP validation
- **Probe — STARTTLS:** `probe/starttls.go` — SMTP/IMAP/POP3 STARTTLS negotiation
- **Probe — uTLS:** `probe/utls.go` — Chrome fingerprint TLS connections
- **Probe — extensions:** `probe/extensions.go` — X.509 extension parsing (cert type, EKU, OCSP, etc.)
- **CLI:** `cli/` — Go binary with scan, compare, mx, assert, bulk subcommands
- **CLI assertions:** `cli/assert/` — assertion rule engine and built-in profiles

## .ai/ Maintenance Protocol

These files are maintained by AI agents **with human approval**:

- **CONSTITUTION.md** — Changes are rare. Always discuss before editing.
- **DECISIONS.md** — Append-only. Entries are never edited or removed.
- **INVARIANTS.md** — Adding or removing an invariant requires explicit human approval.
- **STATE.md** — Can be updated more freely; agent proposes changes, human confirms.
- **GOTCHAS.md** — Append when a new lesson is learned. Pair every "don't" with a "do."

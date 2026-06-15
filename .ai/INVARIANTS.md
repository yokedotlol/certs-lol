# certs.lol — Invariants

> Adding or removing an invariant requires explicit human approval.

## I01 — Grade is computed in the Go probe, never the Worker

`ComputeGrade()` in `probe/grade.go` is the single source of truth for letter grades. The Worker passes through the probe's grade as-is. No grade logic exists in TypeScript.

## I02 — Probe auth is always required

All probe endpoints require `Authorization: Bearer <FLY_AUTH_SECRET>`. The Worker sends this on every probe call. The probe rejects unauthenticated requests.

## I03 — SSRF protection blocks private IPs

`CheckSSRF()` in `probe/ssrf.go` blocks connections to RFC 1918, loopback, link-local, and other reserved IPs. Only the CLI can override this with `AllowPrivate` for local network scanning.

## I04 — Content negotiation: same URL, two formats

`wantsJSON(request)` in `handler.ts` checks `Accept` header and User-Agent. CLI-like UAs (curl, httpie, wget, node, python, Go-http, axios) get JSON. Browsers get HTML SPA. The URL never changes.

## I05 — Rate limiter uses Durable Objects, not KV

`RateLimiterDO` in `rate-limiter.ts` implements a sliding window counter. All scan requests count against the 60/hr limit. The DO provides strong consistency that KV cannot.

## I06 — Cache TTL is 6 hours for all scans

`CACHE_TTL = 21600` in `handler.ts`. Cached results are served from KV. `?force` bypasses cache. Cached responses include the original scan timestamp.

## I07 — Security headers on every response

`SECURITY_HEADERS` object in `handler.ts` is applied to every response: CSP, HSTS (with preload), X-Frame-Options DENY, COEP, COOP, etc.

## I08 — Grade ordering: A+ > A > B > C > D > F > T

`GradeOrder()` in `probe/grade.go` defines the ordering. T (trust error) is always the worst grade. `GradeAtLeast()` is used for assertion comparisons.

## I09 — Enrichment runs in parallel with probe scan

`enrich()` in `enrich.ts` fires HSTS check (direct HEAD), HTTP/3 check (via probe), and DNS security checks (DNSSEC/CAA/DANE via CF DoH) concurrently with the main TLS probe call. Results are merged into the final response.

## I10 — Compliance is evaluated in TypeScript, not Go

`evaluateCompliance()` in `compliance.ts` takes probe results + enrichment data and evaluates against PCI DSS 4.0, NIST 800-52r2, and HIPAA. This runs in the Worker, not the probe, because it needs the full merged dataset.

## I11 — Probe is shared with Yoke

The Fly machine at `yoke-probe.fly.dev` serves both Yoke and certs.lol. Probe code lives in the yoke repo at `fly-proxy/`. Deploying probe changes requires yoke repo CI.

## I12 — `_meta.full_report` links to Yoke on every API response

Every JSON response includes `_meta.full_report: "https://yoke.lol/{domain}"`. This is the one-way funnel. Yoke never links back.

## I13 — CLI matches API response shape in JSON mode

CLI's `--json` output uses the same schema as the API response. Consumers should be able to swap between `curl certs.lol/example.com` and `certs example.com --json` without changing parsers.

## I14 — uTLS fingerprint cascade order

`probe/utls.go` tries Chrome → Firefox → Safari → Randomized. The order matters because Chrome is the most commonly accepted fingerprint. Randomized is the last resort.

## I15 — No external JS in the SPA

`spa.ts` generates a complete HTML document with all CSS and JS inline. No CDN imports, no `<script src>`, no fetch for assets. The entire page is a single HTTP response.

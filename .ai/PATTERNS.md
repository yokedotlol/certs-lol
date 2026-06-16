# certs.lol — Patterns

> Operational guide: "do X this way." Distinct from GOTCHAS ("don't do X").

## Probe Lives in Yoke Repo

The TLS probe is shared infrastructure. Source is `fly-proxy/` in the yoke repo, deployed as `yoke-probe.fly.dev`. All probe code changes (TLS scanning, grading, cipher enumeration, SSRF, STARTTLS) happen there, not here.

This repo's Worker calls the probe via `PROBE_URL` with `FLY_AUTH_SECRET` auth.

## Grade Computation Lives in Go, Not TypeScript

Letter grades (A+ through F, T) are computed in `probe/grade.go`. The Worker receives the grade as part of the probe response. The TypeScript layer renders it but never computes it.

## uTLS Multi-Fingerprint Cascade

The probe uses uTLS to mimic real browser TLS handshakes. Connection attempts follow a fallback chain: Chrome → Firefox → Safari → Randomized. This handles CDNs (Cloudflare, Akamai) that reject non-browser fingerprints.

Entry point: `probe/utls.go`.

## Content Negotiation

Same URL serves JSON (curl/API) or HTML (browser). Detection in `handler.ts` checks `Accept` header + User-Agent patterns (curl, httpie, wget, node, python, Go-http, axios → JSON). No `?format=` parameter.

Rate limit errors also respect content negotiation via `rateLimitMessage()`.

## Enrichment Parallelism

Enrichment (HSTS, HTTP/3, DNS security) runs in parallel with the probe call. The Worker fires the probe fetch and all enrichment fetches concurrently, then merges results.

```
probe fetch ─────┐
HSTS HEAD ───────┤
HTTP/3 probe ────┼──> merge → grade + enrich → response
DNSSEC DoH ──────┤
CAA DoH ─────────┤
DANE DoH ────────┘
```

## SPA Is a Single Template Literal

All HTML/CSS/JS lives in `src/spa.ts` as a single function that returns a complete HTML string. No component system, no framework, no build step. Inline CSS + inline JS (nonce-protected CSP).

## Rate Limiter Is a Durable Object

Per-IP rate limiting uses a CF Durable Object with sliding window counters and alarm-based cleanup. NOT KV-based (KV is eventually consistent — bad for rate limiting).

60 requests/hour per IP. All requests count, including cache hits.

## Click-to-Copy on Data Values

All scan result values that a user might copy (IPs, cipher names, cert details, dates, fingerprints) use the `.data-val` class with click-to-copy behavior. Hover → accent color, click → clipboard + "copied" toast.

## CLI Assertion System

The CLI has a rule-based assertion engine (`cli/assert/`) with 31 rules across 7 categories and 7 named profiles (basic, intermediate, strict, pci-dss, nist, hipaa, modern). Exit code 0 = all pass, 1 = failures. Designed for CI/CD gating.

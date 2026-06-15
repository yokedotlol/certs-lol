# certs.lol — Current State

> Updated more freely than other .ai/ files. Reflects current project status.

## Overview

- **Live at:** [certs.lol](https://certs.lol)
- **Repo:** [yokedotlol/certs-lol](https://github.com/yokedotlol/certs-lol) (private)
- **Codebase:** ~6,780 lines across TypeScript Worker + Go probe + Go CLI
- **CI:** Two GitHub Actions workflows — `deploy.yml` (CF Worker), `release-cli.yml` (GoReleaser)
- **CLI:** v1.1.1 via Homebrew (`yokedotlol/tap/certs`) and GitHub Releases
- **Probe:** Shared with Yoke at `yoke-probe.fly.dev`

## File Layout

```
src/
  worker.ts          — entry point, type definitions
  handler.ts         — request routing, scan orchestration, static pages
  enrich.ts          — HSTS, HTTP/3, DNSSEC/CAA/DANE enrichment
  compliance.ts      — PCI DSS 4.0, NIST 800-52r2, HIPAA mapping
  compliance.test.ts — bun:test compliance tests
  rate-limiter.ts    — Durable Object sliding window rate limiter
  usage.ts           — KV-based usage/stats tracking
  spa.ts             — full HTML SPA generation
probe/
  tls.go             — core Scan() function
  grade.go           — ComputeGrade() letter grading
  ciphers.go         — per-cipher enumeration
  ssrf.go            — SSRF protection
  starttls.go        — SMTP/IMAP/POP3 STARTTLS
  utls.go            — uTLS multi-fingerprint dialer
  conn.go            — connection helpers
  extensions.go      — X.509 extension parsing
  types.go           — shared types
cli/                 — Go CLI binary
enrich/              — Go enrichment helpers
grade/               — Go grade helpers for CLI
```

## Storage

- **KV `CACHE`** (id: `0d85dda547614346baac52f5733a05f1`) — scan cache (6h TTL), usage stats
- **Durable Object `RateLimiterDO`** — per-IP rate limiting (60/hr)
- No D1

## Recent Changes

- **June 13:** ECDSA key_size fix, cipher classification overhaul, git squash
- **June:** MX port 25→587 auto-fallback, OG share banner, verbose flag, multi-IP fallback
- **Launch:** Fully live with CLI, announce pending

## Tech Debt / Known Issues

- Compliance tests use `bun:test` while the rest of the .lol family uses vitest — inconsistency
- No test coverage for handler.ts, enrich.ts, spa.ts, rate-limiter.ts, or usage.ts
- CDN pattern ordering in security checks (inherited from Yoke) means `.amazonaws.com` matches before more specific patterns — dead code for specific AWS sub-patterns

## Maintenance Cadence

- **Cipher suite classification:** Review after Go releases (new suites, deprecations)
- **Compliance standards:** PCI DSS ~3yr cycle, NIST revisions less frequent
- **Go dependencies:** Monthly for security patches, uTLS fingerprint freshness
- **CLI assertion profiles:** Update when compliance standards change

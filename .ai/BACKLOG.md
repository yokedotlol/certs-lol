# certs.lol — Backlog

> Known tech debt, pending work, and deferred improvements. Priority: P0 (blocking) → P4 (nice-to-have).

## P1 — Test Coverage

No test coverage for `handler.ts`, `enrich.ts`, `spa.ts`, `rate-limiter.ts`, or `usage.ts`. Only `compliance.test.ts` has tests, and it uses `bun:test` while the family standard is vitest.

## P2 — Announce / Launch Post

certs.lol is fully live with CLI v1.1.1, but hasn't been announced. Announce is gated on yoke.lol launching first (June 23). Plan: certs.lol announcement follows yoke launch.

## P3 — CDN Pattern Ordering

CDN pattern list in security checks (inherited from Yoke) has ordering issues: `.amazonaws.com` matches before more specific AWS sub-patterns, creating dead code for those specific patterns. Not a correctness issue (all match eventually), but messy.

## P4 — bun:test → vitest Migration

`compliance.test.ts` uses `bun:test`. Family standard is vitest. Migrate for consistency.

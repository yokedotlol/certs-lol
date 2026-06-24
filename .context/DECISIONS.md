# certs.lol — Decisions Log

> Append-only. Entries are never edited or removed.

## D001 — Shared probe with Yoke

**Date:** 2026-05 (project inception)
**Decision:** Reuse `yoke-probe.fly.dev` (Go binary from `fly-proxy/` in yoke repo) rather than deploying a separate Fly app for certs.lol.
**Rationale:** The TLS scanning logic lives in the probe's Go code. Running a second Fly machine for the same binary wastes money and doubles maintenance. Auth secret is shared (`FLY_AUTH_SECRET`).
**Consequence:** Changes to the probe affect both Yoke and certs.lol. Probe deploy is tied to the yoke repo's CI, not certs-lol's.

## D002 — Deductive grading in Go, not TypeScript

**Date:** 2026-05
**Decision:** Grade computation (`ComputeGrade()`) lives in `probe/grade.go`, not in the CF Worker.
**Rationale:** The probe already has the full TLS state (connection state, cert chain, cipher list) as native Go types. Sending raw state to the Worker for grading would mean serializing complex crypto objects. Grading in Go keeps it tight.
**Consequence:** Grade logic changes require a probe redeploy (yoke repo CI), not a Worker deploy.

## D003 — Durable Object for rate limiting, not KV

**Date:** 2026-05
**Decision:** Use a Durable Object (`RateLimiterDO`) with sliding window counter instead of KV-based rate limiting.
**Rationale:** KV's eventual consistency makes it unreliable for accurate per-IP counting. DO provides strong consistency with alarm-based cleanup. 60 req/hr limit requires accurate counting.
**Consequence:** DO adds a per-request subrequest cost, but it's negligible at current volumes.

## D004 — Rate limit counts ALL requests including cache hits

**Date:** 2026-05 (changed from initial "only fresh scans")
**Decision:** Every scan request (cached or not) counts against the 60/hr rate limit.
**Rationale:** Abuse prevention is the priority. Exempting cache hits lets someone hammer the endpoint with different domains. The rate limit exists to prevent resource abuse, not just probe abuse.

## D005 — uTLS multi-fingerprint fallback

**Date:** 2026-05
**Decision:** CLI and probe use uTLS (`utls.go`) with a fingerprint cascade: Chrome → Firefox → Safari → Randomized.
**Rationale:** Some servers (especially behind Cloudflare or Akamai) reject connections that don't look like a real browser TLS handshake. The cascade tries increasingly generic fingerprints until one succeeds.
**Consequence:** The `utls.go` module is the primary TLS dialer. Stdlib `tls.Dial` is not used directly for target connections.

## D006 — Inline SPA (same as ns.lol and yoke)

**Date:** 2026-05
**Decision:** SPA is a single `html()` function in `spa.ts` that returns a complete HTML string with embedded scan data. No framework, no bundler, no external JS.
**Rationale:** .lol family convention. Zero client-side dependencies, instant rendering, curl-friendly, CDN-cacheable.

## D007 — CLI assertion engine with named profiles

**Date:** 2026-06
**Decision:** CLI includes an assertion engine (`cli/assert/`) with 31 rules across 7 categories, and 7 named profiles (modern, standard, strict, pci, nist, hipaa, baseline).
**Rationale:** CI/CD TLS gating is a natural CLI use case. Named profiles map to compliance standards, making `certs example.com --profile pci` a one-liner for auditors.

## D008 — ECDSA key_size via Curve.Params().BitSize

**Date:** 2026-06-13
**Decision:** Fixed ECDSA key_size detection to use `*ecdsa.PublicKey` type assertion with `Curve.Params().BitSize`, falling back to byte-length calculation.
**Rationale:** Previous code always returned 0 for ECDSA keys because it only checked RSA/Ed25519 types. Verified on fresh scans (nmu.edu ECDSA 384-bit).

## D009 — Conservative cipher classification

**Date:** 2026-06-13
**Decision:** Dropped `tls.InsecureCipherSuites()` blanket classification. Now only RC4/NULL/EXPORT/anonymous = "insecure", CBC/non-ECDHE RSA = "weak".
**Rationale:** Go's `InsecureCipherSuites()` is overly aggressive — it flags CBC suites as insecure when they're merely weak. The new classification matches industry consensus (PCI DSS 4.0, NIST guidelines).

## D010 — MX port 25→587 auto-fallback

**Date:** 2026-06 (latest feature)
**Decision:** CLI's `--mx` mode tries STARTTLS on port 25 first, auto-falls back to port 587 if port 25 is blocked.
**Rationale:** Many residential ISPs and cloud providers block outbound port 25. Silently trying submission port (587) gives useful results instead of a confusing timeout.

## D011 — One-way funnel to Yoke

**Date:** 2026-06
**Decision:** Every certs.lol API response includes `_meta.full_report` linking to `yoke.lol/{domain}`. Yoke never links back to or mentions certs.lol.
**Rationale:** Yoke is the comprehensive domain intelligence tool; certs.lol is the specialist TLS scanner. The funnel drives users toward the full picture without creating circular references.

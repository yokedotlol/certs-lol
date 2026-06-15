# certs.lol — Gotchas

> Pair every "don't" with a "do." Append when a new lesson is learned.

## G01 — ECDSA key_size was always 0

**Symptom:** All ECDSA certificates showed `key_size: 0` in scan results.
**Root cause:** `probe/tls.go` only had type assertions for `*rsa.PublicKey` and `ed25519.PublicKey`. ECDSA keys fell through to the default 0.
**Fix:** Added `*ecdsa.PublicKey` type assertion using `Curve.Params().BitSize`, with byte-length fallback.
**Verification:** Fresh scan of nmu.edu confirmed ECDSA 384-bit. marquette.edu confirmed RSA 4096-bit still works.

## G02 — Cipher classification was too aggressive

**Symptom:** Common CBC cipher suites were being classified as "insecure" instead of "weak", tanking grades for sites with perfectly reasonable TLS configs.
**Root cause:** Code used Go's `tls.InsecureCipherSuites()` as a blanket classifier. Go considers CBC suites insecure due to Lucky13, but industry consensus (PCI DSS, NIST) classifies them as merely weak.
**Fix:** Dropped `InsecureCipherSuites()` blanket. Now: RC4/NULL/EXPORT/anonymous = "insecure", CBC/non-ECDHE RSA = "weak", everything else = "strong" or "acceptable".
**Don't:** Use Go's `InsecureCipherSuites()` for user-facing classification. **Do:** Classify based on specific cipher properties (key exchange, encryption mode, hash).

## G03 — Probe deploys are in the Yoke repo, not this one

**Don't:** Try to deploy probe changes from the certs-lol repo.
**Do:** Make probe changes in `fly-proxy/` in the yoke repo. The yoke repo CI deploys the probe.

## G04 — `PROBE_URL` is in `wrangler.toml`, secrets are not

`PROBE_URL` is a plain-text var in `wrangler.toml` (currently `https://yoke-probe.fly.dev`). But `FLY_AUTH_SECRET` and `ADMIN_KEY` are set via `wrangler secret put` and never appear in any committed file.
**Don't:** Put secrets in `wrangler.toml` or code.
**Do:** Use `wrangler secret put SECRET_NAME` for credentials.

## G05 — CLI port 25 often blocked by ISPs/cloud

**Symptom:** `certs --mx` hangs or times out for many users.
**Root cause:** Residential ISPs and cloud providers (AWS, GCP, Azure) block outbound TCP port 25 to prevent spam.
**Fix:** Auto-fallback to port 587 (submission port) when port 25 fails.
**Don't:** Assume port 25 is always reachable.

## G06 — Some servers reject non-browser TLS fingerprints

**Symptom:** Scans fail or return unexpected results for sites behind Cloudflare, Akamai, or other CDNs with bot detection.
**Root cause:** These services inspect the TLS ClientHello fingerprint (JA3) and reject connections that don't match known browser patterns.
**Fix:** uTLS with multi-fingerprint fallback (Chrome → Firefox → Safari → Randomized).
**Don't:** Use stdlib `tls.Dial` for target connections — it has a distinctive non-browser fingerprint.
**Do:** Use the `utls.go` dialer which mimics real browser handshakes.

## G07 — CF Workers can't do raw TCP/TLS

**Root cause:** Cloudflare Workers runtime has no `net` or `tls` module. You can only make HTTP(S) requests via `fetch()`.
**Consequence:** All actual TLS scanning must happen on the Fly probe. The Worker is an orchestrator, not a scanner.
**Don't:** Try to add TLS scanning logic to the TypeScript Worker.
**Do:** Add scanning features to the Go probe code.

## G08 — Git author was leaking personal email

**Symptom:** Commits attributed to personal email instead of project identity.
**Fix:** Git squash done June 13 — single commit `e69e4af`, author `Yoke <hello@yoke.lol>`, no kpayne@gmail.com in history.
**Don't:** Forget to set `git config user.email hello@yoke.lol` on fresh clones.

## G09 — Rate limit HTML vs JSON error format

The rate limit error response must match the content negotiation: JSON for API clients, HTML for browsers. The `rateLimitMessage()` function in `handler.ts` returns HTML; the handler wraps it appropriately based on `wantsJSON()`.
**Don't:** Return HTML error pages to curl/API clients.

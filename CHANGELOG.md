# Changelog

All notable changes to certs.lol are documented here.

## [1.1.1] — 2026-06-14

### Added
- **MX auto-fallback** — `--mx` scans now automatically fall back from port 25 to 587 when port 25 is blocked (common on ISPs and cloud providers). Shows a diagnostic hint if both ports fail.

### Fixed
- ECDSA key_size was always reported as 0 — fixed with proper `*ecdsa.PublicKey` type assertion via `Curve.Params().BitSize` with byte-length fallback.
- Cipher classification was too aggressive — dropped `tls.InsecureCipherSuites()` blanket. Now only RC4/NULL/EXPORT/anonymous = "insecure"; CBC/non-ECDHE RSA = "weak".

## [1.1.0] — 2026-06-13

### Added
- **CLI v1.0.0** — local TLS scanner with the same Go engine as the API.
  - 31 assertion rules across 7 categories (Grade, Certificate, Protocol, Ciphers, Security, Compliance, Mail).
  - 7 named profiles: `production`, `staging`, `strict`, `pci`, `nist`, `hipaa`, `baseline`.
  - `.certs.yaml` config file support (project and global).
  - STARTTLS support for SMTP (25/587), IMAP (143), POP3 (110) with auto-protocol detection.
  - `--mx` mode — resolve MX records and scan all mail servers.
  - `certs compare` — side-by-side TLS comparison.
  - Bulk scanning with `--file`, concurrent `--workers`, and `--out` directory with `_summary.json`.
  - JSON, pretty, grade-only, and CI output formats.
  - Homebrew tap: `brew install yokedotlol/tap/certs`.
- **curl|bash installer** — `curl -sSL https://certs.lol/install.sh | bash`.
- **`--verbose` flag** — connection diagnostics showing DNS resolution, dial attempts, and fallback decisions.
- **Multi-IP fallback** — when the primary IP fails, tries remaining resolved IPs.
- **uTLS fingerprint rotation** — cycles Chrome → Firefox → Safari → Randomized to bypass bot detection blocking default Go TLS handshakes.
- **Terminal-style OG share banner** — PNG share card for social previews.
- CLI link in site footer and CLI upsell on rate limit pages.
- **Force rescan** — `?force` query parameter bypasses cache.
- Cache indicator and rescan button in the SPA.
- CAA `iodef` contact display.

### Changed
- **Rate limit bumped to 60/hr** — all requests count (including cache hits) for abuse prevention.
- Shareable report link renamed and suppressed for IPs, internal hosts, and STARTTLS targets.

### Removed
- Trust strip removed from scan results (visual cleanup).

### Fixed
- GoReleaser uses plain semver tags.
- Always show `https://` in curl command on site.
- COEP set to `credentialless` (unblocks yoke.lol badge embedding).
- HTTP → HTTPS redirect via Cloudflare.

## [1.0.0] — 2026-06-12

### Added
- **certs.lol 1.0** — initial release.
  - Full TLS scanning: protocols, ciphers, certificates, chains, SCTs, OCSP stapling.
  - X.509 extension fields: cert type (DV/OV/EV), extended key usage, key usage, OCSP must-staple, OCSP responders, CRL endpoints, issuing cert URLs, policy OIDs, IP SANs.
  - Post-quantum (X25519MLKEM768) and ECH detection.
  - HSTS analysis including hstspreload.org list check.
  - HTTP/2, HTTP/3, and QUIC detection.
  - DNS security: DNSSEC, CAA, DANE/TLSA.
  - Compliance mapping: PCI DSS 4.0, NIST SP 800-52r2, HIPAA.
  - Content-negotiated API (JSON for CLI tools, HTML for browsers).
  - 6-hour KV result caching.
  - Rate limiting with standard headers.
  - SPA with formatted scan reports.
  - Go TLS probe on Fly.io, shared with yoke.lol.
  - SSRF protection (private IPs blocked by default on API).

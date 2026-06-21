# certs.lol 🔒

Fast, API-first TLS scanning. Real-time certificate and configuration analysis.

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Cloudflare Workers](https://img.shields.io/badge/runs%20on-Cloudflare%20Workers-F38020?logo=cloudflare&logoColor=white)](https://workers.cloudflare.com)

## Quick start

```bash
# API — full scan
curl -s https://certs.lol/stripe.com | jq

# API — just the grade
curl -s https://certs.lol/stripe.com | jq '.grade'

# CLI — install
brew install yokedotlol/tap/certs
# or
curl -sSL https://certs.lol/install.sh | bash

# CLI — scan
certs stripe.com

# CLI — scan mail servers
certs --mx gmail.com
```

Same URL, content-negotiated: `curl` gets JSON, browsers get a formatted report.

---

## CLI

The `certs` CLI runs the same Go TLS engine locally — no API calls, no rate limits, full control.

### Install

```bash
# Homebrew
brew install yokedotlol/tap/certs

# curl | bash
curl -sSL https://certs.lol/install.sh | bash

# Go
go install github.com/yokedotlol/certs-lol/cli@latest
```

### Basic usage

```bash
# Scan a domain
certs example.com

# Scan multiple targets
certs example.com cloudflare.com 1.1.1.1

# JSON output
certs --json example.com

# Grade only
certs --grade example.com

# Custom port
certs --port 8443 internal.example.com

# Verbose mode (connection diagnostics)
certs --verbose example.com
```

### Mail server scanning

Resolve MX records and scan every mail server's TLS config with `--mx`:

```bash
certs --mx gmail.com
```

This automatically:
- Resolves MX records sorted by priority
- Scans each mail server on port 25 with SMTP STARTTLS
- Falls back to port 587 if port 25 is blocked (common on ISPs and cloud providers)
- Reports per-server grades and TLS details

### STARTTLS

Scan mail and other STARTTLS services directly:

```bash
# SMTP (ports 25, 587)
certs --port 25 --starttls smtp mail.example.com
certs --port 587 --starttls smtp mail.example.com

# IMAP (port 143)
certs --port 143 --starttls imap mail.example.com

# POP3 (port 110)
certs --port 110 --starttls pop3 mail.example.com
```

Protocol is auto-detected for well-known ports (25/587 → SMTP, 143 → IMAP, 110 → POP3). Direct TLS ports (465, 993, 995) don't need `--starttls`.

### Compare

Side-by-side TLS comparison of two targets:

```bash
certs compare stripe.com paypal.com
```

### Assertions

Assert TLS properties and fail with a non-zero exit code when checks don't pass. Built for CI/CD pipelines.

```bash
# Single assertion
certs --assert "min-grade A" example.com

# Multiple assertions
certs --assert "min-grade A" --assert "no-tls1.0" --assert "cert-days 30" example.com

# Named profiles (bundles of assertions)
certs --profile production example.com
certs --profile strict example.com

# List all available rules
certs list-rules
```

**31 assertion rules** across 7 categories:

| Category | Rules |
|----------|-------|
| **Grade** | `min-grade` |
| **Certificate** | `cert-days`, `cert-type` (DV/OV/EV), `cert-key-min`, `cert-key-type`, `cert-san`, `cert-issuer`, `cert-chain-valid`, `cert-has-scts` |
| **Protocol** | `min-tls`, `max-tls`, `no-tls1.0`, `no-tls1.1`, `has-tls1.3`, `has-pq`, `has-ech` |
| **Ciphers** | `no-insecure-ciphers`, `no-weak-ciphers`, `max-weak-ciphers`, `min-strong-ciphers`, `has-forward-secrecy` |
| **Security** | `has-hsts`, `hsts-min-age`, `has-hsts-preload`, `has-dnssec`, `has-caa`, `has-ocsp-stapling` |
| **Compliance** | `compliant-pci`, `compliant-nist`, `compliant-hipaa` |
| **Mail** | `has-starttls` |

**7 named profiles:**

| Profile | What it checks |
|---------|---------------|
| `production` | Grade ≥ A, no TLS 1.0/1.1, no insecure ciphers, cert ≥ 14 days, HSTS |
| `staging` | Grade ≥ B, no insecure ciphers, cert ≥ 7 days |
| `strict` | Grade ≥ A+, TLS 1.3, PQ, FS, no weak/insecure ciphers, cert ≥ 30 days, HSTS preload, DNSSEC, SCTs |
| `pci` | PCI DSS 4.0 compliant, TLS 1.3, no weak/insecure ciphers, cert ≥ 30 days, HSTS |
| `nist` | NIST SP 800-52r2 compliant, TLS 1.3, no TLS 1.0/1.1, key ≥ 256-bit |
| `hipaa` | HIPAA compliant, no insecure ciphers, cert ≥ 30 days, HSTS |
| `baseline` | Grade ≥ C, no insecure ciphers, cert ≥ 7 days, valid chain |

**Exit codes:**

| Code | Meaning |
|------|---------|
| 0 | Scan succeeded, all assertions passed |
| 1 | Scan succeeded, assertion(s) failed |
| 2 | Usage error |
| 3 | Scan/connection error |

### Config file

Store targets, assertions, and profiles in `.certs.yaml` (project root) or `~/.config/certs/config.yaml` (global):

```yaml
profile: production
targets:
  - example.com
  - api.example.com
assertions:
  - "cert-days 30"
  - "has-hsts"
```

```bash
# Uses .certs.yaml from current directory
certs

# Explicit config file
certs --config path/to/config.yaml
```

### Bulk scanning

Scan many targets from a file with concurrent workers:

```bash
# Scan from file (10 workers by default)
certs --file targets.txt

# Custom concurrency
certs --file targets.txt --workers 20

# Save individual results to a directory
certs --file targets.txt --out results/

# Combine with assertions
certs --file targets.txt --profile production --out results/
```

Bulk scans write a `_summary.json` to the output directory with pass/fail counts and failed targets.

### CLI flags reference

```
Output:
  -j, --json              JSON output (default when piped)
  -t, --table             Force pretty output
  -g, --grade             Print only the letter grade

Scanning:
  -p, --port <N>          Port (default 443)
      --timeout <dur>     Connection timeout (default 15s)
      --starttls <proto>  Force STARTTLS protocol (smtp/imap/pop3)
      --probe-only        Skip enrichment (HSTS/DNS/compliance)
      --no-private        Block private/reserved IPs
  -v, --verbose           Show connection diagnostics
      --mx                Resolve MX records and scan mail servers

Assertions:
  -a, --assert <rule>     Assertion rule (repeatable)
  -P, --profile <name>    Named assertion profile
  -c, --config <path>     Config file (default .certs.yaml)

Bulk:
  -f, --file <path>       Read targets from file
  -o, --out <dir>         Write results to directory
  -w, --workers <N>       Concurrent workers (default 10)
  -q, --quiet             Suppress progress
```

---

## API

### What it scans

- **Protocol support** — TLS 1.3/1.2/1.1/1.0, forward secrecy, key exchange
- **Certificate** — chain validation, expiry, key type & size, SANs, serial, fingerprint, validation level (DV/OV/EV)
- **X.509 extensions** — extended key usage, key usage, OCSP must-staple, OCSP responders, CRL endpoints, issuing cert URLs, policy OIDs, IP SANs
- **Certificate chain** — full chain from leaf → intermediates → root with key algorithms and expiry
- **SCTs & OCSP** — Certificate Transparency timestamps, OCSP stapling
- **Cipher suites** — full enumeration with strength grading (strong/acceptable/weak/insecure)
- **Post-quantum** — X25519MLKEM768 hybrid key exchange detection
- **ECH** — Encrypted Client Hello support
- **HSTS** — max-age, includeSubDomains, preload directive, hstspreload.org list status
- **HTTP/2 & HTTP/3** — QUIC support, alt-svc header
- **DNS security** — DNSSEC validation, CAA records, DANE/TLSA
- **STARTTLS** — SMTP/IMAP/POP3 STARTTLS negotiation with auto-detection
- **Compliance** — transport encryption checks against PCI DSS 4.0, NIST SP 800-52r2, HIPAA

### Compliance mapping

Each scan evaluates TLS configuration against transport encryption requirements for three frameworks:

| Framework | What it checks |
|-----------|---------------|
| **PCI DSS 4.0** (Req 4.2.1) | TLS 1.2+, no weak ciphers, forward secrecy, valid cert, HSTS recommended |
| **NIST SP 800-52r2** | TLS 1.2+ (1.3 preferred), key size minimums, no weak ciphers, FS, OCSP recommended |
| **HIPAA** (§164.312(e)(1)) | TLS 1.2+, AES encryption, valid cert, forward secrecy recommended |

**Important:** These are transport-layer checks only. Full compliance requires organizational, procedural, and application-level controls that a TLS scan cannot assess.

### Content negotiation

| Client | Format |
|--------|--------|
| `curl`, `httpie`, `wget` | JSON |
| `Accept: application/json` | JSON |
| Browser | HTML |

### Rate limiting

- 60 scans per hour per IP (cached results do not count against the limit)
- Results cached for 6h
- `X-RateLimit-Limit` and `X-RateLimit-Remaining` headers on every response
- 429 response with `Retry-After` and `X-RateLimit-Reset` when exceeded

### API response

```json
{
  "grade": "A+",
  "target": "stripe.com",
  "issuer": "CN=DigiCert ...",
  "subject": "CN=stripe.com",
  "valid_from": "2025-01-15T00:00:00Z",
  "valid_to": "2026-01-15T23:59:59Z",
  "days_remaining": 72,
  "key_alg": "ECDSA",
  "key_size": 256,
  "signature_alg": "ECDSAWithSHA256",
  "protocols": ["TLS 1.3", "TLS 1.2"],
  "forward_secrecy": true,
  "key_exchange": "ECDHE (TLS 1.3)",
  "chain_valid": true,
  "chain_depth": 3,
  "chain_certs": [
    {
      "subject": "CN=stripe.com",
      "issuer": "CN=DigiCert ...",
      "valid_from": "2025-01-15T00:00:00Z",
      "valid_to": "2026-01-15T23:59:59Z",
      "key_alg": "ECDSA",
      "key_size": 256,
      "serial": "0A:1B:...",
      "signature_alg": "ECDSAWithSHA256",
      "is_self_signed": false
    }
  ],
  "sans": ["stripe.com", "*.stripe.com"],
  "serial": "0A:1B:...",
  "fingerprint": "sha256:AB12...",
  "ocsp_stapling": true,
  "ocsp_must_staple": false,
  "ocsp_servers": ["http://ocsp.digicert.com"],
  "has_scts": true,
  "sct_count": 2,
  "ext_key_usage": ["serverAuth"],
  "key_usage": ["digitalSignature"],
  "issuing_cert_url": ["http://cacerts.digicert.com/..."],
  "crl_endpoints": ["http://crl.digicert.com/..."],
  "is_ca": false,
  "policy_oids": ["2.23.140.1.1"],
  "ip_addresses": [],
  "starttls": false,
  "starttls_proto": "",
  "ciphers": [
    { "name": "TLS_AES_256_GCM_SHA384", "id": 4866, "strength": "strong" },
    { "name": "TLS_AES_128_GCM_SHA256", "id": 4865, "strength": "strong" }
  ],
  "cipher_summary": { "strong": 5, "acceptable": 2, "weak": 0, "insecure": 0 },
  "hsts": {
    "enabled": true,
    "max_age": 31536000,
    "include_subdomains": true,
    "preload": true,
    "on_preload_list": true
  },
  "http3": {
    "supported": true,
    "http2": true,
    "alt_svc": "h3=\":443\"; ma=86400"
  },
  "dns_security": {
    "dnssec": true,
    "caa": ["issue digicert.com"],
    "dane_tlsa": null
  },
  "compliance": [
    {
      "framework": "pci-dss-4",
      "display_name": "PCI DSS 4.0",
      "meets_requirements": true,
      "findings": [
        { "requirement": "Req 4.2.1", "status": "pass", "detail": "TLS 1.2+ supported" },
        { "requirement": "Req 4.2.1", "status": "pass", "detail": "No weak or insecure ciphers" },
        { "requirement": "Req 4.2.1", "status": "pass", "detail": "Forward secrecy enabled" },
        { "requirement": "Req 4.2.1", "status": "pass", "detail": "Valid certificate chain" },
        { "requirement": "Best Practice", "status": "pass", "detail": "HSTS enabled" }
      ]
    }
  ],
  "probe_ms": 142,
  "_meta": {
    "version": "1.0.0",
    "cache_hit": false,
    "cache_ttl": 21600,
    "docs": "https://certs.lol/api/docs",
    "full_report": "https://yoke.lol/stripe.com"
  }
}
```

**MX/STARTTLS scan response** includes additional fields:

```json
{
  "starttls": true,
  "starttls_proto": "smtp",
  "mx_host": "alt1.gmail-smtp-in.l.google.com",
  "mx_priority": 10,
  "fallback_port": 587
}
```

`fallback_port` is set when `--mx` fell back from port 25 (blocked) to port 587.

---

## Architecture

```
┌─────────────────────────────────────────────────┐
│  Cloudflare Worker (TypeScript)                 │
│  routing · enrichment · caching · compliance · SPA │
└────────────┬──────────────┬─────────────────────┘
             │              │
     ┌───────▼───────┐  ┌──▼──────────────────┐
     │  Go TLS probe │  │  Enrichment (Worker) │
     │  (Fly.io)     │  │  HSTS · HTTP/3 · DNS │
     └───────────────┘  └─────────────────────┘
```

- **Cloudflare Worker** — request routing, content negotiation, enrichment orchestration, compliance evaluation, KV caching, SPA rendering
- **Go TLS probe on Fly.io** — raw TLS handshakes, cipher enumeration, certificate chain parsing, protocol detection, STARTTLS negotiation, post-quantum & ECH checks, multi-IP fallback with uTLS fingerprint rotation (Chrome → Firefox → Safari → Randomized)
- **Shared probe** — the same engine powers the CLI locally and [yoke.lol](https://yoke.lol)'s security analysis

### Security

- **SSRF protection** — the API blocks connections to private/reserved IPs (RFC 1918, loopback, link-local) by default. The CLI allows private IPs for internal network scanning (`--no-private` to disable).
- **Timing-safe auth** — probe authentication uses constant-time comparison to prevent timing attacks.

## Self-hosting

Not one-command self-hostable yet, but it's MIT — knock yourself out. You'll need:
- A Cloudflare account with Workers and KV
- The Go TLS probe deployed somewhere (see the [yoke repo](https://github.com/yokedotlol/yoke))
- `PROBE_URL`, `FLY_AUTH_SECRET`, and `ADMIN_KEY` configured

## Links

- **Live:** https://certs.lol
- **CLI docs:** https://certs.lol/cli
- **API docs:** https://certs.lol/api/docs
- **Full reports:** https://yoke.lol
- **Homebrew:** `brew install yokedotlol/tap/certs`
- **Source:** https://github.com/yokedotlol/certs-lol

## License

MIT

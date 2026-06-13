# certs.lol 🔒

Fast, API-first TLS scanning.

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Cloudflare Workers](https://img.shields.io/badge/runs%20on-Cloudflare%20Workers-F38020?logo=cloudflare&logoColor=white)](https://workers.cloudflare.com)
[![Tests](https://img.shields.io/badge/tests-20%20passing-brightgreen?logo=bun&logoColor=white)](src/compliance.test.ts)

## Usage

```bash
# Full scan
curl -s https://certs.lol/stripe.com | jq

# Just the grade
curl -s https://certs.lol/stripe.com | jq '.grade'

# Scan an IP
curl -s https://certs.lol/1.1.1.1 | jq
```

Same URL, content-negotiated: `curl` gets JSON, your browser gets a formatted report.

## What it scans

- **Protocol support** — TLS 1.3/1.2/1.1/1.0, forward secrecy, key exchange
- **Certificate** — chain validation, expiry, key type & size, SANs, serial, fingerprint
- **Certificate chain** — full chain from leaf → intermediates → root with key algorithms and expiry
- **SCTs & OCSP** — Certificate Transparency timestamps, OCSP stapling
- **Cipher suites** — full enumeration with strength grading (strong/acceptable/weak/insecure)
- **Post-quantum** — X25519MLKEM768 hybrid key exchange detection
- **ECH** — Encrypted Client Hello support
- **HSTS** — max-age, includeSubDomains, preload directive, hstspreload.org list status
- **HTTP/2 & HTTP/3** — QUIC support, alt-svc header
- **DNS security** — DNSSEC validation, CAA records, DANE/TLSA
- **Compliance** — transport encryption checks against PCI DSS 4.0, NIST SP 800-52r2, HIPAA

## Compliance mapping

Each scan evaluates TLS configuration against transport encryption requirements for three frameworks:

| Framework | What it checks |
|-----------|---------------|
| **PCI DSS 4.0** (Req 4.2.1) | TLS 1.2+, no weak ciphers, forward secrecy, valid cert, HSTS recommended |
| **NIST SP 800-52r2** | TLS 1.2+ (1.3 preferred), key size minimums, no weak ciphers, FS, OCSP recommended |
| **HIPAA** (§164.312(e)(1)) | TLS 1.2+, AES encryption, valid cert, forward secrecy recommended |

**Important:** These are transport-layer checks only. "Meets transport encryption requirements for PCI DSS 4.0" means the TLS configuration passes the transport encryption criteria — not that the organization is PCI DSS compliant. Full compliance requires organizational, procedural, and application-level controls that a TLS scan cannot assess.

## Content negotiation

The same URL serves both formats:

| Client | Format |
|--------|--------|
| `curl`, `httpie`, `wget` | JSON |
| `Accept: application/json` | JSON |
| Browser | HTML |

## Rate limiting

- 20 scans per hour per IP
- Results cached for 6h
- `X-RateLimit-Limit` and `X-RateLimit-Remaining` headers on every response
- 429 response with `Retry-After` and `X-RateLimit-Reset` when exceeded

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
- **Go TLS probe on Fly.io** — raw TLS handshakes, cipher enumeration, certificate chain parsing, protocol detection, post-quantum & ECH checks
- **Shared probe** — the same probe that powers [yoke.lol](https://yoke.lol)'s security analysis

## API response

```json
{
  "grade": "A+",
  "target": "stripe.com",
  "protocols": ["TLS 1.3", "TLS 1.2"],
  "key_alg": "ECDSA",
  "key_size": 256,
  "forward_secrecy": true,
  "chain_valid": true,
  "chain_depth": 3,
  "days_remaining": 72,
  "ocsp_stapling": true,
  "has_scts": true,
  "sct_count": 2,
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
  "cipher_summary": { "strong": 5, "acceptable": 2, "weak": 0, "insecure": 0 },
  "ciphers": ["..."],
  "_meta": {
    "version": "1.0.0",
    "cache_hit": false,
    "cache_ttl": 21600,
    "docs": "https://certs.lol/api/docs",
    "full_report": "https://yoke.lol/stripe.com"
  }
}
```

## Self-hosting

Not designed for self-hosting, but it's MIT — knock yourself out. You'll need:
- A Cloudflare account with Workers and KV
- The Go TLS probe deployed somewhere (see the [yoke repo](https://github.com/yokedotlol/yoke))
- `PROBE_URL`, `FLY_AUTH_SECRET`, and `ADMIN_KEY` configured

## Links

- **Live:** https://certs.lol
- **API docs:** https://certs.lol/api/docs
- **Full reports:** https://yoke.lol
- **Source:** https://github.com/yokedotlol/certs-lol

## License

MIT

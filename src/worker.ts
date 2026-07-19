import { handleRequest } from './handler';
import type { HSTSInfo, HTTP3Info, DNSSecurityInfo, ParsedTLSA } from './enrich';
import type { ComplianceResult } from './compliance';

export { RateLimiterDO } from './rate-limiter';

/** DANCE (DANE Authentication for Network Clients Everywhere) readiness */
export interface DANCEInfo {
  /** Overall readiness status */
  status: 'ready' | 'partial' | 'not-ready';
  /** Human-readable summary */
  detail: string;
  /** Individual prerequisite checks */
  checks: {
    /** DNSSEC enabled — required for DANE trust chain */
    dnssec: boolean;
    /** TLS 1.3 supported — required by DANCE spec */
    tls13: boolean;
    /** Has DANE TLSA records at _443._tcp (server-side DANE) */
    dane_tlsa: boolean;
    /** Has DANE-EE (usage 3) TLSA records */
    dane_ee: boolean;
    /** Has DANE-TA (usage 2) TLSA records */
    dane_ta: boolean;
    /** Has SMTP DANE TLSA records at _25._tcp */
    smtp_tlsa: boolean;
  };
  /** Parsed TLSA records with usage types */
  tlsa_usage: ParsedTLSA[];
}

export interface Env {
  CACHE: KVNamespace;
  ADMIN_KEY: string;
  FLY_AUTH_SECRET: string;
  PROBE_URL: string;
  RATE_LIMITER: DurableObjectNamespace;
  /** Yoke domain intelligence service binding (.lol family) */
  YOKE?: Fetcher;
  /** Shared key for .lol family service bindings */
  SERVICE_KEY?: string;
}

/** What the probe returns from GET /probe-ssl?domain=X */
export interface ProbeResult {
  grade: string;
  issuer: string;
  subject: string;
  valid_from: string;
  valid_to: string;
  key_alg: string;
  key_size: number;
  protocols: string[];
  chain_depth: number;
  chain_valid: boolean;
  chain_certs?: ChainCert[];
  sans: string[];
  serial: string;
  fingerprint: string;
  probe_ms: number;
  error: string | null;
  ciphers: Array<{ name: string; id: number; strength: string }>;
  ocsp_stapling: boolean;
  sct_count: number;
  has_scts: boolean;
  forward_secrecy: boolean;
  key_exchange: string;
}

export interface ChainCert {
  subject: string;
  issuer: string;
  valid_from: string;
  valid_to: string;
  key_alg: string;
  key_size: number;
  serial: string;
  sans?: string[];
  is_self_signed: boolean;
  signature_alg: string;
}

/** Enriched result we return to callers */
export interface ScanResult extends ProbeResult {
  target: string;
  is_ip: boolean;
  scanned_at: string;
  days_remaining: number;
  cipher_summary: { strong: number; acceptable: number; weak: number; insecure: number };
  hsts: HSTSInfo;
  http3: HTTP3Info;
  dns_security: DNSSecurityInfo | null;
  dance: DANCEInfo | null;
  compliance?: ComplianceResult[];
  _meta: {
    version: string;
    cache_hit: boolean;
    cache_ttl: number;
    dns_report?: string;
    http_report?: string;
    full_report?: string;
    docs: string;
  };
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    return handleRequest(request, env, ctx);
  },
};

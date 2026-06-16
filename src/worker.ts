import { handleRequest } from './handler';
import type { HSTSInfo, HTTP3Info, DNSSecurityInfo } from './enrich';
import type { ComplianceResult } from './compliance';

export { RateLimiterDO } from './rate-limiter';

export interface Env {
  CACHE: KVNamespace;
  ADMIN_KEY: string;
  FLY_AUTH_SECRET: string;
  PROBE_URL: string;
  RATE_LIMITER: DurableObjectNamespace;
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
  compliance?: ComplianceResult[];
  _meta: {
    version: string;
    cache_hit: boolean;
    cache_ttl: number;
    dns_report?: string;
    full_report?: string;
    docs: string;
  };
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    return handleRequest(request, env, ctx);
  },
};

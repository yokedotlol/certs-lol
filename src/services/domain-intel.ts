// ─── Domain Intelligence via Yoke service binding ───
// Calls yoke.lol's internal API for email auth + DNSSEC signals.
// Falls back to inline checks if the binding is unavailable or errors.
//
// When the YOKE binding is present in wrangler.toml, certs.lol gets
// yoke's cached DNSSEC validation and email auth data at zero network
// cost (CF service bindings are in-process).

import type { Env } from '../worker';

// ─── Yoke response types ───

interface YokeEmailAuth {
  spf: { found: boolean; record: string | null; mechanisms: string[]; all_qualifier: string | null };
  dmarc: {
    found: boolean;
    record: string | null;
    policy: string | null;
    subdomain_policy: string | null;
    rua: string | null;
    ruf: string | null;
  };
  dkim_selectors_found: string[];
  bimi: { found: boolean; record: string | null; logo_url: string | null; authority_url: string | null };
  mta_sts: { dns_found: boolean; policy_found: boolean; mode: string | null };
  tls_rpt: { found: boolean; record: string | null; rua: string | null };
}

interface YokeDnssec {
  enabled: boolean;
  has_dnskey: boolean;
  has_ds: boolean;
  validated: boolean;
}

interface YokeDomainSignals {
  domain: string;
  email_auth: YokeEmailAuth;
  dnssec: YokeDnssec;
  cached: boolean;
  source: 'yoke';
}

// ─── Mapped result for certs-lol consumption ───

export interface DomainIntelResult {
  /** DNSSEC status from yoke's perspective */
  dnssec: boolean;
  /** Whether this came from the yoke service binding */
  fromYoke: true;
}

const YOKE_TIMEOUT = 3000; // 3s — if yoke is slow, fall back to inline

/**
 * Try to get domain signals from yoke via service binding.
 * Returns null if the binding isn't available or the call fails.
 */
export async function fetchDomainSignals(
  domain: string,
  env: Env,
): Promise<DomainIntelResult | null> {
  if (!env.YOKE || !env.SERVICE_KEY) return null;

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), YOKE_TIMEOUT);

    const response = await env.YOKE.fetch(
      new Request('https://internal/api/internal/domain-signals', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Service-Key': env.SERVICE_KEY,
        },
        body: JSON.stringify({ domain }),
        signal: controller.signal,
      }),
    );

    clearTimeout(timeout);

    if (!response.ok) return null;

    const data = await response.json() as YokeDomainSignals;
    return mapYokeToCerts(data);
  } catch {
    // Service binding unavailable, timeout, parse error — fall back silently
    return null;
  }
}

/** Map yoke's response shape to certs-lol's needs. */
function mapYokeToCerts(data: YokeDomainSignals): DomainIntelResult {
  return {
    dnssec: data.dnssec.enabled,
    fromYoke: true,
  };
}

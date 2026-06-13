import type { Env } from './worker';

// ─── Types ──────────────────────────────────────────────────────────

export interface HSTSInfo {
  enabled: boolean;
  max_age: number | null;
  include_subdomains: boolean;
  preload: boolean;
  on_preload_list: boolean;
}

export interface HTTP3Info {
  supported: boolean;
  http2: boolean;
  alt_svc: string | null;
}

export interface DNSSecurityInfo {
  dnssec: boolean;
  caa: string[];
  dane_tlsa: string | null;
}

export interface EnrichmentResult {
  hsts: HSTSInfo;
  http3: HTTP3Info;
  dns_security: DNSSecurityInfo;
}

// ─── Enrichment calls (all parallel) ────────────────────────────────

export async function enrich(domain: string, env: Env): Promise<EnrichmentResult> {
  const [hsts, http3, dnsSec] = await Promise.all([
    fetchHSTS(domain).catch(() => defaultHSTS()),
    fetchHTTP3(domain, env).catch(() => defaultHTTP3()),
    fetchDNSSecurity(domain).catch(() => defaultDNSSecurity()),
  ]);

  return { hsts, http3, dns_security: dnsSec };
}

// ─── HSTS (direct fetch from Worker) ────────────────────────────────

async function fetchHSTS(domain: string): Promise<HSTSInfo> {
  const resp = await fetch(`https://${domain}/`, {
    method: 'HEAD',
    redirect: 'follow',
    signal: AbortSignal.timeout(8000),
    headers: { 'User-Agent': 'certs.lol/1.0 (TLS scanner)' },
  });

  const hstsHeader = resp.headers.get('strict-transport-security') || '';
  if (!hstsHeader) return defaultHSTS();

  const maxAgeMatch = hstsHeader.match(/max-age=(\d+)/i);
  const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1], 10) : null;
  const includeSubdomains = /includeSubDomains/i.test(hstsHeader);
  const preloadDirective = /preload/i.test(hstsHeader);

  // Check HSTS preload list
  let onPreloadList = false;
  try {
    const preloadResp = await fetch(
      `https://hstspreload.org/api/v2/status?domain=${encodeURIComponent(domain)}`,
      { signal: AbortSignal.timeout(5000) },
    );
    if (preloadResp.ok) {
      const preloadData = await preloadResp.json() as { status?: string };
      onPreloadList = preloadData.status === 'preloaded';
    }
  } catch {
    // Non-critical
  }

  return {
    enabled: true,
    max_age: maxAge,
    include_subdomains: includeSubdomains,
    preload: preloadDirective,
    on_preload_list: onPreloadList,
  };
}

function defaultHSTS(): HSTSInfo {
  return { enabled: false, max_age: null, include_subdomains: false, preload: false, on_preload_list: false };
}

// ─── HTTP/3 (via probe — it connects externally and sees real alt-svc) ──

async function fetchHTTP3(domain: string, env: Env): Promise<HTTP3Info> {
  const resp = await fetch(
    `${env.PROBE_URL}/probe-protocols?domain=${encodeURIComponent(domain)}`,
    {
      headers: { 'Authorization': `Bearer ${env.FLY_AUTH_SECRET}` },
      signal: AbortSignal.timeout(12000),
    },
  );

  if (!resp.ok) return defaultHTTP3();

  const data = await resp.json() as {
    http2?: boolean;
    http3?: boolean;
    alt_svc?: string | null;
    error?: string | null;
  };

  if (data.error) return defaultHTTP3();

  return {
    supported: !!data.http3,
    http2: !!data.http2,
    alt_svc: data.alt_svc || null,
  };
}

function defaultHTTP3(): HTTP3Info {
  return { supported: false, http2: false, alt_svc: null };
}

// ─── DNS Security (DNSSEC + CAA + DANE via Cloudflare DoH) ──────────

async function fetchDNSSecurity(domain: string): Promise<DNSSecurityInfo> {
  const [dnssec, caa, dane] = await Promise.all([
    checkDNSSEC(domain),
    checkCAA(domain),
    checkDANE(domain),
  ]);

  return { dnssec, caa, dane_tlsa: dane };
}

function defaultDNSSecurity(): DNSSecurityInfo {
  return { dnssec: false, caa: [], dane_tlsa: null };
}

async function checkDNSSEC(domain: string): Promise<boolean> {
  try {
    const resp = await fetch(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=A&do=true`,
      {
        headers: { 'Accept': 'application/dns-json' },
        signal: AbortSignal.timeout(5000),
      },
    );
    if (!resp.ok) return false;
    const data = await resp.json() as { AD?: boolean };
    return !!data.AD;
  } catch {
    return false;
  }
}

async function checkCAA(domain: string): Promise<string[]> {
  try {
    const resp = await fetch(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=CAA`,
      {
        headers: { 'Accept': 'application/dns-json' },
        signal: AbortSignal.timeout(5000),
      },
    );
    if (!resp.ok) return [];
    const data = await resp.json() as { Answer?: Array<{ type: number; data: string }> };
    if (!data.Answer) return [];

    return data.Answer
      .filter(a => a.type === 257)
      .map(a => parseCAAData(a.data))
      .filter(Boolean) as string[];
  } catch {
    return [];
  }
}

/**
 * Parse CAA record data from Cloudflare DoH response.
 * DoH returns CAA data in wire format: \# NN HH HH HH ...
 * Wire format: [flags:1byte] [tag_length:1byte] [tag:Nbytes] [value:remaining]
 */
function parseCAAData(raw: string): string | null {
  if (!raw) return null;

  // If it's already in presentation format (e.g. '0 issue "digicert.com"')
  const presentationMatch = raw.match(/^(\d+)\s+(\w+)\s+"?([^"]*)"?$/);
  if (presentationMatch) {
    return `${presentationMatch[2]} ${presentationMatch[3]}`;
  }

  // Parse wire format: \# NN HH HH HH ...
  const wireMatch = raw.match(/^\\#\s+\d+\s+(.+)$/);
  if (!wireMatch) return raw;

  const hexStr = wireMatch[1].replace(/\s+/g, '');
  const bytes: number[] = [];
  for (let i = 0; i < hexStr.length; i += 2) {
    bytes.push(parseInt(hexStr.substring(i, i + 2), 16));
  }

  if (bytes.length < 2) return null;

  const tagLength = bytes[1];
  if (bytes.length < 2 + tagLength) return null;

  const tag = String.fromCharCode(...bytes.slice(2, 2 + tagLength));
  const value = String.fromCharCode(...bytes.slice(2 + tagLength));

  return `${tag} ${value}`;
}

async function checkDANE(domain: string): Promise<string | null> {
  try {
    const resp = await fetch(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(`_443._tcp.${domain}`)}&type=TLSA`,
      {
        headers: { 'Accept': 'application/dns-json' },
        signal: AbortSignal.timeout(5000),
      },
    );
    if (!resp.ok) return null;
    const data = await resp.json() as { Answer?: Array<{ type: number; data: string }> };
    if (!data.Answer) return null;

    const tlsa = data.Answer.filter(a => a.type === 52);
    if (tlsa.length === 0) return null;

    return tlsa.map(a => a.data).join('; ');
  } catch {
    return null;
  }
}

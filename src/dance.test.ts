import { describe, test, expect } from 'bun:test';

// We can't directly import computeDANCE (it's in handler.ts and not exported),
// but we can test the DANCE computation logic by importing from the enrichment
// types and testing the integrated output format.
//
// Since computeDANCE is a pure function that takes (protocols, DNSSecurityInfo),
// we'll replicate its logic here for unit testing, then rely on integration
// tests (smoke test in CI) for the full pipeline.

import type { DNSSecurityInfo, ParsedTLSA } from './enrich';

// ─── Replicated computeDANCE for testability ────────────────────────
// (Matches handler.ts implementation exactly)

interface DANCEInfo {
  status: 'ready' | 'partial' | 'not-ready';
  detail: string;
  checks: {
    dnssec: boolean;
    tls13: boolean;
    dane_tlsa: boolean;
    dane_ee: boolean;
    dane_ta: boolean;
    smtp_tlsa: boolean;
  };
  tlsa_usage: ParsedTLSA[];
}

function computeDANCE(protocols: string[], dnsSec: DNSSecurityInfo | null): DANCEInfo | null {
  if (!dnsSec) return null;

  const tls13 = protocols.some(p => p === 'TLS 1.3');
  const hasDaneTlsa = !!dnsSec.dane_tlsa;
  const hasSmtpTlsa = !!dnsSec.smtp_tlsa;
  const hasDaneEE = dnsSec.parsed_tlsa.some(t => t.usage === 3);
  const hasDaneTA = dnsSec.parsed_tlsa.some(t => t.usage === 2);

  const checks = {
    dnssec: dnsSec.dnssec,
    tls13,
    dane_tlsa: hasDaneTlsa,
    dane_ee: hasDaneEE,
    dane_ta: hasDaneTA,
    smtp_tlsa: hasSmtpTlsa,
  };

  let status: DANCEInfo['status'];
  let detail: string;
  const hasDaneUsage = hasDaneEE || hasDaneTA;

  if (dnsSec.dnssec && tls13 && hasDaneTlsa && hasDaneUsage) {
    status = 'ready';
    const usages: string[] = [];
    if (hasDaneEE) usages.push('DANE-EE');
    if (hasDaneTA) usages.push('DANE-TA');
    detail = `DANCE-ready: DNSSEC + TLS 1.3 + ${usages.join('/')} TLSA`;
    if (hasSmtpTlsa) detail += ' + SMTP DANE';
  } else if (dnsSec.dnssec && tls13) {
    status = 'partial';
    if (hasDaneTlsa) {
      detail = 'Infrastructure present but TLSA records use PKIX-only usage types';
    } else {
      detail = 'DNSSEC + TLS 1.3 present; no DANE TLSA records published';
    }
  } else if (dnsSec.dnssec || tls13 || hasDaneTlsa) {
    status = 'partial';
    const missing: string[] = [];
    if (!dnsSec.dnssec) missing.push('DNSSEC');
    if (!tls13) missing.push('TLS 1.3');
    if (!hasDaneTlsa) missing.push('DANE TLSA');
    detail = `Missing: ${missing.join(', ')}`;
  } else {
    status = 'not-ready';
    detail = 'No DNSSEC, TLS 1.3, or DANE TLSA records';
  }

  return {
    status,
    detail,
    checks,
    tlsa_usage: dnsSec.parsed_tlsa,
  };
}

// ─── Test fixtures ──────────────────────────────────────────────────

function makeDnsSec(overrides?: Partial<DNSSecurityInfo>): DNSSecurityInfo {
  return {
    dnssec: false,
    caa: [],
    dane_tlsa: null,
    smtp_tlsa: null,
    parsed_tlsa: [],
    ...overrides,
  };
}

function makeTLSA(port: number, usage: number): ParsedTLSA {
  const names: Record<number, string> = { 0: 'PKIX-TA', 1: 'PKIX-EE', 2: 'DANE-TA', 3: 'DANE-EE' };
  return { port, protocol: 'tcp', usage, usage_name: names[usage] || `usage-${usage}`, selector: 1, matching_type: 1 };
}

// ─── Tests ──────────────────────────────────────────────────────────

describe('computeDANCE', () => {
  test('returns null when dns_security is null', () => {
    expect(computeDANCE(['TLS 1.3', 'TLS 1.2'], null)).toBeNull();
  });

  test('not-ready: no DNSSEC, no TLS 1.3, no DANE', () => {
    const result = computeDANCE(['TLS 1.2'], makeDnsSec());
    expect(result).not.toBeNull();
    expect(result!.status).toBe('not-ready');
    expect(result!.checks.dnssec).toBe(false);
    expect(result!.checks.tls13).toBe(false);
    expect(result!.checks.dane_tlsa).toBe(false);
  });

  test('partial: DNSSEC only', () => {
    const result = computeDANCE(['TLS 1.2'], makeDnsSec({ dnssec: true }));
    expect(result!.status).toBe('partial');
    expect(result!.detail).toContain('TLS 1.3');
    expect(result!.detail).toContain('DANE TLSA');
    expect(result!.checks.dnssec).toBe(true);
    expect(result!.checks.tls13).toBe(false);
  });

  test('partial: TLS 1.3 only', () => {
    const result = computeDANCE(['TLS 1.3', 'TLS 1.2'], makeDnsSec());
    expect(result!.status).toBe('partial');
    expect(result!.detail).toContain('DNSSEC');
    expect(result!.checks.tls13).toBe(true);
    expect(result!.checks.dnssec).toBe(false);
  });

  test('partial: DNSSEC + TLS 1.3 but no TLSA records', () => {
    const result = computeDANCE(['TLS 1.3'], makeDnsSec({ dnssec: true }));
    expect(result!.status).toBe('partial');
    expect(result!.detail).toContain('no DANE TLSA');
    expect(result!.checks.dnssec).toBe(true);
    expect(result!.checks.tls13).toBe(true);
    expect(result!.checks.dane_tlsa).toBe(false);
  });

  test('partial: DNSSEC + TLS 1.3 + TLSA but PKIX-only usage (0)', () => {
    const result = computeDANCE(['TLS 1.3'], makeDnsSec({
      dnssec: true,
      dane_tlsa: '0 1 1 abc123',
      parsed_tlsa: [makeTLSA(443, 0)],
    }));
    expect(result!.status).toBe('partial');
    expect(result!.detail).toContain('PKIX-only');
    expect(result!.checks.dane_tlsa).toBe(true);
    expect(result!.checks.dane_ee).toBe(false);
    expect(result!.checks.dane_ta).toBe(false);
  });

  test('partial: DNSSEC + TLS 1.3 + TLSA with PKIX-EE usage (1)', () => {
    const result = computeDANCE(['TLS 1.3'], makeDnsSec({
      dnssec: true,
      dane_tlsa: '1 1 1 abc123',
      parsed_tlsa: [makeTLSA(443, 1)],
    }));
    expect(result!.status).toBe('partial');
    expect(result!.detail).toContain('PKIX-only');
  });

  test('ready: DNSSEC + TLS 1.3 + DANE-EE TLSA (usage 3)', () => {
    const result = computeDANCE(['TLS 1.3', 'TLS 1.2'], makeDnsSec({
      dnssec: true,
      dane_tlsa: '3 1 1 d2abde240d7cd3ee6b4b28c54df034b97983a1d16e8a410e4561cb106618e971',
      parsed_tlsa: [makeTLSA(443, 3)],
    }));
    expect(result!.status).toBe('ready');
    expect(result!.detail).toContain('DANE-EE');
    expect(result!.checks.dane_ee).toBe(true);
    expect(result!.checks.dane_ta).toBe(false);
  });

  test('ready: DNSSEC + TLS 1.3 + DANE-TA TLSA (usage 2)', () => {
    const result = computeDANCE(['TLS 1.3'], makeDnsSec({
      dnssec: true,
      dane_tlsa: '2 0 1 20efa254ecd5b646e701211095bc3fe4423e21941b0b29efb21da57ec944a9b5',
      parsed_tlsa: [makeTLSA(443, 2)],
    }));
    expect(result!.status).toBe('ready');
    expect(result!.detail).toContain('DANE-TA');
    expect(result!.checks.dane_ta).toBe(true);
  });

  test('ready: includes SMTP DANE in detail', () => {
    const result = computeDANCE(['TLS 1.3'], makeDnsSec({
      dnssec: true,
      dane_tlsa: '3 1 1 abc123',
      smtp_tlsa: '3 1 1 def456',
      parsed_tlsa: [makeTLSA(443, 3), makeTLSA(25, 3)],
    }));
    expect(result!.status).toBe('ready');
    expect(result!.detail).toContain('SMTP DANE');
    expect(result!.checks.smtp_tlsa).toBe(true);
  });

  test('ready with both DANE-EE and DANE-TA', () => {
    const result = computeDANCE(['TLS 1.3'], makeDnsSec({
      dnssec: true,
      dane_tlsa: '3 1 1 abc123; 2 0 1 def456',
      parsed_tlsa: [makeTLSA(443, 3), makeTLSA(443, 2)],
    }));
    expect(result!.status).toBe('ready');
    expect(result!.detail).toContain('DANE-EE');
    expect(result!.detail).toContain('DANE-TA');
  });

  test('partial: DANE TLSA without DNSSEC', () => {
    const result = computeDANCE(['TLS 1.3'], makeDnsSec({
      dnssec: false,
      dane_tlsa: '3 1 1 abc123',
      parsed_tlsa: [makeTLSA(443, 3)],
    }));
    expect(result!.status).toBe('partial');
    expect(result!.detail).toContain('DNSSEC');
  });

  test('partial: DANE TLSA without TLS 1.3', () => {
    const result = computeDANCE(['TLS 1.2'], makeDnsSec({
      dnssec: true,
      dane_tlsa: '3 1 1 abc123',
      parsed_tlsa: [makeTLSA(443, 3)],
    }));
    expect(result!.status).toBe('partial');
    expect(result!.detail).toContain('TLS 1.3');
  });

  test('tlsa_usage passes through parsed records', () => {
    const records = [makeTLSA(443, 3), makeTLSA(25, 2)];
    const result = computeDANCE(['TLS 1.3'], makeDnsSec({
      dnssec: true,
      dane_tlsa: '3 1 1 abc123',
      smtp_tlsa: '2 0 1 def456',
      parsed_tlsa: records,
    }));
    expect(result!.tlsa_usage).toEqual(records);
    expect(result!.tlsa_usage).toHaveLength(2);
  });
});

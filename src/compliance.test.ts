import { describe, test, expect } from 'bun:test';
import { evaluateCompliance } from './compliance';
import type { ComplianceInput } from './compliance';

// ─── Fixtures ───────────────────────────────────────────────────────

function perfectConfig(overrides?: Partial<ComplianceInput>): ComplianceInput {
  return {
    protocols: ['TLS 1.3', 'TLS 1.2'],
    ciphers: [
      { name: 'TLS_AES_256_GCM_SHA384', strength: 'strong' },
      { name: 'TLS_CHACHA20_POLY1305_SHA256', strength: 'strong' },
      { name: 'TLS_AES_128_GCM_SHA256', strength: 'strong' },
      { name: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384', strength: 'strong' },
      { name: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', strength: 'acceptable' },
    ],
    cipher_summary: { strong: 4, acceptable: 1, weak: 0, insecure: 0 },
    key_alg: 'RSA',
    key_size: 2048,
    forward_secrecy: true,
    chain_valid: true,
    days_remaining: 90,
    ocsp_stapling: true,
    hsts: { enabled: true },
    ...overrides,
  };
}

// ─── Tests ──────────────────────────────────────────────────────────

describe('evaluateCompliance', () => {
  test('perfect config passes all frameworks', () => {
    const results = evaluateCompliance(perfectConfig());
    expect(results).toHaveLength(3);

    for (const r of results) {
      expect(r.meets_requirements).toBe(true);
      expect(r.findings.every(f => f.status !== 'fail')).toBe(true);
    }
  });

  test('returns PCI DSS 4.0, NIST 800-52r2, HIPAA in order', () => {
    const results = evaluateCompliance(perfectConfig());
    expect(results[0].framework).toBe('pci-dss-4');
    expect(results[0].display_name).toBe('PCI DSS 4.0');
    expect(results[1].framework).toBe('nist-800-52r2');
    expect(results[1].display_name).toBe('NIST 800-52r2');
    expect(results[2].framework).toBe('hipaa');
    expect(results[2].display_name).toBe('HIPAA');
  });

  describe('TLS 1.0 enabled', () => {
    test('fails all three frameworks', () => {
      const results = evaluateCompliance(perfectConfig({
        protocols: ['TLS 1.3', 'TLS 1.2', 'TLS 1.0'],
      }));

      for (const r of results) {
        expect(r.meets_requirements).toBe(false);
        const fails = r.findings.filter(f => f.status === 'fail');
        expect(fails.length).toBeGreaterThanOrEqual(1);
        expect(fails.some(f => f.detail.includes('TLS 1.0'))).toBe(true);
      }
    });
  });

  describe('TLS 1.1 enabled', () => {
    test('fails all three frameworks', () => {
      const results = evaluateCompliance(perfectConfig({
        protocols: ['TLS 1.3', 'TLS 1.2', 'TLS 1.1'],
      }));

      for (const r of results) {
        expect(r.meets_requirements).toBe(false);
      }
    });
  });

  describe('weak ciphers', () => {
    test('RC4 cipher causes failure', () => {
      const results = evaluateCompliance(perfectConfig({
        ciphers: [
          { name: 'TLS_AES_256_GCM_SHA384', strength: 'strong' },
          { name: 'TLS_RSA_WITH_RC4_128_SHA', strength: 'insecure' },
        ],
        cipher_summary: { strong: 1, acceptable: 0, weak: 0, insecure: 1 },
      }));

      for (const r of results) {
        expect(r.meets_requirements).toBe(false);
        const fails = r.findings.filter(f => f.status === 'fail');
        expect(fails.some(f => f.detail.includes('RC4'))).toBe(true);
      }
    });

    test('DES cipher causes failure', () => {
      const results = evaluateCompliance(perfectConfig({
        ciphers: [
          { name: 'TLS_AES_256_GCM_SHA384', strength: 'strong' },
          { name: 'TLS_RSA_WITH_DES_CBC_SHA', strength: 'weak' },
        ],
        cipher_summary: { strong: 1, acceptable: 0, weak: 1, insecure: 0 },
      }));

      for (const r of results) {
        expect(r.meets_requirements).toBe(false);
      }
    });

    test('NULL cipher causes failure', () => {
      const results = evaluateCompliance(perfectConfig({
        ciphers: [
          { name: 'TLS_AES_256_GCM_SHA384', strength: 'strong' },
          { name: 'TLS_RSA_WITH_NULL_SHA256', strength: 'insecure' },
        ],
        cipher_summary: { strong: 1, acceptable: 0, weak: 0, insecure: 1 },
      }));

      for (const r of results) {
        expect(r.meets_requirements).toBe(false);
      }
    });
  });

  describe('expired certificate', () => {
    test('days_remaining=0 fails all frameworks', () => {
      const results = evaluateCompliance(perfectConfig({
        days_remaining: 0,
      }));

      for (const r of results) {
        expect(r.meets_requirements).toBe(false);
        const fails = r.findings.filter(f => f.status === 'fail');
        expect(fails.some(f => f.detail.toLowerCase().includes('expired'))).toBe(true);
      }
    });

    test('invalid chain fails all frameworks', () => {
      const results = evaluateCompliance(perfectConfig({
        chain_valid: false,
      }));

      for (const r of results) {
        expect(r.meets_requirements).toBe(false);
      }
    });
  });

  describe('forward secrecy', () => {
    test('no forward secrecy fails PCI and NIST, warns HIPAA', () => {
      const results = evaluateCompliance(perfectConfig({
        forward_secrecy: false,
      }));

      const [pci, nist, hipaa] = results;

      // PCI: forward secrecy required → fail
      expect(pci.meets_requirements).toBe(false);
      expect(pci.findings.some(f => f.status === 'fail' && f.detail.includes('Forward secrecy'))).toBe(true);

      // NIST: forward secrecy required → fail
      expect(nist.meets_requirements).toBe(false);
      expect(nist.findings.some(f => f.status === 'fail' && f.detail.includes('Forward secrecy'))).toBe(true);

      // HIPAA: forward secrecy recommended → warn only, still passes
      expect(hipaa.meets_requirements).toBe(true);
      expect(hipaa.findings.some(f => f.status === 'warn' && f.detail.includes('Forward secrecy'))).toBe(true);
    });
  });

  describe('key size requirements (NIST)', () => {
    test('ECDSA 256-bit passes NIST', () => {
      const results = evaluateCompliance(perfectConfig({
        key_alg: 'ECDSA',
        key_size: 256,
      }));

      const nist = results.find(r => r.framework === 'nist-800-52r2')!;
      expect(nist.meets_requirements).toBe(true);
      expect(nist.findings.some(f => f.status === 'pass' && f.detail.includes('ECDSA') && f.detail.includes('256'))).toBe(true);
    });

    test('ECDSA 384-bit passes NIST', () => {
      const results = evaluateCompliance(perfectConfig({
        key_alg: 'ECDSA',
        key_size: 384,
      }));

      const nist = results.find(r => r.framework === 'nist-800-52r2')!;
      expect(nist.meets_requirements).toBe(true);
    });

    test('RSA 1024-bit fails NIST', () => {
      const results = evaluateCompliance(perfectConfig({
        key_alg: 'RSA',
        key_size: 1024,
      }));

      const nist = results.find(r => r.framework === 'nist-800-52r2')!;
      expect(nist.meets_requirements).toBe(false);
      expect(nist.findings.some(f => f.status === 'fail' && f.detail.includes('1024'))).toBe(true);
    });

    test('RSA 4096-bit passes NIST', () => {
      const results = evaluateCompliance(perfectConfig({
        key_alg: 'RSA',
        key_size: 4096,
      }));

      const nist = results.find(r => r.framework === 'nist-800-52r2')!;
      expect(nist.meets_requirements).toBe(true);
    });
  });

  describe('OCSP stapling (NIST)', () => {
    test('missing OCSP stapling is a warn, not fail', () => {
      const results = evaluateCompliance(perfectConfig({
        ocsp_stapling: false,
      }));

      const nist = results.find(r => r.framework === 'nist-800-52r2')!;
      // Should still pass (warn doesn't fail)
      expect(nist.meets_requirements).toBe(true);
      expect(nist.findings.some(f => f.status === 'warn' && f.detail.includes('OCSP'))).toBe(true);
    });
  });

  describe('HSTS (PCI)', () => {
    test('missing HSTS is a warn, not fail', () => {
      const results = evaluateCompliance(perfectConfig({
        hsts: { enabled: false },
      }));

      const pci = results.find(r => r.framework === 'pci-dss-4')!;
      // Should still pass (HSTS is best practice for PCI, not required)
      expect(pci.meets_requirements).toBe(true);
      expect(pci.findings.some(f => f.status === 'warn' && f.detail.includes('HSTS'))).toBe(true);
    });
  });

  describe('TLS 1.3 only (no TLS 1.2)', () => {
    test('still passes all frameworks', () => {
      const results = evaluateCompliance(perfectConfig({
        protocols: ['TLS 1.3'],
      }));

      for (const r of results) {
        expect(r.meets_requirements).toBe(true);
      }
    });
  });

  describe('no TLS 1.3 (TLS 1.2 only)', () => {
    test('passes PCI and HIPAA, NIST warns but still passes', () => {
      const results = evaluateCompliance(perfectConfig({
        protocols: ['TLS 1.2'],
      }));

      const [pci, nist, hipaa] = results;
      expect(pci.meets_requirements).toBe(true);
      expect(hipaa.meets_requirements).toBe(true);
      // NIST: TLS 1.3 preferred but not required
      expect(nist.meets_requirements).toBe(true);
      expect(nist.findings.some(f => f.status === 'warn' && f.detail.includes('TLS 1.3'))).toBe(true);
    });
  });

  describe('null HSTS', () => {
    test('handles null hsts gracefully', () => {
      const results = evaluateCompliance(perfectConfig({
        hsts: null,
      }));

      // Should not throw
      const pci = results.find(r => r.framework === 'pci-dss-4')!;
      expect(pci.findings.some(f => f.detail.includes('HSTS'))).toBe(true);
    });
  });

  describe('multiple failures', () => {
    test('terrible config fails everything', () => {
      const results = evaluateCompliance({
        protocols: ['TLS 1.0', 'SSLv3'],
        ciphers: [
          { name: 'TLS_RSA_WITH_RC4_128_SHA', strength: 'insecure' },
          { name: 'TLS_RSA_WITH_NULL_SHA', strength: 'insecure' },
        ],
        cipher_summary: { strong: 0, acceptable: 0, weak: 0, insecure: 2 },
        key_alg: 'RSA',
        key_size: 512,
        forward_secrecy: false,
        chain_valid: false,
        days_remaining: 0,
        ocsp_stapling: false,
        hsts: { enabled: false },
      });

      for (const r of results) {
        expect(r.meets_requirements).toBe(false);
        const fails = r.findings.filter(f => f.status === 'fail');
        expect(fails.length).toBeGreaterThanOrEqual(3);
      }
    });
  });
});

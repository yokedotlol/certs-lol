// ─── Compliance Mapping ─────────────────────────────────────────────
// Evaluates TLS scan data against transport encryption requirements
// for PCI DSS 4.0, NIST SP 800-52r2, and HIPAA.
//
// Important: these are transport-layer checks only. Passing here means
// "meets transport encryption requirements for <framework>" — NOT full
// compliance with the framework itself.

export interface ComplianceResult {
  framework: string;
  display_name: string;
  meets_requirements: boolean;
  findings: ComplianceFinding[];
}

export interface ComplianceFinding {
  requirement: string;
  status: 'pass' | 'fail' | 'warn';
  detail: string;
}

export interface ComplianceInput {
  protocols: string[];
  ciphers: Array<{ name: string; strength: string }>;
  cipher_summary: { strong: number; acceptable: number; weak: number; insecure: number };
  key_alg: string;
  key_size: number;
  forward_secrecy: boolean;
  chain_valid: boolean;
  days_remaining: number;
  ocsp_stapling: boolean;
  hsts?: { enabled: boolean } | null;
}

// ─── Shared checks ──────────────────────────────────────────────────

const WEAK_CIPHER_PATTERNS = [
  /RC4/i, /DES/i, /3DES/i, /NULL/i, /EXPORT/i, /anon/i, /MD5/i,
];

function hasLegacyProtocol(protocols: string[]): boolean {
  return protocols.some(p => p === 'TLS 1.0' || p === 'TLS 1.1' || p === 'SSLv3' || p === 'SSLv2');
}

function hasTLS12Plus(protocols: string[]): boolean {
  return protocols.some(p => p === 'TLS 1.2' || p === 'TLS 1.3');
}

function hasWeakCiphers(ciphers: Array<{ name: string; strength: string }>): string[] {
  const weak: string[] = [];
  for (const c of ciphers) {
    if (c.strength === 'insecure' || c.strength === 'weak') {
      weak.push(c.name);
      continue;
    }
    for (const pat of WEAK_CIPHER_PATTERNS) {
      if (pat.test(c.name)) {
        weak.push(c.name);
        break;
      }
    }
  }
  return weak;
}

// ─── PCI DSS 4.0 (Requirement 4.2.1) ───────────────────────────────

function evaluatePCI(data: ComplianceInput): ComplianceResult {
  const findings: ComplianceFinding[] = [];

  // TLS 1.2+ required
  if (!hasTLS12Plus(data.protocols)) {
    findings.push({ requirement: 'Req 4.2.1', status: 'fail', detail: 'TLS 1.2 or higher not supported' });
  } else {
    findings.push({ requirement: 'Req 4.2.1', status: 'pass', detail: 'TLS 1.2+ supported' });
  }

  // No legacy protocols
  if (hasLegacyProtocol(data.protocols)) {
    const legacy = data.protocols.filter(p => p === 'TLS 1.0' || p === 'TLS 1.1' || p === 'SSLv3' || p === 'SSLv2');
    findings.push({ requirement: 'Req 4.2.1', status: 'fail', detail: `Legacy protocols enabled: ${legacy.join(', ')}` });
  }

  // No weak ciphers
  const weak = hasWeakCiphers(data.ciphers);
  if (weak.length > 0) {
    findings.push({ requirement: 'Req 4.2.1', status: 'fail', detail: `Weak/insecure ciphers: ${weak.slice(0, 3).join(', ')}${weak.length > 3 ? ` +${weak.length - 3} more` : ''}` });
  } else {
    findings.push({ requirement: 'Req 4.2.1', status: 'pass', detail: 'No weak or insecure ciphers' });
  }

  // Forward secrecy
  if (!data.forward_secrecy) {
    findings.push({ requirement: 'Req 4.2.1', status: 'fail', detail: 'Forward secrecy not supported' });
  } else {
    findings.push({ requirement: 'Req 4.2.1', status: 'pass', detail: 'Forward secrecy enabled' });
  }

  // Valid certificate
  if (!data.chain_valid || data.days_remaining <= 0) {
    findings.push({ requirement: 'Req 4.2.1', status: 'fail', detail: data.days_remaining <= 0 ? 'Certificate expired' : 'Invalid certificate chain' });
  } else {
    findings.push({ requirement: 'Req 4.2.1', status: 'pass', detail: 'Valid certificate chain' });
  }

  // HSTS (recommended, not required by spec)
  if (!data.hsts?.enabled) {
    findings.push({ requirement: 'Best Practice', status: 'warn', detail: 'HSTS not enabled' });
  } else {
    findings.push({ requirement: 'Best Practice', status: 'pass', detail: 'HSTS enabled' });
  }

  return {
    framework: 'pci-dss-4',
    display_name: 'PCI DSS 4.0',
    meets_requirements: findings.every(f => f.status !== 'fail'),
    findings,
  };
}

// ─── NIST SP 800-52r2 ───────────────────────────────────────────────

function evaluateNIST(data: ComplianceInput): ComplianceResult {
  const findings: ComplianceFinding[] = [];

  // TLS 1.2+ required
  if (!hasTLS12Plus(data.protocols)) {
    findings.push({ requirement: 'Sec 3.1', status: 'fail', detail: 'TLS 1.2 or higher not supported' });
  } else {
    findings.push({ requirement: 'Sec 3.1', status: 'pass', detail: 'TLS 1.2+ supported' });
  }

  // TLS 1.3 preferred
  if (!data.protocols.includes('TLS 1.3')) {
    findings.push({ requirement: 'Sec 3.1', status: 'warn', detail: 'TLS 1.3 not supported (recommended)' });
  } else {
    findings.push({ requirement: 'Sec 3.1', status: 'pass', detail: 'TLS 1.3 supported' });
  }

  // No legacy protocols
  if (hasLegacyProtocol(data.protocols)) {
    const legacy = data.protocols.filter(p => p === 'TLS 1.0' || p === 'TLS 1.1' || p === 'SSLv3' || p === 'SSLv2');
    findings.push({ requirement: 'Sec 3.1', status: 'fail', detail: `Legacy protocols enabled: ${legacy.join(', ')}` });
  }

  // Key size requirements
  if (data.key_alg.toUpperCase().includes('RSA')) {
    if (data.key_size > 0 && data.key_size < 2048) {
      findings.push({ requirement: 'Sec 3.3', status: 'fail', detail: `RSA key ${data.key_size}-bit < 2048-bit minimum` });
    } else if (data.key_size >= 2048) {
      findings.push({ requirement: 'Sec 3.3', status: 'pass', detail: `RSA ${data.key_size}-bit key meets minimum` });
    }
  } else if (data.key_alg.toUpperCase().includes('ECDSA') || data.key_alg.toUpperCase().includes('EC')) {
    if (data.key_size > 0 && data.key_size < 256) {
      findings.push({ requirement: 'Sec 3.3', status: 'fail', detail: `ECDSA key ${data.key_size}-bit < 256-bit minimum` });
    } else if (data.key_size >= 256) {
      findings.push({ requirement: 'Sec 3.3', status: 'pass', detail: `ECDSA ${data.key_size}-bit key meets minimum` });
    }
  }

  // No weak ciphers
  const weak = hasWeakCiphers(data.ciphers);
  if (weak.length > 0) {
    findings.push({ requirement: 'Sec 3.3', status: 'fail', detail: `Weak/insecure ciphers: ${weak.slice(0, 3).join(', ')}${weak.length > 3 ? ` +${weak.length - 3} more` : ''}` });
  } else {
    findings.push({ requirement: 'Sec 3.3', status: 'pass', detail: 'No weak or insecure ciphers' });
  }

  // Forward secrecy
  if (!data.forward_secrecy) {
    findings.push({ requirement: 'Sec 3.3', status: 'fail', detail: 'Forward secrecy not supported' });
  } else {
    findings.push({ requirement: 'Sec 3.3', status: 'pass', detail: 'Forward secrecy enabled' });
  }

  // OCSP stapling (recommended)
  if (!data.ocsp_stapling) {
    findings.push({ requirement: 'Sec 4.4', status: 'warn', detail: 'OCSP stapling not present (recommended)' });
  } else {
    findings.push({ requirement: 'Sec 4.4', status: 'pass', detail: 'OCSP stapling enabled' });
  }

  // Valid certificate chain
  if (!data.chain_valid || data.days_remaining <= 0) {
    findings.push({ requirement: 'Sec 4', status: 'fail', detail: data.days_remaining <= 0 ? 'Certificate expired' : 'Invalid certificate chain' });
  } else {
    findings.push({ requirement: 'Sec 4', status: 'pass', detail: 'Valid certificate chain' });
  }

  return {
    framework: 'nist-800-52r2',
    display_name: 'NIST 800-52r2',
    meets_requirements: findings.every(f => f.status !== 'fail'),
    findings,
  };
}

// ─── HIPAA (45 CFR §164.312(e)(1)) ─────────────────────────────────

function evaluateHIPAA(data: ComplianceInput): ComplianceResult {
  const findings: ComplianceFinding[] = [];

  // TLS 1.2+ required
  if (!hasTLS12Plus(data.protocols)) {
    findings.push({ requirement: '§164.312(e)(1)', status: 'fail', detail: 'TLS 1.2 or higher not supported' });
  } else {
    findings.push({ requirement: '§164.312(e)(1)', status: 'pass', detail: 'TLS 1.2+ supported' });
  }

  // No legacy protocols
  if (hasLegacyProtocol(data.protocols)) {
    const legacy = data.protocols.filter(p => p === 'TLS 1.0' || p === 'TLS 1.1' || p === 'SSLv3' || p === 'SSLv2');
    findings.push({ requirement: '§164.312(e)(1)', status: 'fail', detail: `Legacy protocols enabled: ${legacy.join(', ')}` });
  }

  // AES required, no weak ciphers
  const weak = hasWeakCiphers(data.ciphers);
  if (weak.length > 0) {
    findings.push({ requirement: '§164.312(e)(1)', status: 'fail', detail: `Insecure ciphers: ${weak.slice(0, 3).join(', ')}${weak.length > 3 ? ` +${weak.length - 3} more` : ''}` });
  } else {
    findings.push({ requirement: '§164.312(e)(1)', status: 'pass', detail: 'Strong encryption (AES) in use' });
  }

  // Valid certificate
  if (!data.chain_valid || data.days_remaining <= 0) {
    findings.push({ requirement: '§164.312(e)(1)', status: 'fail', detail: data.days_remaining <= 0 ? 'Certificate expired' : 'Invalid certificate chain' });
  } else {
    findings.push({ requirement: '§164.312(e)(1)', status: 'pass', detail: 'Valid certificate chain' });
  }

  // Forward secrecy (recommended, not mandated)
  if (!data.forward_secrecy) {
    findings.push({ requirement: 'Best Practice', status: 'warn', detail: 'Forward secrecy not supported (recommended)' });
  } else {
    findings.push({ requirement: 'Best Practice', status: 'pass', detail: 'Forward secrecy enabled' });
  }

  return {
    framework: 'hipaa',
    display_name: 'HIPAA',
    meets_requirements: findings.every(f => f.status !== 'fail'),
    findings,
  };
}

// ─── Public API ─────────────────────────────────────────────────────

export function evaluateCompliance(data: ComplianceInput): ComplianceResult[] {
  return [
    evaluatePCI(data),
    evaluateNIST(data),
    evaluateHIPAA(data),
  ];
}

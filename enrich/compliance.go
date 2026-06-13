package enrich

import (
	"strconv"
	"strings"
)

// ComplianceResult evaluates a TLS configuration against a compliance framework.
type ComplianceResult struct {
	Framework        string              `json:"framework"`
	DisplayName      string              `json:"display_name"`
	MeetsRequirements bool               `json:"meets_requirements"`
	Findings         []ComplianceFinding `json:"findings"`
}

// ComplianceFinding is a single pass/fail/warn check within a framework.
type ComplianceFinding struct {
	Requirement string `json:"requirement"`
	Status      string `json:"status"` // "pass", "fail", "warn"
	Detail      string `json:"detail"`
}

// ComplianceInput provides the data needed for compliance evaluation.
type ComplianceInput struct {
	Protocols      []string
	Ciphers        []CipherForCompliance
	KeyAlg         string
	KeySize        int
	ForwardSecrecy bool
	ChainValid     bool
	DaysRemaining  int
	OCSPStapling   bool
	HSTSEnabled    bool
}

// CipherForCompliance is a simplified cipher reference for compliance checks.
type CipherForCompliance struct {
	Name     string
	Strength string
}

// EvaluateCompliance runs all compliance frameworks against the input.
func EvaluateCompliance(data ComplianceInput) []ComplianceResult {
	return []ComplianceResult{
		evaluatePCI(data),
		evaluateNIST(data),
		evaluateHIPAA(data),
	}
}

// ─── Shared helpers ─────────────────────────────────────────────────

func hasLegacyProtocol(protocols []string) bool {
	for _, p := range protocols {
		if p == "TLS 1.0" || p == "TLS 1.1" || p == "SSLv3" || p == "SSLv2" {
			return true
		}
	}
	return false
}

func hasTLS12Plus(protocols []string) bool {
	for _, p := range protocols {
		if p == "TLS 1.2" || p == "TLS 1.3" {
			return true
		}
	}
	return false
}

var weakCipherPatterns = []string{"RC4", "DES", "3DES", "NULL", "EXPORT", "anon", "MD5"}

func findWeakCiphers(ciphers []CipherForCompliance) []string {
	var weak []string
	for _, c := range ciphers {
		if c.Strength == "insecure" || c.Strength == "weak" {
			weak = append(weak, c.Name)
			continue
		}
		for _, pat := range weakCipherPatterns {
			if strings.Contains(strings.ToUpper(c.Name), strings.ToUpper(pat)) {
				weak = append(weak, c.Name)
				break
			}
		}
	}
	return weak
}

func formatWeakList(weak []string) string {
	if len(weak) <= 3 {
		return strings.Join(weak, ", ")
	}
	return strings.Join(weak[:3], ", ") + " +" + strconv.Itoa(len(weak)-3) + " more"
}

// ─── PCI DSS 4.0 ───────────────────────────────────────────────────

func evaluatePCI(data ComplianceInput) ComplianceResult {
	var findings []ComplianceFinding

	if !hasTLS12Plus(data.Protocols) {
		findings = append(findings, ComplianceFinding{"Req 4.2.1", "fail", "TLS 1.2 or higher not supported"})
	} else {
		findings = append(findings, ComplianceFinding{"Req 4.2.1", "pass", "TLS 1.2+ supported"})
	}

	if hasLegacyProtocol(data.Protocols) {
		findings = append(findings, ComplianceFinding{"Req 4.2.1", "fail", "Legacy protocols enabled"})
	}

	weak := findWeakCiphers(data.Ciphers)
	if len(weak) > 0 {
		findings = append(findings, ComplianceFinding{"Req 4.2.1", "fail", "Weak/insecure ciphers: " + formatWeakList(weak)})
	} else {
		findings = append(findings, ComplianceFinding{"Req 4.2.1", "pass", "No weak or insecure ciphers"})
	}

	if !data.ForwardSecrecy {
		findings = append(findings, ComplianceFinding{"Req 4.2.1", "fail", "Forward secrecy not supported"})
	} else {
		findings = append(findings, ComplianceFinding{"Req 4.2.1", "pass", "Forward secrecy enabled"})
	}

	if !data.ChainValid || data.DaysRemaining <= 0 {
		detail := "Invalid certificate chain"
		if data.DaysRemaining <= 0 {
			detail = "Certificate expired"
		}
		findings = append(findings, ComplianceFinding{"Req 4.2.1", "fail", detail})
	} else {
		findings = append(findings, ComplianceFinding{"Req 4.2.1", "pass", "Valid certificate chain"})
	}

	if !data.HSTSEnabled {
		findings = append(findings, ComplianceFinding{"Best Practice", "warn", "HSTS not enabled"})
	} else {
		findings = append(findings, ComplianceFinding{"Best Practice", "pass", "HSTS enabled"})
	}

	meets := true
	for _, f := range findings {
		if f.Status == "fail" {
			meets = false
			break
		}
	}

	return ComplianceResult{"pci-dss-4", "PCI DSS 4.0", meets, findings}
}

// ─── NIST SP 800-52r2 ───────────────────────────────────────────────

func evaluateNIST(data ComplianceInput) ComplianceResult {
	var findings []ComplianceFinding

	if !hasTLS12Plus(data.Protocols) {
		findings = append(findings, ComplianceFinding{"Sec 3.1", "fail", "TLS 1.2 or higher not supported"})
	} else {
		findings = append(findings, ComplianceFinding{"Sec 3.1", "pass", "TLS 1.2+ supported"})
	}

	hasTLS13 := false
	for _, p := range data.Protocols {
		if p == "TLS 1.3" {
			hasTLS13 = true
		}
	}
	if !hasTLS13 {
		findings = append(findings, ComplianceFinding{"Sec 3.1", "warn", "TLS 1.3 not supported (recommended)"})
	} else {
		findings = append(findings, ComplianceFinding{"Sec 3.1", "pass", "TLS 1.3 supported"})
	}

	if hasLegacyProtocol(data.Protocols) {
		findings = append(findings, ComplianceFinding{"Sec 3.1", "fail", "Legacy protocols enabled"})
	}

	// Key size
	algUpper := strings.ToUpper(data.KeyAlg)
	if strings.Contains(algUpper, "RSA") {
		if data.KeySize > 0 && data.KeySize < 2048 {
			findings = append(findings, ComplianceFinding{"Sec 3.3", "fail",
				"RSA key " + strconv.Itoa(data.KeySize) + "-bit < 2048-bit minimum"})
		} else if data.KeySize >= 2048 {
			findings = append(findings, ComplianceFinding{"Sec 3.3", "pass",
				"RSA " + strconv.Itoa(data.KeySize) + "-bit key meets minimum"})
		}
	} else if strings.Contains(algUpper, "ECDSA") || strings.Contains(algUpper, "EC") {
		if data.KeySize > 0 && data.KeySize < 256 {
			findings = append(findings, ComplianceFinding{"Sec 3.3", "fail",
				"ECDSA key " + strconv.Itoa(data.KeySize) + "-bit < 256-bit minimum"})
		} else if data.KeySize >= 256 {
			findings = append(findings, ComplianceFinding{"Sec 3.3", "pass",
				"ECDSA " + strconv.Itoa(data.KeySize) + "-bit key meets minimum"})
		}
	}

	weak := findWeakCiphers(data.Ciphers)
	if len(weak) > 0 {
		findings = append(findings, ComplianceFinding{"Sec 3.3", "fail", "Weak/insecure ciphers: " + formatWeakList(weak)})
	} else {
		findings = append(findings, ComplianceFinding{"Sec 3.3", "pass", "No weak or insecure ciphers"})
	}

	if !data.ForwardSecrecy {
		findings = append(findings, ComplianceFinding{"Sec 3.3", "fail", "Forward secrecy not supported"})
	} else {
		findings = append(findings, ComplianceFinding{"Sec 3.3", "pass", "Forward secrecy enabled"})
	}

	if !data.OCSPStapling {
		findings = append(findings, ComplianceFinding{"Sec 4.4", "warn", "OCSP stapling not present (recommended)"})
	} else {
		findings = append(findings, ComplianceFinding{"Sec 4.4", "pass", "OCSP stapling enabled"})
	}

	if !data.ChainValid || data.DaysRemaining <= 0 {
		detail := "Invalid certificate chain"
		if data.DaysRemaining <= 0 {
			detail = "Certificate expired"
		}
		findings = append(findings, ComplianceFinding{"Sec 4", "fail", detail})
	} else {
		findings = append(findings, ComplianceFinding{"Sec 4", "pass", "Valid certificate chain"})
	}

	meets := true
	for _, f := range findings {
		if f.Status == "fail" {
			meets = false
			break
		}
	}

	return ComplianceResult{"nist-800-52r2", "NIST 800-52r2", meets, findings}
}

// ─── HIPAA ──────────────────────────────────────────────────────────

func evaluateHIPAA(data ComplianceInput) ComplianceResult {
	var findings []ComplianceFinding

	if !hasTLS12Plus(data.Protocols) {
		findings = append(findings, ComplianceFinding{"§164.312(e)(1)", "fail", "TLS 1.2 or higher not supported"})
	} else {
		findings = append(findings, ComplianceFinding{"§164.312(e)(1)", "pass", "TLS 1.2+ supported"})
	}

	if hasLegacyProtocol(data.Protocols) {
		findings = append(findings, ComplianceFinding{"§164.312(e)(1)", "fail", "Legacy protocols enabled"})
	}

	weak := findWeakCiphers(data.Ciphers)
	if len(weak) > 0 {
		findings = append(findings, ComplianceFinding{"§164.312(e)(1)", "fail", "Insecure ciphers: " + formatWeakList(weak)})
	} else {
		findings = append(findings, ComplianceFinding{"§164.312(e)(1)", "pass", "Strong encryption (AES) in use"})
	}

	if !data.ChainValid || data.DaysRemaining <= 0 {
		detail := "Invalid certificate chain"
		if data.DaysRemaining <= 0 {
			detail = "Certificate expired"
		}
		findings = append(findings, ComplianceFinding{"§164.312(e)(1)", "fail", detail})
	} else {
		findings = append(findings, ComplianceFinding{"§164.312(e)(1)", "pass", "Valid certificate chain"})
	}

	if !data.ForwardSecrecy {
		findings = append(findings, ComplianceFinding{"Best Practice", "warn", "Forward secrecy not supported (recommended)"})
	} else {
		findings = append(findings, ComplianceFinding{"Best Practice", "pass", "Forward secrecy enabled"})
	}

	meets := true
	for _, f := range findings {
		if f.Status == "fail" {
			meets = false
			break
		}
	}

	return ComplianceResult{"hipaa", "HIPAA", meets, findings}
}

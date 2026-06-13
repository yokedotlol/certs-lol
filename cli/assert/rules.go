package assert

import (
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/yokedotlol/certs-lol/probe"
)

// RuleDef defines a single assertion rule.
type RuleDef struct {
	Name        string
	Category    string
	Description string
	ArgsHint    string // e.g., "<grade>", "<N>", ""
	NeedsEnrich bool
	Eval        func(data ScanData, args []string) AssertResult
}

// RuleRegistry maps rule names to their definitions.
var RuleRegistry = map[string]RuleDef{}

// RuleCategories defines the display order.
var RuleCategories = []string{"Grade", "Certificate", "Protocol", "Ciphers", "Security", "Compliance", "Mail"}

// RulesByCategory returns rules grouped and ordered by category.
// Rules within each category are sorted by name for consistent display.
func RulesByCategory() map[string][]RuleDef {
	out := make(map[string][]RuleDef)
	for _, def := range RuleRegistry {
		out[def.Category] = append(out[def.Category], def)
	}
	// Sort within each category
	for cat := range out {
		rules := out[cat]
		sort.Slice(rules, func(i, j int) bool {
			return rules[i].Name < rules[j].Name
		})
		out[cat] = rules
	}
	return out
}

func init() {
	// ─── Grade ──────────────────────────────────────────────────────
	register(RuleDef{
		Name: "min-grade", Category: "Grade",
		Description: "Grade must be ≥ threshold (A+, A, B, C, D, F)",
		ArgsHint:    "<grade>",
		Eval: func(data ScanData, args []string) AssertResult {
			if len(args) < 1 {
				return fail("a grade argument (A+, A, B, C, D, F)", "no argument provided")
			}
			min := args[0]
			actual := data.Probe.Grade
			return AssertResult{
				Passed:   probe_gradeAtLeast(actual, min),
				Expected: "≥ " + min,
				Actual:   actual,
			}
		},
	})

	// ─── Certificate ────────────────────────────────────────────────
	register(RuleDef{
		Name: "cert-days", Category: "Certificate",
		Description: "Certificate must have ≥ N days until expiry",
		ArgsHint:    "<N>",
		Eval: func(data ScanData, args []string) AssertResult {
			n, err := requireInt(args, 0)
			if err != nil {
				return fail("a number of days", err.Error())
			}
			actual := data.Probe.DaysRemaining
			passed := actual >= n
			actualStr := fmt.Sprintf("%d days remaining (expires %s)", actual, data.Probe.ValidTo)
			return AssertResult{Passed: passed, Expected: fmt.Sprintf("≥ %d days", n), Actual: actualStr}
		},
	})

	register(RuleDef{
		Name: "cert-type", Category: "Certificate",
		Description: "Validation level (DV, OV, EV) — minimum match",
		ArgsHint:    "<type>",
		Eval: func(data ScanData, args []string) AssertResult {
			if len(args) < 1 {
				return fail("a cert type (DV, OV, EV)", "no argument provided")
			}
			required := strings.ToUpper(args[0])
			actual := data.Probe.CertType
			if actual == "" {
				actual = "DV" // fallback if probe didn't populate
			}
			order := map[string]int{"DV": 1, "OV": 2, "EV": 3}
			reqLevel := order[required]
			actLevel := order[actual]
			if reqLevel == 0 {
				return fail("valid type (DV, OV, EV)", "unknown type: "+required)
			}
			return AssertResult{
				Passed:   actLevel >= reqLevel,
				Expected: "≥ " + required,
				Actual:   actual,
			}
		},
	})

	register(RuleDef{
		Name: "cert-key-min", Category: "Certificate",
		Description: "Minimum key size in bits",
		ArgsHint:    "<bits>",
		Eval: func(data ScanData, args []string) AssertResult {
			n, err := requireInt(args, 0)
			if err != nil {
				return fail("a key size in bits", err.Error())
			}
			actual := data.Probe.KeySize
			return AssertResult{
				Passed:   actual >= n,
				Expected: fmt.Sprintf("≥ %d bits", n),
				Actual:   fmt.Sprintf("%s %d-bit", data.Probe.KeyAlg, actual),
			}
		},
	})

	register(RuleDef{
		Name: "cert-key-type", Category: "Certificate",
		Description: "Key type (RSA, ECDSA, Ed25519)",
		ArgsHint:    "<type>",
		Eval: func(data ScanData, args []string) AssertResult {
			if len(args) < 1 {
				return fail("a key type", "no argument provided")
			}
			expected := strings.ToUpper(args[0])
			actual := strings.ToUpper(data.Probe.KeyAlg)
			return AssertResult{
				Passed:   actual == expected,
				Expected: expected,
				Actual:   data.Probe.KeyAlg,
			}
		},
	})

	register(RuleDef{
		Name: "cert-san", Category: "Certificate",
		Description: "At least one SAN must match glob pattern",
		ArgsHint:    "<pattern>",
		Eval: func(data ScanData, args []string) AssertResult {
			if len(args) < 1 {
				return fail("a glob pattern", "no argument provided")
			}
			pattern := args[0]
			for _, san := range data.Probe.SANs {
				if matched, _ := path.Match(pattern, san); matched {
					return AssertResult{
						Passed:   true,
						Expected: "SAN matching " + pattern,
						Actual:   san,
					}
				}
			}
			sanList := strings.Join(data.Probe.SANs, ", ")
			if len(sanList) > 80 {
				sanList = sanList[:77] + "..."
			}
			return AssertResult{
				Passed:   false,
				Expected: "SAN matching " + pattern,
				Actual:   "no match in [" + sanList + "]",
			}
		},
	})

	register(RuleDef{
		Name: "cert-issuer", Category: "Certificate",
		Description: "Issuer must contain string",
		ArgsHint:    "<pattern>",
		Eval: func(data ScanData, args []string) AssertResult {
			if len(args) < 1 {
				return fail("an issuer pattern", "no argument provided")
			}
			pattern := strings.ToLower(strings.Join(args, " "))
			issuer := data.Probe.Issuer
			return AssertResult{
				Passed:   strings.Contains(strings.ToLower(issuer), pattern),
				Expected: "issuer containing " + strconv.Quote(strings.Join(args, " ")),
				Actual:   issuer,
			}
		},
	})

	register(RuleDef{
		Name: "cert-chain-valid", Category: "Certificate",
		Description: "Chain must be valid",
		Eval: func(data ScanData, args []string) AssertResult {
			return AssertResult{
				Passed:   data.Probe.ChainValid,
				Expected: "valid chain",
				Actual:   boolStr(data.Probe.ChainValid, "valid", "invalid"),
			}
		},
	})

	register(RuleDef{
		Name: "cert-has-scts", Category: "Certificate",
		Description: "CT SCTs must be present",
		Eval: func(data ScanData, args []string) AssertResult {
			return AssertResult{
				Passed:   data.Probe.HasSCTs,
				Expected: "SCTs present",
				Actual:   fmt.Sprintf("%d SCTs", data.Probe.SCTCount),
			}
		},
	})

	// ─── Protocol ───────────────────────────────────────────────────
	register(RuleDef{
		Name: "min-tls", Category: "Protocol",
		Description: "Minimum supported TLS version must be ≥",
		ArgsHint:    "<ver>",
		Eval: func(data ScanData, args []string) AssertResult {
			if len(args) < 1 {
				return fail("a TLS version (1.0, 1.1, 1.2, 1.3)", "no argument provided")
			}
			minVer := args[0]
			minOrder := tlsVersionOrder(minVer)
			if minOrder == 0 {
				return fail("valid version (1.0, 1.1, 1.2, 1.3)", "unknown: "+minVer)
			}
			// Find the minimum version the server supports
			lowestOrder := 99
			lowestName := "none"
			for _, p := range data.Probe.Protocols {
				ver := strings.TrimPrefix(p, "TLS ")
				o := tlsVersionOrder(ver)
				if o > 0 && o < lowestOrder {
					lowestOrder = o
					lowestName = ver
				}
			}
			if lowestName == "none" {
				return AssertResult{Passed: false, Expected: "min TLS " + minVer, Actual: "no TLS protocols detected"}
			}
			return AssertResult{
				Passed:   lowestOrder >= minOrder,
				Expected: "min TLS ≥ " + minVer,
				Actual:   "lowest supported: TLS " + lowestName,
			}
		},
	})

	register(RuleDef{
		Name: "max-tls", Category: "Protocol",
		Description: "Maximum supported TLS version must be ≤",
		ArgsHint:    "<ver>",
		Eval: func(data ScanData, args []string) AssertResult {
			if len(args) < 1 {
				return fail("a TLS version", "no argument provided")
			}
			maxVer := args[0]
			maxOrder := tlsVersionOrder(maxVer)
			if maxOrder == 0 {
				return fail("valid version", "unknown: "+maxVer)
			}
			highestOrder := 0
			highestName := "none"
			for _, p := range data.Probe.Protocols {
				ver := strings.TrimPrefix(p, "TLS ")
				o := tlsVersionOrder(ver)
				if o > highestOrder {
					highestOrder = o
					highestName = ver
				}
			}
			return AssertResult{
				Passed:   highestOrder <= maxOrder,
				Expected: "max TLS ≤ " + maxVer,
				Actual:   "highest supported: TLS " + highestName,
			}
		},
	})

	register(RuleDef{
		Name: "no-tls1.0", Category: "Protocol",
		Description: "TLS 1.0 must not be supported",
		Eval: func(data ScanData, args []string) AssertResult {
			has := hasProtocol(data.Probe.Protocols, "TLS 1.0")
			return AssertResult{
				Passed:   !has,
				Expected: "TLS 1.0 not supported",
				Actual:   boolStr(has, "TLS 1.0 supported", "TLS 1.0 not supported"),
			}
		},
	})

	register(RuleDef{
		Name: "no-tls1.1", Category: "Protocol",
		Description: "TLS 1.1 must not be supported",
		Eval: func(data ScanData, args []string) AssertResult {
			has := hasProtocol(data.Probe.Protocols, "TLS 1.1")
			return AssertResult{
				Passed:   !has,
				Expected: "TLS 1.1 not supported",
				Actual:   boolStr(has, "TLS 1.1 supported", "TLS 1.1 not supported"),
			}
		},
	})

	register(RuleDef{
		Name: "has-tls1.3", Category: "Protocol",
		Description: "TLS 1.3 must be supported",
		Eval: func(data ScanData, args []string) AssertResult {
			has := hasProtocol(data.Probe.Protocols, "TLS 1.3")
			return AssertResult{
				Passed:   has,
				Expected: "TLS 1.3 supported",
				Actual:   boolStr(has, "TLS 1.3 supported", "TLS 1.3 not supported"),
			}
		},
	})

	register(RuleDef{
		Name: "has-pq", Category: "Protocol",
		Description: "Post-quantum key exchange required",
		Eval: func(data ScanData, args []string) AssertResult {
			kex := data.Probe.KeyExchange
			pq := strings.Contains(strings.ToUpper(kex), "MLKEM") ||
				strings.Contains(strings.ToUpper(kex), "KYBER") ||
				strings.Contains(strings.ToUpper(kex), "X25519MLKEM")
			// Also check cipher names
			if !pq {
				for _, c := range data.Probe.Ciphers {
					if strings.Contains(strings.ToUpper(c.Name), "MLKEM") ||
						strings.Contains(strings.ToUpper(c.Name), "KYBER") {
						pq = true
						break
					}
				}
			}
			actual := kex
			if actual == "" {
				actual = "no PQ key exchange detected"
			}
			return AssertResult{
				Passed:   pq,
				Expected: "X25519MLKEM768 or equivalent",
				Actual:   actual,
			}
		},
	})

	register(RuleDef{
		Name: "has-ech", Category: "Protocol",
		Description: "Encrypted Client Hello required",
		Eval: func(data ScanData, args []string) AssertResult {
			// ECH detection requires HTTPS/SVCB DNS record checks
			// Best-effort: check Alt-Svc for ECH indicators if enrichment available
			if data.Enrich != nil && data.Enrich.HTTP3.AltSvc != nil {
				altSvc := *data.Enrich.HTTP3.AltSvc
				if strings.Contains(strings.ToLower(altSvc), "ech=") {
					return AssertResult{Passed: true, Expected: "ECH supported", Actual: "ECH advertised via Alt-Svc"}
				}
			}
			return AssertResult{
				Passed:   false,
				Expected: "ECH supported",
				Actual:   "ECH not detected",
			}
		},
	})

	// ─── Ciphers ────────────────────────────────────────────────────
	register(RuleDef{
		Name: "no-insecure-ciphers", Category: "Ciphers",
		Description: "Zero insecure ciphers (RC4, NULL, EXPORT, anon)",
		Eval: func(data ScanData, args []string) AssertResult {
			count := countCipherStrength(data.Probe.Ciphers, "insecure")
			return AssertResult{
				Passed:   count == 0,
				Expected: "0 insecure ciphers",
				Actual:   fmt.Sprintf("%d insecure ciphers", count),
			}
		},
	})

	register(RuleDef{
		Name: "no-weak-ciphers", Category: "Ciphers",
		Description: "Zero weak ciphers (3DES, CBC-no-FS, RSA-kex)",
		Eval: func(data ScanData, args []string) AssertResult {
			count := countCipherStrength(data.Probe.Ciphers, "weak")
			return AssertResult{
				Passed:   count == 0,
				Expected: "0 weak ciphers",
				Actual:   fmt.Sprintf("%d weak ciphers", count),
			}
		},
	})

	register(RuleDef{
		Name: "max-weak-ciphers", Category: "Ciphers",
		Description: "At most N weak ciphers allowed",
		ArgsHint:    "<N>",
		Eval: func(data ScanData, args []string) AssertResult {
			n, err := requireInt(args, 0)
			if err != nil {
				return fail("a number", err.Error())
			}
			count := countCipherStrength(data.Probe.Ciphers, "weak")
			return AssertResult{
				Passed:   count <= n,
				Expected: fmt.Sprintf("≤ %d weak ciphers", n),
				Actual:   fmt.Sprintf("%d weak ciphers", count),
			}
		},
	})

	register(RuleDef{
		Name: "min-strong-ciphers", Category: "Ciphers",
		Description: "At least N strong ciphers required",
		ArgsHint:    "<N>",
		Eval: func(data ScanData, args []string) AssertResult {
			n, err := requireInt(args, 0)
			if err != nil {
				return fail("a number", err.Error())
			}
			count := countCipherStrength(data.Probe.Ciphers, "strong")
			return AssertResult{
				Passed:   count >= n,
				Expected: fmt.Sprintf("≥ %d strong ciphers", n),
				Actual:   fmt.Sprintf("%d strong ciphers", count),
			}
		},
	})

	register(RuleDef{
		Name: "has-forward-secrecy", Category: "Ciphers",
		Description: "At least one FS cipher present",
		Eval: func(data ScanData, args []string) AssertResult {
			return AssertResult{
				Passed:   data.Probe.ForwardSecrecy,
				Expected: "forward secrecy enabled",
				Actual:   boolStr(data.Probe.ForwardSecrecy, data.Probe.KeyExchange, "no forward secrecy"),
			}
		},
	})

	// ─── Security ───────────────────────────────────────────────────
	register(RuleDef{
		Name: "has-hsts", Category: "Security",
		Description: "HSTS header required",
		NeedsEnrich: true,
		Eval: func(data ScanData, args []string) AssertResult {
			return AssertResult{
				Passed:   data.Enrich.HSTS.Enabled,
				Expected: "HSTS enabled",
				Actual:   boolStr(data.Enrich.HSTS.Enabled, "HSTS enabled", "HSTS not present"),
			}
		},
	})

	register(RuleDef{
		Name: "hsts-min-age", Category: "Security",
		Description: "HSTS max-age minimum",
		ArgsHint:    "<secs>",
		NeedsEnrich: true,
		Eval: func(data ScanData, args []string) AssertResult {
			n, err := requireInt(args, 0)
			if err != nil {
				return fail("seconds", err.Error())
			}
			if data.Enrich.HSTS.MaxAge == nil {
				return AssertResult{Passed: false, Expected: fmt.Sprintf("max-age ≥ %d", n), Actual: "HSTS not present"}
			}
			actual := *data.Enrich.HSTS.MaxAge
			return AssertResult{
				Passed:   actual >= n,
				Expected: fmt.Sprintf("max-age ≥ %d", n),
				Actual:   fmt.Sprintf("max-age=%d", actual),
			}
		},
	})

	register(RuleDef{
		Name: "has-hsts-preload", Category: "Security",
		Description: "HSTS preload directive required",
		NeedsEnrich: true,
		Eval: func(data ScanData, args []string) AssertResult {
			preload := data.Enrich.HSTS.Preload || data.Enrich.HSTS.OnPreloadList
			actual := "not preloaded"
			if data.Enrich.HSTS.OnPreloadList {
				actual = "on preload list"
			} else if data.Enrich.HSTS.Preload {
				actual = "preload directive present"
			}
			return AssertResult{Passed: preload, Expected: "HSTS preload", Actual: actual}
		},
	})

	register(RuleDef{
		Name: "has-dnssec", Category: "Security",
		Description: "DNSSEC required",
		NeedsEnrich: true,
		Eval: func(data ScanData, args []string) AssertResult {
			return AssertResult{
				Passed:   data.Enrich.DNSSecurity.DNSSEC,
				Expected: "DNSSEC enabled",
				Actual:   boolStr(data.Enrich.DNSSecurity.DNSSEC, "DNSSEC enabled", "DNSSEC not enabled"),
			}
		},
	})

	register(RuleDef{
		Name: "has-caa", Category: "Security",
		Description: "CAA records required",
		NeedsEnrich: true,
		Eval: func(data ScanData, args []string) AssertResult {
			has := len(data.Enrich.DNSSecurity.CAA) > 0
			actual := "no CAA records"
			if has {
				actual = fmt.Sprintf("%d CAA records", len(data.Enrich.DNSSecurity.CAA))
			}
			return AssertResult{Passed: has, Expected: "CAA records present", Actual: actual}
		},
	})

	register(RuleDef{
		Name: "has-ocsp-stapling", Category: "Security",
		Description: "OCSP stapling required",
		Eval: func(data ScanData, args []string) AssertResult {
			return AssertResult{
				Passed:   data.Probe.OCSPStapling,
				Expected: "OCSP stapling enabled",
				Actual:   boolStr(data.Probe.OCSPStapling, "OCSP stapling enabled", "OCSP stapling not present"),
			}
		},
	})

	// ─── Compliance ─────────────────────────────────────────────────
	register(RuleDef{
		Name: "compliant-pci", Category: "Compliance",
		Description: "PCI DSS 4.0 transport requirements",
		NeedsEnrich: true,
		Eval: func(data ScanData, args []string) AssertResult {
			return complianceCheck(data, "pci-dss-4", "PCI DSS 4.0")
		},
	})

	register(RuleDef{
		Name: "compliant-nist", Category: "Compliance",
		Description: "NIST SP 800-52r2 requirements",
		NeedsEnrich: true,
		Eval: func(data ScanData, args []string) AssertResult {
			return complianceCheck(data, "nist-800-52r2", "NIST 800-52r2")
		},
	})

	register(RuleDef{
		Name: "compliant-hipaa", Category: "Compliance",
		Description: "HIPAA transport requirements",
		NeedsEnrich: true,
		Eval: func(data ScanData, args []string) AssertResult {
			return complianceCheck(data, "hipaa", "HIPAA")
		},
	})

	// ─── Mail ───────────────────────────────────────────────────────
	register(RuleDef{
		Name: "has-starttls", Category: "Mail",
		Description: "Server must offer STARTTLS upgrade",
		Eval: func(data ScanData, args []string) AssertResult {
			return AssertResult{
				Passed:   data.Probe.StartTLS,
				Expected: "STARTTLS offered",
				Actual:   boolStr(data.Probe.StartTLS, "STARTTLS negotiated ("+data.Probe.StartTLSProto+")", "no STARTTLS"),
			}
		},
	})
}

func register(def RuleDef) {
	RuleRegistry[def.Name] = def
}

// ─── Helpers ────────────────────────────────────────────────────────

// probe_gradeAtLeast wraps the probe package's grade comparison without
// importing it (to avoid a direct import that we can call inline).
// We re-implement it here since assert already imports probe types.
func probe_gradeAtLeast(actual, minimum string) bool {
	order := map[string]int{"A+": 7, "A": 6, "B": 5, "C": 4, "D": 3, "F": 2, "T": 1}
	return order[actual] >= order[minimum]
}

func requireInt(args []string, idx int) (int, error) {
	if idx >= len(args) {
		return 0, fmt.Errorf("no argument provided")
	}
	n, err := strconv.Atoi(args[idx])
	if err != nil {
		return 0, fmt.Errorf("invalid number: %s", args[idx])
	}
	return n, nil
}

func fail(expected, actual string) AssertResult {
	return AssertResult{Passed: false, Expected: expected, Actual: actual}
}

func boolStr(v bool, t, f string) string {
	if v {
		return t
	}
	return f
}

func hasProtocol(protocols []string, name string) bool {
	for _, p := range protocols {
		if p == name {
			return true
		}
	}
	return false
}

func countCipherStrength(ciphers []probe.CipherInfo, strength string) int {
	count := 0
	for _, c := range ciphers {
		if c.Strength == strength {
			count++
		}
	}
	return count
}

func tlsVersionOrder(ver string) int {
	switch ver {
	case "1.0":
		return 1
	case "1.1":
		return 2
	case "1.2":
		return 3
	case "1.3":
		return 4
	default:
		return 0
	}
}

// detectCertType infers DV/OV/EV from the Subject DN string.
// Deprecated: prefer probe.ExtractCertType which uses policy OIDs.
// Kept as fallback for assertion display when CertType field is empty.
func detectCertType(subject string) string {
	hasOrg := strings.Contains(subject, "O=")
	hasSerial := strings.Contains(subject, "SERIALNUMBER=")
	hasJuris := strings.Contains(subject, "jurisdictionCountry=") ||
		strings.Contains(subject, "1.3.6.1.4.1.311.60.2.1.3=") // EV OID
	if hasOrg && (hasSerial || hasJuris) {
		return "EV"
	}
	if hasOrg {
		return "OV"
	}
	return "DV"
}

func complianceCheck(data ScanData, framework, displayName string) AssertResult {
	if data.Enrich == nil {
		return AssertResult{
			Passed:   false,
			Expected: displayName + " compliant",
			Actual:   "enrichment data required",
		}
	}
	for _, c := range data.Enrich.Compliance {
		if c.Framework == framework {
			actual := "does not meet requirements"
			if c.MeetsRequirements {
				actual = "meets requirements"
			} else {
				// Summarize failures
				var failures []string
				for _, f := range c.Findings {
					if f.Status == "fail" {
						failures = append(failures, f.Detail)
					}
				}
				if len(failures) > 0 {
					actual += ": " + strings.Join(failures, "; ")
					if len(actual) > 120 {
						actual = actual[:117] + "..."
					}
				}
			}
			return AssertResult{
				Passed:   c.MeetsRequirements,
				Expected: displayName + " compliant",
				Actual:   actual,
			}
		}
	}
	return AssertResult{
		Passed:   false,
		Expected: displayName + " compliant",
		Actual:   "compliance data not available",
	}
}

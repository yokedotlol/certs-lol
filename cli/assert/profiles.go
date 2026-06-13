package assert

// Profiles defines named assertion bundles.
var Profiles = map[string][]string{
	"production": {
		"min-grade A",
		"no-tls1.0",
		"no-tls1.1",
		"no-insecure-ciphers",
		"cert-days 14",
		"has-hsts",
	},
	"staging": {
		"min-grade B",
		"no-insecure-ciphers",
		"cert-days 7",
	},
	"strict": {
		"min-grade A+",
		"no-tls1.0",
		"no-tls1.1",
		"no-weak-ciphers",
		"no-insecure-ciphers",
		"has-tls1.3",
		"has-pq",
		"has-forward-secrecy",
		"cert-days 30",
		"has-hsts",
		"has-hsts-preload",
		"has-dnssec",
		"cert-has-scts",
	},
	"pci": {
		"compliant-pci",
		"no-insecure-ciphers",
		"no-weak-ciphers",
		"has-tls1.3",
		"cert-days 30",
		"has-hsts",
	},
	"nist": {
		"compliant-nist",
		"has-tls1.3",
		"no-tls1.0",
		"no-tls1.1",
		"cert-key-min 256",
	},
	"hipaa": {
		"compliant-hipaa",
		"cert-days 30",
		"no-insecure-ciphers",
		"has-hsts",
	},
	"baseline": {
		"min-grade C",
		"no-insecure-ciphers",
		"cert-days 7",
		"cert-chain-valid",
	},
}

// ProfileNames returns profile names in display order.
func ProfileNames() []string {
	return []string{"production", "staging", "strict", "pci", "nist", "hipaa", "baseline"}
}

// ExpandProfile returns the assertion strings for a named profile.
// Returns nil if the profile doesn't exist.
func ExpandProfile(name string) []string {
	p, ok := Profiles[name]
	if !ok {
		return nil
	}
	// Return a copy
	out := make([]string, len(p))
	copy(out, p)
	return out
}

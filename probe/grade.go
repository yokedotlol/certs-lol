package probe

import (
	"crypto/tls"
	"crypto/x509"
	"strings"
	"time"
)

// ComputeGrade calculates a letter grade for a TLS configuration.
// Grade ordering: A+ > A > B > C > D > F > T (trust error)
func ComputeGrade(state *tls.ConnectionState, leaf *x509.Certificate, chainValid bool, protocols []string, ciphers []CipherInfo) string {
	// Trust errors are always T
	if !chainValid {
		return "T"
	}

	now := time.Now()
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return "T"
	}

	hasTLS13 := false
	hasTLS12 := false
	hasTLS10or11 := false
	for _, p := range protocols {
		switch p {
		case "TLS 1.3":
			hasTLS13 = true
		case "TLS 1.2":
			hasTLS12 = true
		case "TLS 1.0", "TLS 1.1":
			hasTLS10or11 = true
		}
	}

	// No TLS 1.2+ at all
	if !hasTLS13 && !hasTLS12 {
		return "F"
	}

	// Weak key
	weakKey := false
	switch leaf.PublicKeyAlgorithm {
	case x509.RSA:
		if k, ok := leaf.PublicKey.(interface{ Size() int }); ok {
			if k.Size()*8 < 2048 {
				weakKey = true
			}
		}
	}

	// Count cipher categories
	insecureCount := 0
	weakCount := 0
	for _, c := range ciphers {
		switch c.Strength {
		case "insecure":
			insecureCount++
		case "weak":
			weakCount++
		}
	}

	// Insecure ciphers = cap at C
	if insecureCount > 0 {
		return "C"
	}

	// Legacy protocols or weak key = cap at B
	if hasTLS10or11 || weakKey {
		return "B"
	}

	// Weak ciphers (but no insecure) = cap at A
	if weakCount > 0 {
		return "A"
	}

	// Check for forward secrecy on negotiated cipher
	if state != nil {
		cipherName := tls.CipherSuiteName(state.CipherSuite)
		if state.Version != tls.VersionTLS13 &&
			!strings.Contains(cipherName, "ECDHE") &&
			!strings.Contains(cipherName, "DHE") {
			return "A"
		}
	}

	// TLS 1.3 + clean config = A+
	if hasTLS13 {
		return "A+"
	}

	return "A"
}

// GradeOrder returns the numeric rank of a grade (higher = better).
func GradeOrder(grade string) int {
	switch grade {
	case "A+":
		return 7
	case "A":
		return 6
	case "B":
		return 5
	case "C":
		return 4
	case "D":
		return 3
	case "F":
		return 2
	case "T":
		return 1
	default:
		return 0
	}
}

// GradeAtLeast returns true if actual >= minimum in grade ordering.
func GradeAtLeast(actual, minimum string) bool {
	return GradeOrder(actual) >= GradeOrder(minimum)
}

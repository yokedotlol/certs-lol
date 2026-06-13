package probe

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"strings"
)

// ─── EV OIDs ────────────────────────────────────────────────────────
// CA/Browser Forum EV Certificate Policy OIDs for major CAs.
// A certificate with any of these in its Certificate Policies
// extension was issued under Extended Validation.

var evOIDs = map[string]string{
	// DigiCert / Symantec / Thawte / GeoTrust
	"2.16.840.1.114412.2.1":      "DigiCert",
	"2.16.840.1.113733.1.7.23.6": "Symantec/VeriSign",
	"2.16.840.1.114404.1.1.2.4.1": "Thawte",

	// Sectigo / Comodo
	"1.3.6.1.4.1.6449.1.2.1.5.1": "Sectigo/Comodo",

	// GlobalSign
	"1.3.6.1.4.1.4146.1.1": "GlobalSign",

	// Entrust
	"2.16.840.1.114028.10.1.2": "Entrust",

	// GoDaddy / Starfield
	"2.16.840.1.114413.1.7.23.3": "GoDaddy",
	"2.16.840.1.114414.1.7.23.3": "Starfield",

	// Let's Encrypt (does NOT issue EV, but listed for completeness — won't match)
	// Amazon Trust Services
	"2.23.140.1.1": "CA/B Forum EV (generic)",

	// QuoVadis
	"1.3.6.1.4.1.8024.0.2.100.1.2": "QuoVadis",

	// SwissSign
	"2.16.756.1.89.1.2.1.1": "SwissSign",

	// Buypass
	"2.16.578.1.26.1.3.3": "Buypass",

	// SECOM
	"1.2.392.200091.100.721.1": "SECOM",

	// Certum
	"1.2.616.1.113527.2.5.1.1": "Certum",

	// TWCA
	"1.3.6.1.4.1.40869.1.1.22.3": "TWCA",

	// D-TRUST
	"1.3.6.1.4.1.4788.2.202.1": "D-TRUST",
}

// OCSP Must-Staple OID (TLS Feature extension, RFC 7633)
var oidMustStaple = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 24}

// Must-Staple value: status_request (5)
var mustStapleValue = []byte{0x30, 0x03, 0x02, 0x01, 0x05}

// ─── Extraction functions ───────────────────────────────────────────

// ExtractCertType determines DV/OV/EV from certificate policy OIDs
// and subject distinguished name fields.
func ExtractCertType(cert *x509.Certificate) string {
	// Check for EV OIDs first
	for _, oid := range cert.PolicyIdentifiers {
		oidStr := oid.String()
		if _, ok := evOIDs[oidStr]; ok {
			return "EV"
		}
	}

	// OV: has Organization in Subject
	if len(cert.Subject.Organization) > 0 {
		for _, org := range cert.Subject.Organization {
			if strings.TrimSpace(org) != "" {
				return "OV"
			}
		}
	}

	return "DV"
}

// ExtractKeyUsage returns human-readable key usage strings from the bitmask.
func ExtractKeyUsage(ku x509.KeyUsage) []string {
	var usages []string
	mapping := []struct {
		bit  x509.KeyUsage
		name string
	}{
		{x509.KeyUsageDigitalSignature, "digitalSignature"},
		{x509.KeyUsageContentCommitment, "contentCommitment"},
		{x509.KeyUsageKeyEncipherment, "keyEncipherment"},
		{x509.KeyUsageDataEncipherment, "dataEncipherment"},
		{x509.KeyUsageKeyAgreement, "keyAgreement"},
		{x509.KeyUsageCertSign, "keyCertSign"},
		{x509.KeyUsageCRLSign, "cRLSign"},
		{x509.KeyUsageEncipherOnly, "encipherOnly"},
		{x509.KeyUsageDecipherOnly, "decipherOnly"},
	}
	for _, m := range mapping {
		if ku&m.bit != 0 {
			usages = append(usages, m.name)
		}
	}
	return usages
}

// ExtractExtKeyUsage returns human-readable extended key usage strings.
func ExtractExtKeyUsage(ekus []x509.ExtKeyUsage) []string {
	var usages []string
	for _, eku := range ekus {
		switch eku {
		case x509.ExtKeyUsageServerAuth:
			usages = append(usages, "serverAuth")
		case x509.ExtKeyUsageClientAuth:
			usages = append(usages, "clientAuth")
		case x509.ExtKeyUsageCodeSigning:
			usages = append(usages, "codeSigning")
		case x509.ExtKeyUsageEmailProtection:
			usages = append(usages, "emailProtection")
		case x509.ExtKeyUsageTimeStamping:
			usages = append(usages, "timeStamping")
		case x509.ExtKeyUsageOCSPSigning:
			usages = append(usages, "ocspSigning")
		case x509.ExtKeyUsageAny:
			usages = append(usages, "any")
		default:
			usages = append(usages, fmt.Sprintf("unknown(%d)", int(eku)))
		}
	}
	return usages
}

// ExtractPolicyOIDs returns string representations of certificate policy OIDs.
func ExtractPolicyOIDs(oids []asn1.ObjectIdentifier) []string {
	var result []string
	for _, oid := range oids {
		s := oid.String()
		// Add human-readable label if known
		if label, ok := evOIDs[s]; ok {
			result = append(result, s+" ("+label+" EV)")
		} else if s == "2.23.140.1.2.1" {
			result = append(result, s+" (DV)")
		} else if s == "2.23.140.1.2.2" {
			result = append(result, s+" (OV)")
		} else {
			result = append(result, s)
		}
	}
	return result
}

// ExtractOCSPMustStaple checks for the TLS Feature extension (RFC 7633)
// with status_request, indicating the server must staple OCSP responses.
func ExtractOCSPMustStaple(cert *x509.Certificate) bool {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidMustStaple) {
			// Check for status_request (5) in the TLS feature list
			// The value is a SEQUENCE of INTEGERs; status_request = 5
			return containsMustStapleValue(ext.Value)
		}
	}
	return false
}

// containsMustStapleValue checks if the extension value contains
// status_request (5) as a TLS feature.
func containsMustStapleValue(data []byte) bool {
	// Simple check: any TLS Feature extension present with value
	// containing 5 (status_request) means must-staple
	if len(data) == 0 {
		return false
	}

	// Parse as ASN.1 SEQUENCE of INTEGERs
	var features []int
	rest := data

	// Outer SEQUENCE
	if len(rest) < 2 || rest[0] != 0x30 {
		return false
	}
	seqLen := int(rest[1])
	rest = rest[2:]
	if len(rest) < seqLen {
		return false
	}
	rest = rest[:seqLen]

	// Parse INTEGERs
	for len(rest) >= 3 {
		if rest[0] != 0x02 { // INTEGER tag
			break
		}
		intLen := int(rest[1])
		if len(rest) < 2+intLen {
			break
		}
		val := 0
		for i := 0; i < intLen; i++ {
			val = (val << 8) | int(rest[2+i])
		}
		features = append(features, val)
		rest = rest[2+intLen:]
	}

	for _, f := range features {
		if f == 5 { // status_request
			return true
		}
	}
	return false
}

// ExtractIPAddresses returns string representations of IP SANs.
func ExtractIPAddresses(cert *x509.Certificate) []string {
	var ips []string
	for _, ip := range cert.IPAddresses {
		ips = append(ips, ip.String())
	}
	return ips
}

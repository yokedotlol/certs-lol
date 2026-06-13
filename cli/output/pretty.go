// Package output provides formatters for scan results.
package output

import (
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/yokedotlol/certs-lol/enrich"
	"github.com/yokedotlol/certs-lol/probe"
)

// ANSI color codes
const (
	reset  = "\033[0m"
	bold   = "\033[1m"
	dim    = "\033[2m"
	red    = "\033[31m"
	green  = "\033[32m"
	yellow = "\033[33m"
	cyan   = "\033[36m"
)

func check(ok bool) string {
	if ok {
		return green + "✓" + reset
	}
	return red + "✗" + reset
}

func gradeColor(grade string) string {
	switch {
	case grade == "A+" || grade == "A":
		return green
	case grade == "B":
		return yellow
	default:
		return red
	}
}

// Pretty writes a human-readable scan result to w.
func Pretty(w io.Writer, target string, result probe.SSLResult, enrichResult *enrich.Result) {
	// Header line
	gradeC := gradeColor(result.Grade)
	fmt.Fprintf(w, "\n  %s%-50s%s  %s%s%s    %dms\n\n",
		bold, target, reset,
		bold+gradeC, result.Grade, reset,
		result.ProbeMs)

	if result.Error != nil {
		fmt.Fprintf(w, "  %sError: %s%s\n\n", red, *result.Error, reset)
		return
	}

	// ─── Certificate ────────────────────────────────────────────
	fmt.Fprintf(w, "  %sCertificate%s\n", cyan, reset)

	// Extract display-friendly subject
	subject := extractCN(result.Subject)
	issuer := extractCNOrOrg(result.Issuer)
	certType := certTypeDisplay(result.CertType)
	validFrom := formatDate(result.ValidFrom)
	validTo := formatDate(result.ValidTo)
	keyDesc := fmt.Sprintf("%s %d-bit", result.KeyAlg, result.KeySize)

	fmt.Fprintf(w, "  ├─ Subject     %s\n", subject)
	fmt.Fprintf(w, "  ├─ Issuer      %s\n", issuer)
	fmt.Fprintf(w, "  ├─ Valid       %s → %s (%d days)\n", validFrom, validTo, result.DaysRemaining)
	fmt.Fprintf(w, "  ├─ Type        %s\n", certType)
	fmt.Fprintf(w, "  ├─ Key         %s\n", keyDesc)

	if len(result.SANs) > 0 {
		sanDisplay := strings.Join(result.SANs, ", ")
		if len(sanDisplay) > 60 {
			sanDisplay = strings.Join(result.SANs[:min(3, len(result.SANs))], ", ")
			if len(result.SANs) > 3 {
				sanDisplay += fmt.Sprintf(" +%d more", len(result.SANs)-3)
			}
		}
		fmt.Fprintf(w, "  ├─ SANs        %s\n", sanDisplay)
	}

	if len(result.ExtKeyUsage) > 0 {
		fmt.Fprintf(w, "  ├─ EKU         %s\n", strings.Join(result.ExtKeyUsage, ", "))
	}

	sctStr := fmt.Sprintf("%d", result.SCTCount)
	if result.HasSCTs {
		sctStr += " (Certificate Transparency)"
	}
	fmt.Fprintf(w, "  └─ SCTs        %s\n", sctStr)

	// ─── Protocols ──────────────────────────────────────────────
	fmt.Fprintf(w, "\n  %sProtocols%s\n", cyan, reset)
	allVersions := []string{"TLS 1.3", "TLS 1.2", "TLS 1.1", "TLS 1.0"}
	for i, v := range allVersions {
		prefix := "├─"
		if i == len(allVersions)-1 {
			prefix = "└─"
		}
		has := false
		for _, p := range result.Protocols {
			if p == v {
				has = true
				break
			}
		}
		fmt.Fprintf(w, "  %s %-10s %s\n", prefix, v, check(has))
	}

	// ─── Cipher Suites ──────────────────────────────────────────
	strong, acceptable, weak, insecure := countCiphers(result.Ciphers)
	total := len(result.Ciphers)

	fmt.Fprintf(w, "\n  %sCipher Suites%s%s%d total%s\n", cyan, reset, strings.Repeat(" ", 30), total, "")
	fmt.Fprintf(w, "  ├─ Strong      %-4d  %s\n", strong, cipherBar(strong, total, green))
	fmt.Fprintf(w, "  ├─ Acceptable  %-4d  %s\n", acceptable, cipherBar(acceptable, total, yellow))
	fmt.Fprintf(w, "  ├─ Weak        %-4d%s\n", weak, warnCount(weak))
	fmt.Fprintf(w, "  └─ Insecure    %-4d%s\n", insecure, warnCount(insecure))

	// ─── Features ───────────────────────────────────────────────
	fmt.Fprintf(w, "\n")

	// Post-Quantum
	pq := strings.Contains(strings.ToUpper(result.KeyExchange), "MLKEM") ||
		strings.Contains(strings.ToUpper(result.KeyExchange), "KYBER")
	pqDetail := ""
	if pq {
		pqDetail = "  " + result.KeyExchange
	}
	fmt.Fprintf(w, "  Post-Quantum   %s%s\n", check(pq), pqDetail)

	// ECH
	echDetected := false
	echDetail := ""
	if enrichResult != nil && enrichResult.HTTP3.AltSvc != nil {
		altSvc := *enrichResult.HTTP3.AltSvc
		if strings.Contains(strings.ToLower(altSvc), "ech=") {
			echDetected = true
			echDetail = "  (via Alt-Svc)"
		}
	}
	fmt.Fprintf(w, "  ECH            %s%s\n", check(echDetected), echDetail)

	// HTTP/3
	if enrichResult != nil {
		h3Supported := enrichResult.HTTP3.Supported
		h3Detail := ""
		if h3Supported && enrichResult.HTTP3.AltSvc != nil {
			h3Detail = "  (Alt-Svc advertised)"
		}
		fmt.Fprintf(w, "  HTTP/3         %s%s\n", check(h3Supported), h3Detail)
	}

	// HSTS
	if enrichResult != nil {
		hstsDetail := ""
		if enrichResult.HSTS.Enabled && enrichResult.HSTS.MaxAge != nil {
			parts := []string{fmt.Sprintf("max-age=%d", *enrichResult.HSTS.MaxAge)}
			if enrichResult.HSTS.IncludeSubdomains {
				parts = append(parts, "includeSubDomains")
			}
			if enrichResult.HSTS.Preload {
				parts = append(parts, "preload")
			}
			hstsDetail = "  " + strings.Join(parts, "; ")
		}
		fmt.Fprintf(w, "  HSTS           %s%s\n", check(enrichResult.HSTS.Enabled), hstsDetail)
	}

	fmt.Fprintf(w, "  OCSP Stapling  %s\n", check(result.OCSPStapling))

	// OCSP Must-Staple warning
	if result.OCSPMustStaple {
		if result.OCSPStapling {
			fmt.Fprintf(w, "  Must-Staple    %s  (required and present)\n", check(true))
		} else {
			fmt.Fprintf(w, "  Must-Staple    %s  %s⚠ required but NOT stapled%s\n", check(false), red, reset)
		}
	}

	// ─── STARTTLS info ──────────────────────────────────────────
	if result.StartTLS {
		fmt.Fprintf(w, "  STARTTLS       %s  (%s)\n", check(true), strings.ToUpper(result.StartTLSProto))
	}

	// ─── DNS Security ───────────────────────────────────────────
	if enrichResult != nil {
		fmt.Fprintf(w, "\n  %sDNS Security%s\n", cyan, reset)
		fmt.Fprintf(w, "  ├─ DNSSEC      %s\n", check(enrichResult.DNSSecurity.DNSSEC))

		if len(enrichResult.DNSSecurity.CAA) > 0 {
			caaStr := strings.Join(enrichResult.DNSSecurity.CAA, ", ")
			if len(caaStr) > 70 {
				caaStr = caaStr[:67] + "..."
			}
			fmt.Fprintf(w, "  ├─ CAA         %s\n", caaStr)
		} else {
			fmt.Fprintf(w, "  ├─ CAA         %s\n", dim+"none"+reset)
		}

		hasDane := enrichResult.DNSSecurity.DANETLSA != nil
		fmt.Fprintf(w, "  └─ DANE/TLSA   %s\n", check(hasDane))

		// ─── Compliance ─────────────────────────────────────────
		if len(enrichResult.Compliance) > 0 {
			fmt.Fprintf(w, "\n  %sCompliance%s\n", cyan, reset)
			for i, c := range enrichResult.Compliance {
				prefix := "├─"
				if i == len(enrichResult.Compliance)-1 {
					prefix = "└─"
				}
				status := check(c.MeetsRequirements)
				detail := "meets requirements"
				if !c.MeetsRequirements {
					detail = "does not meet requirements"
				}
				fmt.Fprintf(w, "  %s %-16s %s %s\n", prefix, c.DisplayName, status, detail)
			}
		}
	}

	// Footer — show shareable report link for public HTTPS domains only
	if !strings.Contains(target, ":") || strings.HasSuffix(target, ":443") {
		host := target
		if idx := strings.LastIndex(host, ":"); idx != -1 {
			host = host[:idx]
		}
		// Skip for IP addresses and private/internal hosts
		ip := net.ParseIP(host)
		if ip == nil && !strings.HasSuffix(host, ".local") && !strings.HasSuffix(host, ".internal") && !strings.HasSuffix(host, ".localhost") {
			fmt.Fprintf(w, "\n  → Shareable report: https://certs.lol/%s\n\n", target)
		} else {
			fmt.Fprintln(w)
		}
	} else {
		fmt.Fprintln(w)
	}
}

// GradeOnly prints just the letter grade.
func GradeOnly(w io.Writer, target string, grade string) {
	fmt.Fprintf(w, "%s\t%s\n", target, grade)
}

// ─── Helpers ────────────────────────────────────────────────────────

func countCiphers(ciphers []probe.CipherInfo) (strong, acceptable, weak, insecure int) {
	for _, c := range ciphers {
		switch c.Strength {
		case "strong":
			strong++
		case "acceptable":
			acceptable++
		case "weak":
			weak++
		case "insecure":
			insecure++
		}
	}
	return
}

func cipherBar(count, total int, color string) string {
	if total == 0 {
		return ""
	}
	width := 20
	filled := (count * width) / total
	if count > 0 && filled == 0 {
		filled = 1
	}
	bar := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
	return color + bar + reset
}

func warnCount(count int) string {
	if count > 0 {
		return "  " + red + "⚠" + reset
	}
	return ""
}

func extractCN(dn string) string {
	for _, part := range strings.Split(dn, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "CN=") {
			return strings.TrimPrefix(part, "CN=")
		}
	}
	return dn
}

func extractCNOrOrg(dn string) string {
	cn := ""
	org := ""
	for _, part := range strings.Split(dn, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "CN=") && cn == "" {
			cn = strings.TrimPrefix(part, "CN=")
		}
		if strings.HasPrefix(part, "O=") && org == "" {
			org = strings.TrimPrefix(part, "O=")
		}
	}
	if cn != "" {
		return cn
	}
	if org != "" {
		return org
	}
	return dn
}

func certTypeDisplay(certType string) string {
	switch certType {
	case "EV":
		return "EV (Extended Validation)"
	case "OV":
		return "OV (Organization Validated)"
	default:
		return "DV (Domain Validated)"
	}
}

func formatDate(rfc3339 string) string {
	if len(rfc3339) >= 10 {
		return rfc3339[:10]
	}
	return rfc3339
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

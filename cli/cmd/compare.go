package cmd

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/yokedotlol/certs-lol/cli/output"
)

// RunCompare scans two targets and shows a side-by-side comparison.
func RunCompare(w io.Writer, targets []string, opts ScanOptions) int {
	if len(targets) < 2 {
		fmt.Fprintf(os.Stderr, "error: compare requires exactly 2 targets\n")
		return 2
	}

	a := scanTarget(targets[0], opts)
	b := scanTarget(targets[1], opts)

	if opts.JSON || !isTerminal() {
		_ = output.JSON(w, targets[0], a.Probe, a.Enrich, nil, opts.Version)
		_ = output.JSON(w, targets[1], b.Probe, b.Enrich, nil, opts.Version)
		return 0
	}

	// Pretty comparison
	fmt.Fprintf(w, "\n  %sCompare%s\n", "\033[36m", "\033[0m")
	fmt.Fprintf(w, "  %s\n\n", strings.Repeat("─", 60))

	// Grades
	gradeA := gradeColor(a.Probe.Grade)
	gradeB := gradeColor(b.Probe.Grade)
	fmt.Fprintf(w, "  %-30s  %s%-4s%s  vs  %s%-4s%s\n",
		"Grade",
		"\033[1m"+gradeA, a.Probe.Grade, "\033[0m",
		"\033[1m"+gradeB, b.Probe.Grade, "\033[0m")

	// Comparison rows
	compareLine(w, "Subject", extractCNFromDN(a.Probe.Subject), extractCNFromDN(b.Probe.Subject))
	compareLine(w, "Issuer", extractCNFromDN(a.Probe.Issuer), extractCNFromDN(b.Probe.Issuer))
	compareLine(w, "Key", fmt.Sprintf("%s %d-bit", a.Probe.KeyAlg, a.Probe.KeySize), fmt.Sprintf("%s %d-bit", b.Probe.KeyAlg, b.Probe.KeySize))
	compareLine(w, "Cert Type", a.Probe.CertType, b.Probe.CertType)
	compareLine(w, "Days Remaining", fmt.Sprintf("%d", a.Probe.DaysRemaining), fmt.Sprintf("%d", b.Probe.DaysRemaining))
	compareLine(w, "Chain Valid", fmt.Sprintf("%v", a.Probe.ChainValid), fmt.Sprintf("%v", b.Probe.ChainValid))
	compareLine(w, "Protocols", strings.Join(a.Probe.Protocols, ", "), strings.Join(b.Probe.Protocols, ", "))
	compareLine(w, "Ciphers", fmt.Sprintf("%d total", len(a.Probe.Ciphers)), fmt.Sprintf("%d total", len(b.Probe.Ciphers)))
	compareLine(w, "Forward Secrecy", fmt.Sprintf("%v", a.Probe.ForwardSecrecy), fmt.Sprintf("%v", b.Probe.ForwardSecrecy))
	compareLine(w, "OCSP Stapling", fmt.Sprintf("%v", a.Probe.OCSPStapling), fmt.Sprintf("%v", b.Probe.OCSPStapling))
	compareLine(w, "Must-Staple", fmt.Sprintf("%v", a.Probe.OCSPMustStaple), fmt.Sprintf("%v", b.Probe.OCSPMustStaple))
	compareLine(w, "SCTs", fmt.Sprintf("%d", a.Probe.SCTCount), fmt.Sprintf("%d", b.Probe.SCTCount))

	if a.Enrich != nil && b.Enrich != nil {
		compareLine(w, "HSTS", fmt.Sprintf("%v", a.Enrich.HSTS.Enabled), fmt.Sprintf("%v", b.Enrich.HSTS.Enabled))
		compareLine(w, "DNSSEC", fmt.Sprintf("%v", a.Enrich.DNSSecurity.DNSSEC), fmt.Sprintf("%v", b.Enrich.DNSSecurity.DNSSEC))
		compareLine(w, "HTTP/3", fmt.Sprintf("%v", a.Enrich.HTTP3.Supported), fmt.Sprintf("%v", b.Enrich.HTTP3.Supported))
	}

	compareLine(w, "Probe Time", fmt.Sprintf("%dms", a.Probe.ProbeMs), fmt.Sprintf("%dms", b.Probe.ProbeMs))

	fmt.Fprintln(w)
	return 0
}

func compareLine(w io.Writer, label, valA, valB string) {
	diff := ""
	if valA != valB {
		diff = "  ≠"
	}
	fmt.Fprintf(w, "  %-30s  %-24s  %-24s%s\n", label, truncate(valA, 24), truncate(valB, 24), diff)
}

func truncate(s string, maxLen int) string {
	if len(s) > maxLen {
		return s[:maxLen-3] + "..."
	}
	return s
}

func extractCNFromDN(dn string) string {
	for _, part := range strings.Split(dn, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "CN=") {
			return strings.TrimPrefix(part, "CN=")
		}
	}
	return dn
}

func gradeColor(grade string) string {
	switch {
	case grade == "A+" || grade == "A":
		return "\033[32m"
	case grade == "B":
		return "\033[33m"
	default:
		return "\033[31m"
	}
}

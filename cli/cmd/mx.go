package cmd

import (
	"fmt"
	"io"
	"net"
	"sort"
	"strings"

	"github.com/yokedotlol/certs-lol/cli/assert"
	"github.com/yokedotlol/certs-lol/cli/output"
	"github.com/yokedotlol/certs-lol/probe"
)

// RunMXScan resolves MX records for each domain and scans every mail server.
func RunMXScan(w io.Writer, domains []string, opts ScanOptions) int {
	exitCode := 0

	for _, domain := range domains {
		mxRecords, err := net.LookupMX(domain)
		if err != nil {
			fmt.Fprintf(w, "\n  %sError resolving MX for %s: %v%s\n\n", "\033[31m", domain, err, "\033[0m")
			exitCode = maxCode(exitCode, 3)
			continue
		}

		if len(mxRecords) == 0 {
			fmt.Fprintf(w, "\n  %sNo MX records found for %s%s\n\n", "\033[31m", domain, "\033[0m")
			exitCode = maxCode(exitCode, 3)
			continue
		}

		// Sort by preference
		sort.Slice(mxRecords, func(i, j int) bool {
			return mxRecords[i].Pref < mxRecords[j].Pref
		})

		if isTerminal() && !opts.JSON && !opts.GradeOnly {
			fmt.Fprintf(w, "\n  %sMX records for %s:%s\n", "\033[36m", domain, "\033[0m")
			for _, mx := range mxRecords {
				host := strings.TrimSuffix(mx.Host, ".")
				fmt.Fprintf(w, "    %d  %s\n", mx.Pref, host)
			}
			fmt.Fprintln(w)
		}

		// Override port to 25 if still at default 443
		mxOpts := opts
		if mxOpts.Port == 443 {
			mxOpts.Port = 25
		}
		// Force SMTP STARTTLS for standard mail ports
		if mxOpts.StartTLSProto == "" {
			mxOpts.StartTLSProto = probe.DetectProtocol(mxOpts.Port)
			if mxOpts.StartTLSProto == "" {
				mxOpts.StartTLSProto = "smtp"
			}
		}

		for _, mx := range mxRecords {
			host := strings.TrimSuffix(mx.Host, ".")
			result := scanTarget(host, mxOpts)
			result.Probe.MXHost = host
			result.Probe.MXPriority = int(mx.Pref)

			// If port 25 failed with a connection error, try 587 fallback
			if result.Probe.Error != nil && mxOpts.Port == 25 && isPort25Blocked(*result.Probe.Error) {
				if isTerminal() && !mxOpts.JSON && !mxOpts.GradeOnly {
					fmt.Fprintf(w, "  %s⚠ Port 25 appears blocked (%s) — trying port 587%s\n",
						"\033[33m", summarizeConnError(*result.Probe.Error), "\033[0m")
				}

				fallbackOpts := mxOpts
				fallbackOpts.Port = 587
				fallbackOpts.StartTLSProto = "smtp"
				fallbackResult := scanTarget(host, fallbackOpts)
				fallbackResult.Probe.MXHost = host
				fallbackResult.Probe.MXPriority = int(mx.Pref)

				if fallbackResult.Probe.Error == nil {
					result = fallbackResult
					result.Probe.FallbackPort = 587
					if isTerminal() && !mxOpts.JSON && !mxOpts.GradeOnly {
						fmt.Fprintf(w, "  %s✓ Connected via port 587 (submission)%s\n\n",
							"\033[32m", "\033[0m")
					}
				} else {
					// Both failed — show hint
					if isTerminal() && !mxOpts.JSON && !mxOpts.GradeOnly {
						fmt.Fprintf(w, "  %s✗ Port 587 also failed%s\n", "\033[31m", "\033[0m")
						fmt.Fprintf(w, "  %sHint: Port 25 is blocked by most ISPs and cloud providers.%s\n",
							"\033[33m", "\033[0m")
						fmt.Fprintf(w, "  %sTry: certs %s --port 587 --starttls smtp%s\n\n",
							"\033[33m", host, "\033[0m")
					}
				}
			}

			if result.Probe.Error != nil {
				exitCode = maxCode(exitCode, 3)
			}

			// Run assertions if configured
			if len(mxOpts.Assertions) > 0 && result.Probe.Error == nil {
				data := assert.ScanData{Probe: result.Probe, Enrich: result.Enrich}
				result.Assertions = assert.Evaluate(data, mxOpts.Assertions)
				if !result.Assertions.Passed {
					exitCode = maxCode(exitCode, 1)
				}
			}

			displayPort := mxOpts.Port
			if result.Probe.FallbackPort > 0 {
				displayPort = result.Probe.FallbackPort
			}
			label := fmt.Sprintf("%s:%d", host, displayPort)

			if mxOpts.GradeOnly {
				output.GradeOnly(w, label, result.Probe.Grade)
			} else if mxOpts.JSON || !isTerminal() {
				_ = output.JSON(w, label, result.Probe, result.Enrich, result.Assertions, mxOpts.Version)
			} else if result.Assertions != nil {
				output.CI(w, label, result.Probe.Grade, result.Probe.ProbeMs, result.Assertions)
			} else {
				output.Pretty(w, label, result.Probe, result.Enrich)
			}
		}
	}

	return exitCode
}

// isPort25Blocked returns true if the error looks like an outbound port 25 block
// (connection timeout, refused, or network unreachable — not a TLS/protocol error).
func isPort25Blocked(errStr string) bool {
	lower := strings.ToLower(errStr)
	return strings.Contains(lower, "i/o timeout") ||
		strings.Contains(lower, "connection refused") ||
		strings.Contains(lower, "connection timed out") ||
		strings.Contains(lower, "network is unreachable") ||
		strings.Contains(lower, "no route to host") ||
		strings.Contains(lower, "operation timed out") ||
		strings.Contains(lower, "context deadline exceeded")
}

// summarizeConnError returns a short human-readable label for the connection error.
func summarizeConnError(errStr string) string {
	lower := strings.ToLower(errStr)
	if strings.Contains(lower, "refused") {
		return "refused"
	}
	if strings.Contains(lower, "unreachable") || strings.Contains(lower, "no route") {
		return "unreachable"
	}
	if strings.Contains(lower, "timeout") || strings.Contains(lower, "timed out") || strings.Contains(lower, "deadline") {
		return "timeout"
	}
	return "connection failed"
}

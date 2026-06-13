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

			label := fmt.Sprintf("%s:%d", host, mxOpts.Port)

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

// Package cmd provides the scan orchestration logic.
package cmd

import (
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/yokedotlol/certs-lol/cli/assert"
	"github.com/yokedotlol/certs-lol/cli/output"
	"github.com/yokedotlol/certs-lol/enrich"
	"github.com/yokedotlol/certs-lol/probe"
)

// ScanOptions configures a scan.
type ScanOptions struct {
	Port          int
	Timeout       time.Duration
	StartTLSProto string
	ProbeOnly     bool
	NoPrivate     bool
	Assertions    []assert.Assertion
	JSON          bool
	Table         bool
	GradeOnly     bool
	Verbose       bool
	Version       string
}

// ScanResult holds all results for a single target.
type ScanResult struct {
	Target     string
	Probe      probe.SSLResult
	Enrich     *enrich.Result
	Assertions *assert.Results
}

// RunScan scans one or more targets and writes output. Returns the exit code.
func RunScan(w io.Writer, targets []string, opts ScanOptions) int {
	exitCode := 0

	for i, target := range targets {
		result := scanTarget(target, opts)

		if result.Probe.Error != nil {
			exitCode = maxCode(exitCode, 3)
		}

		// Run assertions
		if len(opts.Assertions) > 0 && result.Probe.Error == nil {
			data := assert.ScanData{Probe: result.Probe, Enrich: result.Enrich}
			result.Assertions = assert.Evaluate(data, opts.Assertions)
			if !result.Assertions.Passed {
				exitCode = maxCode(exitCode, 1)
			}
		}

		// Output
		if opts.GradeOnly {
			output.GradeOnly(w, target, result.Probe.Grade)
		} else if opts.JSON || !isTerminal() {
			if err := output.JSON(w, target, result.Probe, result.Enrich, result.Assertions, opts.Version); err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
			}
		} else if result.Assertions != nil {
			output.CI(w, target, result.Probe.Grade, result.Probe.ProbeMs, result.Assertions)
		} else {
			output.Pretty(w, target, result.Probe, result.Enrich)
		}

		// Separator between multiple targets in pretty mode
		if i < len(targets)-1 && !opts.JSON && !opts.GradeOnly && isTerminal() {
			fmt.Fprintf(w, "  %s\n", strings.Repeat("─", 60))
		}
	}

	return exitCode
}

func scanTarget(target string, opts ScanOptions) ScanResult {
	probeOpts := probe.CLIOptions()
	probeOpts.Port = opts.Port
	probeOpts.TimeoutSec = int(opts.Timeout.Seconds())
	probeOpts.StartTLSProto = opts.StartTLSProto
	if opts.NoPrivate {
		probeOpts.AllowPrivate = false
	}
	if opts.Verbose {
		probeOpts.Verbose = func(msg string) {
			fmt.Fprintf(os.Stderr, "%s\n", msg)
		}
	}

	// Auto-detect STARTTLS from port if not explicitly set
	if probeOpts.StartTLSProto == "" {
		probeOpts.StartTLSProto = probe.DetectProtocol(opts.Port)
	}

	result := probe.Scan(target, probeOpts)

	var enrichResult *enrich.Result
	if !opts.ProbeOnly && result.Error == nil && !isIP(target) {
		enrichOpts := enrich.DefaultOptions()
		enrichOpts.Port = opts.Port
		r := enrich.Enrich(target, enrichOpts)

		// Run compliance evaluation
		ciphersForCompliance := make([]enrich.CipherForCompliance, len(result.Ciphers))
		for i, c := range result.Ciphers {
			ciphersForCompliance[i] = enrich.CipherForCompliance{Name: c.Name, Strength: c.Strength}
		}
		r.Compliance = enrich.EvaluateCompliance(enrich.ComplianceInput{
			Protocols:      result.Protocols,
			Ciphers:        ciphersForCompliance,
			KeyAlg:         result.KeyAlg,
			KeySize:        result.KeySize,
			ForwardSecrecy: result.ForwardSecrecy,
			ChainValid:     result.ChainValid,
			DaysRemaining:  result.DaysRemaining,
			OCSPStapling:   result.OCSPStapling,
			HSTSEnabled:    r.HSTS.Enabled,
		})

		enrichResult = &r
	}

	return ScanResult{
		Target: target,
		Probe:  result,
		Enrich: enrichResult,
	}
}

func isIP(s string) bool {
	return net.ParseIP(s) != nil
}

func isTerminal() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func maxCode(a, b int) int {
	if a > b {
		return a
	}
	return b
}

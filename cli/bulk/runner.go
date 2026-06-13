// Package bulk provides concurrent multi-target scanning.
package bulk

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yokedotlol/certs-lol/cli/assert"
	"github.com/yokedotlol/certs-lol/cli/output"
	"github.com/yokedotlol/certs-lol/enrich"
	"github.com/yokedotlol/certs-lol/probe"
)

// ScanFunc performs a single-target scan. Provided by the cmd package to
// avoid a circular import.
type ScanFunc func(target string) (probe.SSLResult, *enrich.Result)

// Options for bulk scanning.
type Options struct {
	Workers    int
	OutDir     string
	Quiet      bool
	Assertions []assert.Assertion
	Version    string
	Profile    string
}

// Summary is the bulk scan summary written to _summary.json.
type Summary struct {
	Total      int              `json:"total"`
	Passed     int              `json:"passed"`
	Failed     int              `json:"failed"`
	Errors     int              `json:"errors"`
	Profile    string           `json:"profile,omitempty"`
	Assertions []string         `json:"assertions,omitempty"`
	Failures   []FailureSummary `json:"failures,omitempty"`
	DurationMs int64            `json:"duration_ms"`
}

// FailureSummary describes a single target failure.
type FailureSummary struct {
	Target           string   `json:"target"`
	FailedAssertions []string `json:"failed_assertions,omitempty"`
	Grade            string   `json:"grade"`
	Error            *string  `json:"error,omitempty"`
}

// Run executes a bulk scan of all targets.
func Run(w io.Writer, targets []string, scanFn ScanFunc, opts Options) int {
	start := time.Now()

	if opts.Workers <= 0 {
		opts.Workers = 10
	}

	// Create output directory
	if opts.OutDir != "" {
		if err := os.MkdirAll(opts.OutDir, 0755); err != nil {
			fmt.Fprintf(os.Stderr, "error: cannot create output dir: %v\n", err)
			return 2
		}
	}

	type result struct {
		target     string
		probe      probe.SSLResult
		enrich     *enrich.Result
		assertions *assert.Results
	}

	results := make([]result, len(targets))
	var completed int64
	total := int64(len(targets))

	// Progress display
	var progressDone chan struct{}
	if !opts.Quiet && isTerminal() {
		progressDone = make(chan struct{})
		go func() {
			defer close(progressDone)
			for {
				c := atomic.LoadInt64(&completed)
				fmt.Fprintf(os.Stderr, "\r  Scanning... %d/%d", c, total)
				if c >= total {
					fmt.Fprintf(os.Stderr, "\r  Scanning... %d/%d ✓\n", total, total)
					return
				}
				time.Sleep(200 * time.Millisecond)
			}
		}()
	}

	// Worker pool
	work := make(chan int, len(targets))
	for i := range targets {
		work <- i
	}
	close(work)

	var wg sync.WaitGroup
	for n := 0; n < opts.Workers; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range work {
				target := targets[idx]
				probeResult, enrichResult := scanFn(target)

				var assertResults *assert.Results
				if len(opts.Assertions) > 0 && probeResult.Error == nil {
					data := assert.ScanData{Probe: probeResult, Enrich: enrichResult}
					assertResults = assert.Evaluate(data, opts.Assertions)
				}

				results[idx] = result{
					target:     target,
					probe:      probeResult,
					enrich:     enrichResult,
					assertions: assertResults,
				}

				// Write individual result file
				if opts.OutDir != "" {
					writeResultFile(opts.OutDir, target, probeResult, enrichResult, assertResults, opts.Version)
				}

				atomic.AddInt64(&completed, 1)
			}
		}()
	}

	wg.Wait()

	if progressDone != nil {
		<-progressDone
	}

	// Build summary
	summary := Summary{
		Total:      len(targets),
		Profile:    opts.Profile,
		DurationMs: time.Since(start).Milliseconds(),
	}

	for _, a := range opts.Assertions {
		summary.Assertions = append(summary.Assertions, a.Raw)
	}

	exitCode := 0
	for _, r := range results {
		if r.probe.Error != nil {
			summary.Errors++
			summary.Failures = append(summary.Failures, FailureSummary{
				Target: r.target,
				Grade:  r.probe.Grade,
				Error:  r.probe.Error,
			})
			exitCode = maxCode(exitCode, 3)
			continue
		}

		if r.assertions != nil && !r.assertions.Passed {
			summary.Failed++
			var failedRules []string
			for _, a := range r.assertions.Items {
				if !a.Passed {
					rule := a.Rule
					if a.Args != "" {
						rule += " " + a.Args
					}
					failedRules = append(failedRules, rule)
				}
			}
			summary.Failures = append(summary.Failures, FailureSummary{
				Target:           r.target,
				FailedAssertions: failedRules,
				Grade:            r.probe.Grade,
			})
			exitCode = maxCode(exitCode, 1)
		} else {
			summary.Passed++
		}
	}

	// Write summary file
	if opts.OutDir != "" {
		writeSummaryFile(opts.OutDir, summary)
	}

	// Print summary to terminal
	if isTerminal() && !opts.Quiet {
		fmt.Fprintf(w, "\n  %sBulk Scan Summary%s\n", "\033[36m", "\033[0m")
		fmt.Fprintf(w, "  Total: %d  Passed: %s%d%s  Failed: %s%d%s  Errors: %d  Duration: %dms\n",
			summary.Total,
			"\033[32m", summary.Passed, "\033[0m",
			"\033[31m", summary.Failed, "\033[0m",
			summary.Errors,
			summary.DurationMs)

		if len(summary.Failures) > 0 {
			fmt.Fprintf(w, "\n  %sFailures:%s\n", "\033[31m", "\033[0m")
			for _, f := range summary.Failures {
				if f.Error != nil {
					fmt.Fprintf(w, "    %s — error: %s\n", f.Target, *f.Error)
				} else {
					fmt.Fprintf(w, "    %s (grade %s) — %s\n", f.Target, f.Grade,
						joinStrings(f.FailedAssertions, ", "))
				}
			}
		}
		fmt.Fprintln(w)
	}

	return exitCode
}

func writeResultFile(outDir, target string, probeResult probe.SSLResult, enrichResult *enrich.Result, assertions *assert.Results, version string) {
	// Sanitize filename
	safe := sanitizeFilename(target)
	path := filepath.Join(outDir, safe+".json")

	f, err := os.Create(path)
	if err != nil {
		return
	}
	defer f.Close()

	_ = output.JSON(f, target, probeResult, enrichResult, assertions, version)
}

func writeSummaryFile(outDir string, summary Summary) {
	path := filepath.Join(outDir, "_summary.json")
	f, err := os.Create(path)
	if err != nil {
		return
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	_ = enc.Encode(summary)
}

func sanitizeFilename(s string) string {
	result := make([]byte, 0, len(s))
	for _, c := range []byte(s) {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '-', c == '_':
			result = append(result, c)
		default:
			result = append(result, '_')
		}
	}
	return string(result)
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

func joinStrings(ss []string, sep string) string {
	if len(ss) == 0 {
		return ""
	}
	result := ss[0]
	for _, s := range ss[1:] {
		result += sep + s
	}
	return result
}

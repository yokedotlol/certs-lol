package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/yokedotlol/certs-lol/cli/assert"
)

// CI writes the assertion pass/fail report for CI mode.
func CI(w io.Writer, target string, grade string, probeMs int, results *assert.Results) {
	gradeC := gradeColor(grade)
	fmt.Fprintf(w, "\n  %s%-50s%s  %s%s%s    %dms\n\n",
		bold, target, reset,
		bold+gradeC, grade, reset,
		probeMs)

	if results == nil || len(results.Items) == 0 {
		fmt.Fprintf(w, "  No assertions to evaluate.\n\n")
		return
	}

	fmt.Fprintf(w, "  %sAssertions%s%s%d passed, %d failed%s\n\n",
		cyan, reset,
		strings.Repeat(" ", 30),
		results.PassCount, results.FailCount, "")

	for _, r := range results.Items {
		mark := green + "✓" + reset
		if !r.Passed {
			mark = red + "✗" + reset
		}

		ruleDisplay := r.Rule
		if r.Args != "" {
			ruleDisplay += " " + r.Args
		}

		fmt.Fprintf(w, "  %s  %-22s %s\n", mark, ruleDisplay, r.Actual)

		if !r.Passed {
			fmt.Fprintf(w, "     %s%-22s expected: %s%s\n", dim, "", r.Expected, reset)
		}
	}

	fmt.Fprintln(w)
	if results.Passed {
		fmt.Fprintf(w, "  %sPASSED%s — all %d assertions passed\n\n", green+bold, reset, results.Total)
	} else {
		fmt.Fprintf(w, "  %sFAILED%s — %d assertion(s) failed\n\n", red+bold, reset, results.FailCount)
	}
}

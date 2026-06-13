package assert

import (
	"strings"

	"github.com/yokedotlol/certs-lol/enrich"
	"github.com/yokedotlol/certs-lol/probe"
)

// ScanData bundles probe and enrichment results for assertion evaluation.
type ScanData struct {
	Probe  probe.SSLResult
	Enrich *enrich.Result // nil when --probe-only
}

// AssertResult is the outcome of evaluating one assertion.
type AssertResult struct {
	Rule     string `json:"rule"`
	Args     string `json:"args"`
	Passed   bool   `json:"passed"`
	Expected string `json:"expected"`
	Actual   string `json:"actual"`
}

// Results is the aggregate outcome of all assertions.
type Results struct {
	Passed    bool           `json:"passed"`
	Total     int            `json:"total"`
	PassCount int            `json:"pass_count"`
	FailCount int            `json:"fail_count"`
	Items     []AssertResult `json:"results"`
}

// Evaluate runs all assertions against the scan data.
func Evaluate(data ScanData, assertions []Assertion) *Results {
	results := &Results{
		Passed: true,
		Total:  len(assertions),
		Items:  make([]AssertResult, 0, len(assertions)),
	}

	for _, a := range assertions {
		def, ok := RuleRegistry[a.Rule]
		if !ok {
			r := AssertResult{
				Rule:     a.Rule,
				Args:     strings.Join(a.Args, " "),
				Passed:   false,
				Expected: "valid rule",
				Actual:   "unknown rule: " + a.Rule,
			}
			results.Items = append(results.Items, r)
			results.FailCount++
			results.Passed = false
			continue
		}

		// Check enrichment requirement
		if def.NeedsEnrich && data.Enrich == nil {
			r := AssertResult{
				Rule:     a.Rule,
				Args:     strings.Join(a.Args, " "),
				Passed:   false,
				Expected: def.Description,
				Actual:   "assertion requires enrichment data; remove --probe-only or drop this assertion",
			}
			results.Items = append(results.Items, r)
			results.FailCount++
			results.Passed = false
			continue
		}

		r := def.Eval(data, a.Args)
		r.Rule = a.Rule
		r.Args = strings.Join(a.Args, " ")
		results.Items = append(results.Items, r)

		if r.Passed {
			results.PassCount++
		} else {
			results.FailCount++
			results.Passed = false
		}
	}

	return results
}

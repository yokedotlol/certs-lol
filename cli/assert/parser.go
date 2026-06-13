// Package assert provides the assertion engine for CI/CD gating.
package assert

import (
	"fmt"
	"strings"
)

// Assertion is a parsed assertion ready for evaluation.
type Assertion struct {
	Rule string   // e.g., "min-grade"
	Args []string // e.g., ["A"]
	Raw  string   // original string
}

// Parse parses a single assertion string like "min-grade A".
func Parse(raw string) (Assertion, error) {
	parts := strings.Fields(strings.TrimSpace(raw))
	if len(parts) == 0 {
		return Assertion{}, fmt.Errorf("empty assertion")
	}

	rule := parts[0]
	args := parts[1:]

	if _, ok := RuleRegistry[rule]; !ok {
		return Assertion{}, fmt.Errorf("unknown assertion rule: %q (run 'certs list-rules' to see available rules)", rule)
	}

	return Assertion{Rule: rule, Args: args, Raw: raw}, nil
}

// ParseAll parses multiple assertion strings.
func ParseAll(raws []string) ([]Assertion, error) {
	var result []Assertion
	for _, raw := range raws {
		a, err := Parse(raw)
		if err != nil {
			return nil, err
		}
		result = append(result, a)
	}
	return result, nil
}

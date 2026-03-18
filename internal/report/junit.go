package report

import (
	"encoding/xml"
	"fmt"
	"os"
	"time"

	"github.com/cameron/agent-harden/internal/optimizer"
	"github.com/cameron/agent-harden/internal/scorer"
)

// JUnit XML structures
type testSuites struct {
	XMLName    xml.Name     `xml:"testsuites"`
	Name       string       `xml:"name,attr"`
	Tests      int          `xml:"tests,attr"`
	Failures   int          `xml:"failures,attr"`
	Time       string       `xml:"time,attr"`
	TestSuites []testSuite  `xml:"testsuite"`
}

type testSuite struct {
	XMLName   xml.Name   `xml:"testsuite"`
	Name      string     `xml:"name,attr"`
	Tests     int        `xml:"tests,attr"`
	Failures  int        `xml:"failures,attr"`
	Timestamp string     `xml:"timestamp,attr"`
	TestCases []testCase `xml:"testcase"`
}

type testCase struct {
	XMLName   xml.Name    `xml:"testcase"`
	Name      string      `xml:"name,attr"`
	Classname string      `xml:"classname,attr"`
	Time      string      `xml:"time,attr"`
	Failure   *failure    `xml:"failure,omitempty"`
	SystemOut string      `xml:"system-out,omitempty"`
}

type failure struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Text    string `xml:",chardata"`
}

// WriteJUnit writes a JUnit XML report to the given path.
func WriteJUnit(path string, result *optimizer.Result, targetName string, elapsed time.Duration) error {
	suitesByCategory := make(map[string]*testSuite)

	allFindings := append(result.Violations, append(result.Maybes, result.Clean...)...) //nolint:gocritic

	for _, f := range allFindings {
		cat := string(f.Result.Attack.Category)
		if _, ok := suitesByCategory[cat]; !ok {
			suitesByCategory[cat] = &testSuite{
				Name:      fmt.Sprintf("agent-harden/%s", cat),
				Timestamp: time.Now().Format(time.RFC3339),
			}
		}
		suite := suitesByCategory[cat]
		suite.Tests++

		tc := testCase{
			Name:      fmt.Sprintf("[%s] %s", f.Result.Attack.Severity, truncate(f.Result.Attack.Text, 80)),
			Classname: fmt.Sprintf("agent-harden.%s.%s", cat, f.Result.Attack.ID),
			Time:      fmt.Sprintf("%.3f", float64(f.Result.Attack.RunCount)/1000.0),
			SystemOut: buildSystemOut(f),
		}

		if f.Score.Tier == scorer.TierViolation {
			suite.Failures++
			tc.Failure = &failure{
				Message: fmt.Sprintf("Policy violation (score=%.3f): %s", f.Score.Value, f.Score.Reason),
				Type:    "PolicyViolation",
				Text:    buildFailureText(f),
			}
		}

		suite.TestCases = append(suite.TestCases, tc)
	}

	// Build sorted suites
	suites := testSuites{
		Name:      fmt.Sprintf("agent-harden: %s", targetName),
		Time:      fmt.Sprintf("%.3f", elapsed.Seconds()),
	}
	for _, s := range suitesByCategory {
		suites.Tests += s.Tests
		suites.Failures += s.Failures
		suites.TestSuites = append(suites.TestSuites, *s)
	}

	out, err := xml.MarshalIndent(suites, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling JUnit XML: %w", err)
	}

	content := append([]byte(xml.Header), out...)
	if err := os.WriteFile(path, content, 0644); err != nil {
		return fmt.Errorf("writing JUnit report to %s: %w", path, err)
	}
	return nil
}

func buildSystemOut(f optimizer.Finding) string {
	return fmt.Sprintf(
		"Attack ID: %s\nCategory: %s\nSeverity: %s\nScore: %.3f\nTier: %s\nReason: %s\n\nAttack:\n%s\n\nResponse:\n%s",
		f.Result.Attack.ID,
		f.Result.Attack.Category,
		f.Result.Attack.Severity,
		f.Score.Value,
		f.Score.Tier.String(),
		f.Score.Reason,
		f.Result.Attack.Text,
		truncate(f.Result.Response, 500),
	)
}

func buildFailureText(f optimizer.Finding) string {
	policies := ""
	if len(f.Score.ViolatedPolicies) > 0 {
		policies = "\nViolated Policies:\n"
		for _, p := range f.Score.ViolatedPolicies {
			policies += fmt.Sprintf("  - %s\n", p)
		}
	}
	return fmt.Sprintf(
		"Attack: %s\n\nScore: %.3f (source: %s)\nReason: %s%s\nResponse: %s",
		f.Result.Attack.Text,
		f.Score.Value,
		f.Score.Source,
		f.Score.Reason,
		policies,
		truncate(f.Result.Response, 300),
	)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

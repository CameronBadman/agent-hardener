package report

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/cameron/agent-harden/internal/optimizer"
	"github.com/cameron/agent-harden/internal/scorer"
)

// PrintSummary writes a human-readable run summary to w.
func PrintSummary(w io.Writer, result *optimizer.Result, targetName string, elapsed time.Duration) {
	total := len(result.Violations) + len(result.Maybes) + len(result.Clean)

	fmt.Fprintf(w, "\n%s\n", strings.Repeat("─", 60))
	fmt.Fprintf(w, "  agent-harden report: %s\n", targetName)
	fmt.Fprintf(w, "%s\n\n", strings.Repeat("─", 60))

	fmt.Fprintf(w, "  Total attacks run:  %d\n", total)
	fmt.Fprintf(w, "  Violations:         %d\n", len(result.Violations))
	fmt.Fprintf(w, "  Maybe (uncertain):  %d\n", len(result.Maybes))
	fmt.Fprintf(w, "  Clean:              %d\n", len(result.Clean))
	fmt.Fprintf(w, "  Errors:             %d\n", len(result.Errors))
	fmt.Fprintf(w, "  Duration:           %s\n\n", elapsed.Round(time.Millisecond))

	if len(result.Violations) > 0 {
		fmt.Fprintf(w, "VIOLATIONS\n%s\n", strings.Repeat("─", 60))
		printFindings(w, result.Violations, scorer.TierViolation)
	}

	if len(result.Maybes) > 0 {
		fmt.Fprintf(w, "\nUNCERTAIN\n%s\n", strings.Repeat("─", 60))
		printFindings(w, result.Maybes, scorer.TierMaybe)
	}

	if len(result.Errors) > 0 {
		fmt.Fprintf(w, "\nERRORS\n%s\n", strings.Repeat("─", 60))
		for _, e := range result.Errors {
			fmt.Fprintf(w, "  ! %s\n", e)
		}
	}

	fmt.Fprintf(w, "\n%s\n", strings.Repeat("─", 60))
	if len(result.Violations) > 0 {
		fmt.Fprintf(w, "  RESULT: FAIL (%d violations found)\n", len(result.Violations))
	} else {
		fmt.Fprintf(w, "  RESULT: PASS\n")
	}
	fmt.Fprintf(w, "%s\n\n", strings.Repeat("─", 60))
}

func printFindings(w io.Writer, findings []optimizer.Finding, tier scorer.Tier) {
	for _, f := range findings {
		atk := f.Result.Attack
		fmt.Fprintf(w, "  [%s/%s] %s (score=%.3f)\n",
			atk.Category,
			atk.Severity,
			atk.ID,
			f.Score.Value,
		)
		fmt.Fprintf(w, "    Attack: %s\n", truncate(atk.Text, 100))
		fmt.Fprintf(w, "    Reason: %s\n", f.Score.Reason)
		if len(f.Score.ViolatedPolicies) > 0 {
			fmt.Fprintf(w, "    Policies: %s\n", strings.Join(f.Score.ViolatedPolicies, ", "))
		}
		if tier == scorer.TierViolation && f.Result.Response != "" {
			fmt.Fprintf(w, "    Response: %s\n", truncate(f.Result.Response, 150))
		}
		fmt.Fprintln(w)
	}
}

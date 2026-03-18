package report

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/cameron/agent-harden/internal/optimizer"
	"github.com/cameron/agent-harden/internal/patcher"
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

// PrintPatchSuggestion writes the hardened prompt suggestion to w.
func PrintPatchSuggestion(w io.Writer, result *patcher.Result, outPath string) {
	fmt.Fprintf(w, "\n%s\n", strings.Repeat("─", 60))
	fmt.Fprintf(w, "  SUGGESTED SYSTEM PROMPT PATCH\n")
	fmt.Fprintf(w, "%s\n\n", strings.Repeat("─", 60))

	fmt.Fprintf(w, "  %s\n\n", result.Summary)

	fmt.Fprintf(w, "  Changes made:\n")
	for _, a := range result.Annotations {
		fmt.Fprintf(w, "  [%s] %s → %s\n", a.FindingID, a.Technique, a.Target)
		fmt.Fprintf(w, "    %s\n\n", a.Change)
	}

	fmt.Fprintf(w, "%s\n", strings.Repeat("─", 60))
	fmt.Fprintf(w, "  HARDENED SYSTEM PROMPT\n")
	fmt.Fprintf(w, "%s\n\n", strings.Repeat("─", 60))
	for _, line := range strings.Split(result.HardenedPrompt, "\n") {
		fmt.Fprintf(w, "  %s\n", line)
	}

	if outPath != "" {
		fmt.Fprintf(w, "\n%s\n", strings.Repeat("─", 60))
		fmt.Fprintf(w, "  Written to: %s\n", outPath)
		fmt.Fprintf(w, "  Review the changes and replace your config when ready.\n")
	} else {
		fmt.Fprintf(w, "\n  Run with --auto-patch to write a hardened config file.\n")
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
		fmt.Fprintf(w, "    Attack:    %s\n", truncate(atk.Text, 100))
		fmt.Fprintf(w, "    Technique: %s → %s\n", atk.Technique, atk.Target)
		fmt.Fprintf(w, "    Reason:    %s\n", f.Score.Reason)
		if len(f.Score.ViolatedPolicies) > 0 {
			fmt.Fprintf(w, "    Policies:  %s\n", strings.Join(f.Score.ViolatedPolicies, ", "))
		}
		if tier == scorer.TierViolation && f.Result.Response != "" {
			fmt.Fprintf(w, "    Response:  %s\n", truncate(f.Result.Response, 150))
		}
		fmt.Fprintln(w)
	}
}

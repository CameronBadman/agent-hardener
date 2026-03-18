package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/cameron/agent-harden/cli"
)

func main() {
	root := &cobra.Command{
		Use:   "agent-harden",
		Short: "Red-team your LLM agent before deployment",
		Long: `agent-harden is a CI/CD tool that fires adversarial prompts at LLM agents,
scores responses for policy violations, and evolves effective attack vectors
using LLM-assisted mutation. Integrates with GitLab CI via JUnit XML reports.`,
		SilenceUsage: true,
	}

	root.AddCommand(
		cli.NewRunCmd(),
		cli.NewAddAttackCmd(),
		cli.NewReportCmd(),
		cli.NewDBCmd(),
	)

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

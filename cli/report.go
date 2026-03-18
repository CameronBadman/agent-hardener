package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func NewReportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "report",
		Short: "Report commands",
	}

	cmd.AddCommand(newReportViewCmd())
	return cmd
}

func newReportViewCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "view [junit-file]",
		Short: "View a JUnit XML report",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("Use 'cat %s' or open in a JUnit-compatible viewer.\n", args[0])
			fmt.Println("GitLab CI automatically renders JUnit reports in the pipeline test report UI.")
			return nil
		},
	}
}

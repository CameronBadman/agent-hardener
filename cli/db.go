package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/cameron/agent-harden/internal/attack"
	"github.com/cameron/agent-harden/internal/config"
)

// note: buildEmbedFunc is defined in run.go (same package)

func NewDBCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "db",
		Short: "Manage the attack prompt database",
	}

	cmd.AddCommand(newDBSeedCmd())
	cmd.AddCommand(newDBListCmd())
	cmd.AddCommand(newDBStatsCmd())

	return cmd
}

func newDBSeedCmd() *cobra.Command {
	var configPath string

	cmd := &cobra.Command{
		Use:   "seed",
		Short: "Load seed corpus into the database",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(configPath)
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}

			ctx := context.Background()
			embedFunc := buildEmbedFunc(cfg)
			store, err := attack.NewChromemStore(cfg.Database.Path, embedFunc)
			if err != nil {
				return fmt.Errorf("opening store: %w", err)
			}

			n, err := attack.SeedStore(ctx, store)
			if err != nil {
				return fmt.Errorf("seeding: %w", err)
			}
			fmt.Fprintf(os.Stdout, "Seeded %d attacks into %s\n", n, cfg.Database.Path)
			return nil
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", "agent-harden.yaml", "Path to config file")
	return cmd
}

func newDBListCmd() *cobra.Command {
	var (
		configPath string
		category   string
		limit      int
	)

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List attacks in the database",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(configPath)
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}

			ctx := context.Background()
			embedFunc := buildEmbedFunc(cfg)
			store, err := attack.NewChromemStore(cfg.Database.Path, embedFunc)
			if err != nil {
				return fmt.Errorf("opening store: %w", err)
			}

			attacks, err := store.Query(ctx, category, limit)
			if err != nil {
				return fmt.Errorf("querying store: %w", err)
			}

			for _, a := range attacks {
				fmt.Fprintf(os.Stdout, "%-20s %-12s %-8s gen=%-2d score=%.3f  %s\n",
					a.ID, a.Category, a.Severity, a.Generation, a.BestScore, truncateStr(a.Text, 60))
			}
			fmt.Fprintf(os.Stdout, "\n%d attacks\n", len(attacks))
			return nil
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", "agent-harden.yaml", "Path to config file")
	cmd.Flags().StringVar(&category, "category", "", "Filter by category")
	cmd.Flags().IntVar(&limit, "limit", 100, "Max results")
	return cmd
}

func newDBStatsCmd() *cobra.Command {
	var configPath string

	cmd := &cobra.Command{
		Use:   "stats",
		Short: "Show database statistics",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(configPath)
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}

			ctx := context.Background()
			embedFunc := buildEmbedFunc(cfg)
			store, err := attack.NewChromemStore(cfg.Database.Path, embedFunc)
			if err != nil {
				return fmt.Errorf("opening store: %w", err)
			}

			total, err := store.Count(ctx)
			if err != nil {
				return fmt.Errorf("counting: %w", err)
			}
			fmt.Fprintf(os.Stdout, "Database: %s\nTotal attacks: %d\n", cfg.Database.Path, total)
			return nil
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", "agent-harden.yaml", "Path to config file")
	return cmd
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

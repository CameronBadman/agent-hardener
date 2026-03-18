package cli

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/cameron/agent-harden/internal/attack"
	"github.com/cameron/agent-harden/internal/config"
)

func NewAddAttackCmd() *cobra.Command {
	var (
		configPath string
		id         string
		text       string
		category   string
		severity   string
		tags       []string
	)

	cmd := &cobra.Command{
		Use:   "add-attack",
		Short: "Add a custom attack prompt to the database",
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

			if id == "" {
				id = fmt.Sprintf("custom-%d", time.Now().UnixMilli())
			}

			atk := attack.AttackPrompt{
				ID:        id,
				Text:      text,
				Category:  attack.CategoryFromString(category),
				Severity:  severity,
				Tags:      tags,
				CreatedAt: time.Now(),
			}

			if err := store.Add(ctx, []attack.AttackPrompt{atk}); err != nil {
				return fmt.Errorf("adding attack: %w", err)
			}

			fmt.Fprintf(os.Stdout, "Added attack %s to database\n", id)
			return nil
		},
	}

	cmd.Flags().StringVarP(&configPath, "config", "c", "agent-harden.yaml", "Path to config file")
	cmd.Flags().StringVar(&id, "id", "", "Attack ID (auto-generated if omitted)")
	cmd.Flags().StringVarP(&text, "text", "t", "", "Attack prompt text (required)")
	cmd.Flags().StringVar(&category, "category", "injection", "Attack category")
	cmd.Flags().StringVar(&severity, "severity", "medium", "Attack severity (low, medium, high, critical)")
	cmd.Flags().StringSliceVar(&tags, "tags", nil, "Comma-separated tags")

	_ = cmd.MarkFlagRequired("text")
	return cmd
}

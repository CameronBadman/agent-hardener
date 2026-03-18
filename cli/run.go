package cli

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/cameron/agent-harden/internal/attack"
	"github.com/cameron/agent-harden/internal/config"
	"github.com/cameron/agent-harden/internal/mutator"
	"github.com/cameron/agent-harden/internal/optimizer"
	"github.com/cameron/agent-harden/internal/report"
	"github.com/cameron/agent-harden/internal/runner"
	"github.com/cameron/agent-harden/internal/scorer"

	chromem "github.com/philippgille/chromem-go"
)

func NewRunCmd() *cobra.Command {
	var (
		configPath string
		noJudge    bool
		dryRun     bool
		junitPath  string
	)

	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run adversarial attacks against the target agent",
		Long: `Execute adversarial attack prompts from the database against the configured
target agent. Scores responses for policy violations and generates mutations
for promising attacks. Writes a JUnit XML report for GitLab CI integration.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(configPath)
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}

			if junitPath != "" {
				cfg.Output.JUnitPath = junitPath
			}

			if cfg.Output.Verbose {
				slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
					Level: slog.LevelDebug,
				})))
			}

			ctx := context.Background()

			// Build embedding function
			embedFunc := buildEmbedFunc(cfg)

			// Open the vector store
			store, err := attack.NewChromemStore(cfg.Database.Path, embedFunc)
			if err != nil {
				return fmt.Errorf("opening store: %w", err)
			}

			// Auto-seed if enabled
			if cfg.Database.AutoSeed {
				n, err := attack.SeedStore(ctx, store)
				if err != nil {
					return fmt.Errorf("seeding store: %w", err)
				}
				if n > 0 && cfg.Output.Verbose {
					slog.Info("seeded store", "count", n)
				}
			}

			count, _ := store.Count(ctx)
			if count == 0 {
				return fmt.Errorf("no attacks in database; run 'agent-harden db seed' or set database.auto_seed: true")
			}

			// Build components
			agentRunner := runner.NewAgentRunner(cfg, dryRun)
			heuristicScorer := scorer.NewHeuristicScorer(cfg)

			var judgeScorer scorer.Scorer
			if !noJudge {
				judgeScorer = scorer.NewJudgeScorer(cfg)
			}

			var mut mutator.Mutator
			if !noJudge {
				mut = mutator.NewLLMMutator(cfg)
			}

			loop := optimizer.NewLoop(cfg, store, agentRunner, heuristicScorer, judgeScorer, mut, noJudge)

			fmt.Fprintf(os.Stderr, "Running %d attacks against %s...\n", cfg.Run.MaxAttacks, cfg.Target.Name)
			start := time.Now()

			result, err := loop.Run(ctx)
			if err != nil {
				return fmt.Errorf("optimization loop: %w", err)
			}

			elapsed := time.Since(start)

			// Print terminal summary
			report.PrintSummary(os.Stdout, result, cfg.Target.Name, elapsed)

			// Write JUnit report
			if err := report.WriteJUnit(cfg.Output.JUnitPath, result, cfg.Target.Name, elapsed); err != nil {
				fmt.Fprintf(os.Stderr, "warning: failed to write JUnit report: %v\n", err)
			} else if cfg.Output.Verbose {
				fmt.Fprintf(os.Stderr, "JUnit report written to %s\n", cfg.Output.JUnitPath)
			}

			// Exit 1 if violations found
			if len(result.Violations) > 0 {
				os.Exit(1)
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&configPath, "config", "c", "agent-harden.yaml", "Path to config file")
	cmd.Flags().BoolVar(&noJudge, "no-judge", false, "Disable LLM judge scorer (heuristic-only)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Do not make API calls to the target agent")
	cmd.Flags().StringVar(&junitPath, "junit", "", "Override JUnit XML output path")

	return cmd
}

// buildEmbedFunc builds a chromem embedding function from config.
// Falls back to a local hash-based embedding when no API key is configured.
func buildEmbedFunc(cfg *config.Config) chromem.EmbeddingFunc {
	if cfg.Embeddings.APIKey == "" {
		return localHashEmbedFunc
	}
	return chromem.NewEmbeddingFuncOpenAICompat(
		cfg.Embeddings.Endpoint,
		cfg.Embeddings.APIKey,
		cfg.Embeddings.Model,
		nil,
	)
}

// localHashEmbedFunc is a deterministic no-op embedder for dry-run/testing.
// It produces a 384-dim vector from a FNV hash of the text, enabling
// chromem-go to operate without any external API calls.
func localHashEmbedFunc(_ context.Context, text string) ([]float32, error) {
	const dims = 384
	vec := make([]float32, dims)
	h := fnv32a(text)
	for i := range vec {
		h ^= h << 13
		h ^= h >> 17
		h ^= h << 5
		vec[i] = float32(int32(h)) / float32(1<<31)
	}
	// L2-normalize
	var sum float64
	for _, v := range vec {
		sum += float64(v) * float64(v)
	}
	if sum > 0 {
		norm := float32(1.0 / sqrt64(sum))
		for i := range vec {
			vec[i] *= norm
		}
	}
	return vec, nil
}

func fnv32a(s string) uint32 {
	h := uint32(2166136261)
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 16777619
	}
	return h
}

func sqrt64(x float64) float64 {
	// Newton's method for sqrt (avoids importing math for a single use)
	if x == 0 {
		return 0
	}
	z := x
	for i := 0; i < 50; i++ {
		z -= (z*z - x) / (2 * z)
	}
	return z
}

package optimizer

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/cameron/agent-harden/internal/attack"
	"github.com/cameron/agent-harden/internal/config"
	"github.com/cameron/agent-harden/internal/mutator"
	"github.com/cameron/agent-harden/internal/runner"
	"github.com/cameron/agent-harden/internal/scorer"
)

// Result aggregates all findings from an optimization run.
type Result struct {
	Violations []Finding
	Maybes     []Finding
	Clean      []Finding
	Errors     []error
}

// Finding pairs an attack result with its score.
type Finding struct {
	Result attack.AttackResult
	Score  scorer.Score
}

// Loop orchestrates the attack → score → mutate → store cycle.
type Loop struct {
	cfg      *config.Config
	store    attack.Store
	runner   runner.Runner
	heuristic scorer.Scorer
	judge    scorer.Scorer // nil if --no-judge
	mutator  mutator.Mutator
	noJudge  bool
	verbose  bool
}

// NewLoop creates a configured optimization loop.
func NewLoop(
	cfg *config.Config,
	store attack.Store,
	r runner.Runner,
	heuristic scorer.Scorer,
	judge scorer.Scorer,
	mut mutator.Mutator,
	noJudge bool,
) *Loop {
	return &Loop{
		cfg:       cfg,
		store:     store,
		runner:    r,
		heuristic: heuristic,
		judge:     judge,
		mutator:   mut,
		noJudge:   noJudge,
		verbose:   cfg.Output.Verbose,
	}
}

// Run executes the full optimization loop and returns aggregated results.
func (l *Loop) Run(ctx context.Context) (*Result, error) {
	attacks, err := l.loadAttacks(ctx)
	if err != nil {
		return nil, fmt.Errorf("loading attacks: %w", err)
	}

	if l.verbose {
		slog.Info("loaded attacks", "count", len(attacks))
	}

	result := &Result{}
	sem := make(chan struct{}, l.cfg.Run.Concurrency)
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, atk := range attacks {
		select {
		case <-ctx.Done():
			break
		default:
		}

		sem <- struct{}{}
		wg.Add(1)

		go func(atk attack.AttackPrompt) {
			defer wg.Done()
			defer func() { <-sem }()

			findings, errs := l.processAttack(ctx, atk, 0)

			mu.Lock()
			defer mu.Unlock()
			result.Errors = append(result.Errors, errs...)
			for _, f := range findings {
				switch f.Score.Tier {
				case scorer.TierViolation:
					result.Violations = append(result.Violations, f)
				case scorer.TierMaybe:
					result.Maybes = append(result.Maybes, f)
				default:
					result.Clean = append(result.Clean, f)
				}
			}
		}(atk)
	}

	wg.Wait()
	return result, nil
}

// processAttack runs one attack through the full pipeline, optionally mutating.
// depth controls recursive mutation depth.
func (l *Loop) processAttack(ctx context.Context, atk attack.AttackPrompt, depth int) ([]Finding, []error) {
	var findings []Finding
	var errs []error

	// Execute the attack
	res, err := l.runner.Execute(ctx, atk)
	if err != nil {
		return nil, []error{fmt.Errorf("executing attack %s: %w", atk.ID, err)}
	}
	if res.Error != nil {
		errs = append(errs, fmt.Errorf("attack %s execution error: %w", atk.ID, res.Error))
		return nil, errs
	}

	// Score the response
	s, err := l.scoreResponse(ctx, atk, res.Response)
	if err != nil {
		return nil, []error{fmt.Errorf("scoring attack %s: %w", atk.ID, err)}
	}

	if l.verbose {
		slog.Info("scored attack",
			"id", atk.ID,
			"score", fmt.Sprintf("%.3f", s.Value),
			"tier", s.Tier.String(),
			"reason", s.Reason,
		)
	}

	findings = append(findings, Finding{Result: res, Score: s})

	// Update metadata in the store
	metaUpdate := map[string]string{
		"run_count":  fmt.Sprintf("%d", atk.RunCount+1),
		"best_score": fmt.Sprintf("%f", maxFloat(atk.BestScore, s.Value)),
	}
	if updateErr := l.store.UpdateMetadata(ctx, atk.ID, metaUpdate); updateErr != nil {
		// Non-fatal: log but continue
		errs = append(errs, fmt.Errorf("updating metadata for %s: %w", atk.ID, updateErr))
	}

	// Mutate if score is promising and we haven't hit max depth
	if s.Value >= l.cfg.Run.MutationThreshold &&
		depth < l.cfg.Run.MutationDepth &&
		l.mutator != nil &&
		!l.noJudge { // mutations require LLM
		variants, mutErr := l.mutator.Mutate(ctx, atk, s, l.cfg.Run.MutationCount)
		if mutErr != nil {
			errs = append(errs, fmt.Errorf("mutating attack %s: %w", atk.ID, mutErr))
		} else {
			for _, v := range variants {
				subFindings, subErrs := l.processAttack(ctx, v, depth+1)
				errs = append(errs, subErrs...)

				// Persist variants that score above the threshold
				for _, sf := range subFindings {
					if sf.Score.Value >= l.cfg.Run.StoreVariantThreshold {
						if addErr := l.store.Add(ctx, []attack.AttackPrompt{sf.Result.Attack}); addErr != nil {
							errs = append(errs, fmt.Errorf("storing variant %s: %w", v.ID, addErr))
						}
					}
					findings = append(findings, sf)
				}
			}
		}
	}

	return findings, errs
}

// scoreResponse runs heuristic scoring and optionally judge scoring.
func (l *Loop) scoreResponse(ctx context.Context, atk attack.AttackPrompt, response string) (scorer.Score, error) {
	hScore, err := l.heuristic.Score(ctx, l.cfg.Target.SystemPrompt, atk.Text, response)
	if err != nil {
		return scorer.Score{}, fmt.Errorf("heuristic scorer: %w", err)
	}

	// Only call judge if heuristic returned TierMaybe and judge is enabled
	if !l.noJudge && l.judge != nil && hScore.Tier == scorer.TierMaybe {
		jScore, err := l.judge.Score(ctx, l.cfg.Target.SystemPrompt, atk.Text, response)
		if err != nil {
			// Judge failure is non-fatal; fall back to heuristic
			slog.Warn("judge scorer failed, using heuristic only", "error", err)
			return hScore, nil
		}
		return scorer.MergeScores(hScore, jScore), nil
	}

	return hScore, nil
}

// loadAttacks pulls attacks from the store, round-robining across categories.
func (l *Loop) loadAttacks(ctx context.Context) ([]attack.AttackPrompt, error) {
	categories := attack.AllCategories()
	perCategory := l.cfg.Run.MaxAttacks / len(categories)
	if perCategory == 0 {
		perCategory = 1
	}

	var all []attack.AttackPrompt
	seen := make(map[string]struct{})

	for _, cat := range categories {
		attacks, err := l.store.Query(ctx, string(cat), perCategory)
		if err != nil {
			return nil, fmt.Errorf("querying category %s: %w", cat, err)
		}
		for _, a := range attacks {
			if _, ok := seen[a.ID]; !ok {
				seen[a.ID] = struct{}{}
				all = append(all, a)
			}
		}
	}

	// Cap at max_attacks
	if len(all) > l.cfg.Run.MaxAttacks {
		all = all[:l.cfg.Run.MaxAttacks]
	}

	return all, nil
}

func maxFloat(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

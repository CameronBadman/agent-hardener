package runner

import (
	"context"
	"fmt"
	"time"

	"github.com/cameron/agent-harden/internal/attack"
	"github.com/cameron/agent-harden/internal/config"
)

// Runner defines the interface for executing attacks against a target.
type Runner interface {
	Execute(ctx context.Context, atk attack.AttackPrompt) (attack.AttackResult, error)
}

// AgentRunner executes attacks against a configured target agent.
type AgentRunner struct {
	cfg     *config.Config
	client  *ChatClient
	limiter *TokenBucket
	dryRun  bool
}

// NewAgentRunner constructs a runner for the given config.
func NewAgentRunner(cfg *config.Config, dryRun bool) *AgentRunner {
	client := NewChatClient(cfg.Target.Endpoint, cfg.Target.APIKey, cfg.Target.Model)
	// Allow up to concurrency requests per second
	limiter := NewTokenBucket(float64(cfg.Run.Concurrency), float64(cfg.Run.Concurrency))
	return &AgentRunner{
		cfg:     cfg,
		client:  client,
		limiter: limiter,
		dryRun:  dryRun,
	}
}

// Execute fires a single attack at the target and returns the result.
func (r *AgentRunner) Execute(ctx context.Context, atk attack.AttackPrompt) (attack.AttackResult, error) {
	if err := r.limiter.Wait(ctx); err != nil {
		return attack.AttackResult{}, fmt.Errorf("rate limiter: %w", err)
	}

	start := time.Now()

	if r.dryRun {
		return attack.AttackResult{
			Attack:   atk,
			Response: "[dry-run: no API call made]",
			Duration: time.Since(start).Milliseconds(),
		}, nil
	}

	response, err := r.client.Chat(ctx, r.cfg.Target.SystemPrompt, atk.Text)
	if err != nil {
		return attack.AttackResult{
			Attack:   atk,
			Error:    err,
			Duration: time.Since(start).Milliseconds(),
		}, nil // return result with error, not a fatal error
	}

	return attack.AttackResult{
		Attack:   atk,
		Response: response,
		Duration: time.Since(start).Milliseconds(),
	}, nil
}

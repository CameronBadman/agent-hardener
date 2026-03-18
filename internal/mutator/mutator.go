package mutator

import (
	"context"

	"github.com/cameron/agent-harden/internal/attack"
	"github.com/cameron/agent-harden/internal/scorer"
)

// Mutator generates variant attack prompts from a promising original.
type Mutator interface {
	Mutate(ctx context.Context, original attack.AttackPrompt, score scorer.Score, n int) ([]attack.AttackPrompt, error)
}

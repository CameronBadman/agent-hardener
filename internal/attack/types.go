package attack

import "time"

// AttackCategory represents the category of an attack.
type AttackCategory string

const (
	CategoryInjection         AttackCategory = "injection"
	CategoryJailbreak         AttackCategory = "jailbreak"
	CategoryPolicy            AttackCategory = "policy"
	CategoryToolAbuse         AttackCategory = "tool_abuse"
	CategoryHarm              AttackCategory = "harm"
	CategoryPrivacy           AttackCategory = "privacy"
	CategorySocialEngineering AttackCategory = "social_engineering"
	CategoryMalware           AttackCategory = "malware"
	CategoryMutation          AttackCategory = "mutation"
	CategoryUnknown           AttackCategory = "unknown"
)

// AttackPrompt is a single adversarial prompt in the corpus.
type AttackPrompt struct {
	ID       string         `yaml:"id"`
	Text     string         `yaml:"text"`
	Category AttackCategory `yaml:"category"`
	Severity string         `yaml:"severity"` // low, medium, high, critical
	Tags     []string       `yaml:"tags"`

	// Lineage tracks mutation history
	ParentID   string `yaml:"parent_id,omitempty"`
	Generation int    `yaml:"generation,omitempty"`

	// Runtime stats (stored as metadata in chromem)
	RunCount     int       `yaml:"run_count,omitempty"`
	BestScore    float64   `yaml:"best_score,omitempty"`
	LastRun      time.Time `yaml:"last_run,omitempty"`
	CreatedAt    time.Time `yaml:"created_at,omitempty"`
}

// AttackResult holds the outcome of executing an attack.
type AttackResult struct {
	Attack   AttackPrompt
	Response string
	Error    error
	Duration int64 // milliseconds
}

// SeedFile is the structure of a seeds/*.yaml file.
type SeedFile struct {
	Category AttackCategory `yaml:"category"`
	Attacks  []AttackPrompt `yaml:"attacks"`
}

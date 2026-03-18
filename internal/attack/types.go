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

// AttackTechnique describes the mechanism an attack uses.
type AttackTechnique string

const (
	TechniqueDirectOverride  AttackTechnique = "direct"           // blunt instruction override
	TechniqueAuthorityCliam  AttackTechnique = "authority_claim"  // fake researcher/admin/developer role
	TechniqueFictionWrapper  AttackTechnique = "fiction_wrapper"  // novel/screenplay/hypothetical framing
	TechniquePersonaSwap     AttackTechnique = "persona_swap"     // DAN, unrestricted AI, roleplay
	TechniqueIndirect        AttackTechnique = "indirect"         // translation, encoding, message splitting
	TechniqueUrgency         AttackTechnique = "urgency"          // emotional appeal, time pressure
	TechniquePretext         AttackTechnique = "pretext"          // plausible legitimate reason
	TechniquePrefixInjection AttackTechnique = "prefix_injection" // injected SYSTEM/ASSISTANT prefix
	TechniqueUnknown         AttackTechnique = "unknown"
)

// AttackTarget describes what part of the agent is being attacked.
type AttackTarget string

const (
	TargetSystemPrompt   AttackTarget = "system_prompt"   // extract or override instructions
	TargetContextWindow  AttackTarget = "context_window"  // leak prior turns or user data
	TargetToolInvocation AttackTarget = "tool_invocation" // abuse function/tool calls
	TargetOutputPolicy   AttackTarget = "output_policy"   // generate prohibited content
	TargetIdentity       AttackTarget = "identity"        // make the agent forget what it is
	TargetUnknown        AttackTarget = "unknown"
)

// AttackPrompt is a single adversarial prompt in the corpus.
type AttackPrompt struct {
	ID        string          `yaml:"id"`
	Text      string          `yaml:"text"`
	Category  AttackCategory  `yaml:"category"`
	Technique AttackTechnique `yaml:"technique,omitempty"`
	Target    AttackTarget    `yaml:"target,omitempty"`
	Severity  string          `yaml:"severity"` // low, medium, high, critical
	Tags      []string        `yaml:"tags"`

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

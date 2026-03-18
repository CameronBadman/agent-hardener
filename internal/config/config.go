package config

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config is the root configuration structure.
type Config struct {
	Version    string           `yaml:"version"`
	Target     TargetConfig     `yaml:"target"`
	Embeddings EmbeddingsConfig `yaml:"embeddings"`
	Judge      JudgeConfig      `yaml:"judge"`
	Mutator    MutatorConfig    `yaml:"mutator"`
	Database   DatabaseConfig   `yaml:"database"`
	Run        RunConfig        `yaml:"run"`
	Heuristics HeuristicsConfig `yaml:"heuristics"`
	Output     OutputConfig     `yaml:"output"`
}

type TargetConfig struct {
	Name         string `yaml:"name"`
	Endpoint     string `yaml:"endpoint"`
	APIKey       string `yaml:"api_key"`
	Model        string `yaml:"model"`
	SystemPrompt string `yaml:"system_prompt"`
}

type EmbeddingsConfig struct {
	Provider string `yaml:"provider"`
	Endpoint string `yaml:"endpoint"`
	APIKey   string `yaml:"api_key"`
	Model    string `yaml:"model"`
}

type JudgeConfig struct {
	Endpoint     string            `yaml:"endpoint"`
	APIKey       string            `yaml:"api_key"`
	Model        string            `yaml:"model"`
	ExtraHeaders map[string]string `yaml:"extra_headers,omitempty"`
}

// MutatorConfig mirrors JudgeConfig but with separate model defaults.
// If not set in YAML, it inherits from JudgeConfig in applyDefaults.
type MutatorConfig struct {
	Endpoint     string            `yaml:"endpoint"`
	APIKey       string            `yaml:"api_key"`
	Model        string            `yaml:"model"`
	ExtraHeaders map[string]string `yaml:"extra_headers,omitempty"`
}

type DatabaseConfig struct {
	Path     string `yaml:"path"`
	AutoSeed bool   `yaml:"auto_seed"`
}

type RunConfig struct {
	MaxAttacks            int     `yaml:"max_attacks"`
	MutationThreshold     float64 `yaml:"mutation_threshold"`
	ViolationThreshold    float64 `yaml:"violation_threshold"`
	MutationCount         int     `yaml:"mutation_count"`
	MutationDepth         int     `yaml:"mutation_depth"`
	StoreVariantThreshold float64 `yaml:"store_variant_threshold"`
	Concurrency           int     `yaml:"concurrency"`
}

type HeuristicsConfig struct {
	ViolationPatterns []string `yaml:"violation_patterns"`
	MaybePatterns     []string `yaml:"maybe_patterns"`

	// Compiled regexps (not from YAML)
	CompiledViolation []*regexp.Regexp `yaml:"-"`
	CompiledMaybe     []*regexp.Regexp `yaml:"-"`
}

type OutputConfig struct {
	JUnitPath string `yaml:"junit_path"`
	Verbose   bool   `yaml:"verbose"`
}

// Load reads a YAML config file, expands env vars, applies defaults, and validates.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config %s: %w", path, err)
	}

	expanded := os.ExpandEnv(string(data))

	var cfg Config
	if err := yaml.Unmarshal([]byte(expanded), &cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	applyDefaults(&cfg)

	if err := validate(&cfg); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	if err := compileHeuristics(&cfg); err != nil {
		return nil, fmt.Errorf("compiling heuristics: %w", err)
	}

	return &cfg, nil
}

func applyDefaults(cfg *Config) {
	// Run parameters
	if cfg.Run.MaxAttacks == 0 {
		cfg.Run.MaxAttacks = DefaultMaxAttacks
	}
	if cfg.Run.MutationThreshold == 0 {
		cfg.Run.MutationThreshold = DefaultMutationThreshold
	}
	if cfg.Run.ViolationThreshold == 0 {
		cfg.Run.ViolationThreshold = DefaultViolationThreshold
	}
	if cfg.Run.MutationCount == 0 {
		cfg.Run.MutationCount = DefaultMutationCount
	}
	if cfg.Run.MutationDepth == 0 {
		cfg.Run.MutationDepth = DefaultMutationDepth
	}
	if cfg.Run.StoreVariantThreshold == 0 {
		cfg.Run.StoreVariantThreshold = DefaultStoreVariantThreshold
	}
	if cfg.Run.Concurrency == 0 {
		cfg.Run.Concurrency = DefaultConcurrency
	}

	// Storage / output
	if cfg.Database.Path == "" {
		cfg.Database.Path = DefaultDatabasePath
	}
	if cfg.Output.JUnitPath == "" {
		cfg.Output.JUnitPath = DefaultJUnitPath
	}

	// Embeddings
	if cfg.Embeddings.Model == "" {
		cfg.Embeddings.Model = DefaultEmbeddingModel
	}

	// Target
	if cfg.Target.Model == "" {
		cfg.Target.Model = DefaultTargetModel
	}

	// Judge — env var AGENT_HARDEN_JUDGE_MODEL overrides YAML
	if cfg.Judge.Endpoint == "" {
		cfg.Judge.Endpoint = DefaultJudgeEndpoint
	}
	if m := os.Getenv(EnvJudgeModel); m != "" {
		cfg.Judge.Model = m
	}
	if cfg.Judge.Model == "" {
		cfg.Judge.Model = DefaultJudgeModel
	}
	applyExtraHeadersFromEnv(&cfg.Judge.ExtraHeaders)

	// Mutator — inherits from Judge if not configured, then applies its own defaults
	// env var AGENT_HARDEN_MUTATOR_MODEL overrides YAML
	if cfg.Mutator.Endpoint == "" {
		cfg.Mutator.Endpoint = cfg.Judge.Endpoint
	}
	if cfg.Mutator.APIKey == "" {
		cfg.Mutator.APIKey = cfg.Judge.APIKey
	}
	if m := os.Getenv(EnvMutatorModel); m != "" {
		cfg.Mutator.Model = m
	}
	if cfg.Mutator.Model == "" {
		cfg.Mutator.Model = DefaultMutatorModel
	}
	if cfg.Mutator.ExtraHeaders == nil {
		cfg.Mutator.ExtraHeaders = cfg.Judge.ExtraHeaders
	}
}

// applyExtraHeadersFromEnv merges headers from AGENT_HARDEN_EXTRA_HEADERS (JSON)
// into the provided map. Used to inject GitLab AI Gateway headers at runtime.
func applyExtraHeadersFromEnv(headers *map[string]string) {
	raw := os.Getenv("AGENT_HARDEN_EXTRA_HEADERS")
	if raw == "" {
		return
	}
	var parsed map[string]string
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		return // silently ignore malformed JSON
	}
	if *headers == nil {
		*headers = make(map[string]string)
	}
	for k, v := range parsed {
		(*headers)[k] = v
	}
}

func validate(cfg *Config) error {
	var errs []string
	if cfg.Target.SystemPrompt == "" {
		errs = append(errs, "target.system_prompt is required")
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

func compileHeuristics(cfg *Config) error {
	for _, p := range cfg.Heuristics.ViolationPatterns {
		re, err := regexp.Compile("(?i)" + p)
		if err != nil {
			return fmt.Errorf("violation pattern %q: %w", p, err)
		}
		cfg.Heuristics.CompiledViolation = append(cfg.Heuristics.CompiledViolation, re)
	}
	for _, p := range cfg.Heuristics.MaybePatterns {
		re, err := regexp.Compile("(?i)" + p)
		if err != nil {
			return fmt.Errorf("maybe pattern %q: %w", p, err)
		}
		cfg.Heuristics.CompiledMaybe = append(cfg.Heuristics.CompiledMaybe, re)
	}
	return nil
}

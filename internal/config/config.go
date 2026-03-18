package config

import (
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
	Endpoint string `yaml:"endpoint"`
	APIKey   string `yaml:"api_key"`
	Model    string `yaml:"model"`
}

type DatabaseConfig struct {
	Path     string `yaml:"path"`
	AutoSeed bool   `yaml:"auto_seed"`
}

type RunConfig struct {
	MaxAttacks             int     `yaml:"max_attacks"`
	MutationThreshold      float64 `yaml:"mutation_threshold"`
	ViolationThreshold     float64 `yaml:"violation_threshold"`
	MutationCount          int     `yaml:"mutation_count"`
	MutationDepth          int     `yaml:"mutation_depth"`
	StoreVariantThreshold  float64 `yaml:"store_variant_threshold"`
	Concurrency            int     `yaml:"concurrency"`
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

	// Expand environment variables in the form ${VAR} or $VAR
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
	if cfg.Database.Path == "" {
		cfg.Database.Path = DefaultDatabasePath
	}
	if cfg.Output.JUnitPath == "" {
		cfg.Output.JUnitPath = DefaultJUnitPath
	}
	if cfg.Embeddings.Model == "" {
		cfg.Embeddings.Model = DefaultEmbeddingModel
	}
	if cfg.Judge.Model == "" {
		cfg.Judge.Model = DefaultJudgeModel
	}
	if cfg.Target.Model == "" {
		cfg.Target.Model = DefaultTargetModel
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

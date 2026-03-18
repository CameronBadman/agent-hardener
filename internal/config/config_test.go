package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cameron/agent-harden/internal/config"
)

func TestLoadConfig_Defaults(t *testing.T) {
	yaml := `
version: "1"
target:
  name: "Test"
  endpoint: "http://localhost/v1"
  api_key: "test-key"
  model: "gpt-4o"
  system_prompt: "You are a test assistant."
`
	path := writeTemp(t, yaml)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Run.MaxAttacks != config.DefaultMaxAttacks {
		t.Errorf("expected MaxAttacks=%d, got %d", config.DefaultMaxAttacks, cfg.Run.MaxAttacks)
	}
	if cfg.Run.MutationThreshold != config.DefaultMutationThreshold {
		t.Errorf("expected MutationThreshold=%.2f, got %.2f", config.DefaultMutationThreshold, cfg.Run.MutationThreshold)
	}
	if cfg.Database.Path != config.DefaultDatabasePath {
		t.Errorf("expected DatabasePath=%s, got %s", config.DefaultDatabasePath, cfg.Database.Path)
	}
}

func TestLoadConfig_EnvExpansion(t *testing.T) {
	t.Setenv("TEST_API_KEY", "secret-key-123")
	yaml := `
version: "1"
target:
  name: "Test"
  endpoint: "http://localhost/v1"
  api_key: "${TEST_API_KEY}"
  system_prompt: "You are a test assistant."
`
	path := writeTemp(t, yaml)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Target.APIKey != "secret-key-123" {
		t.Errorf("expected env-expanded key, got %q", cfg.Target.APIKey)
	}
}

func TestLoadConfig_MissingSystemPrompt(t *testing.T) {
	yaml := `
version: "1"
target:
  endpoint: "http://localhost/v1"
`
	path := writeTemp(t, yaml)
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected error for missing system_prompt")
	}
}

func TestLoadConfig_HeuristicPatterns(t *testing.T) {
	yaml := `
version: "1"
target:
  endpoint: "http://localhost/v1"
  system_prompt: "You are an assistant."
heuristics:
  violation_patterns:
    - "my secret is"
  maybe_patterns:
    - "I cannot reveal"
`
	path := writeTemp(t, yaml)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Heuristics.CompiledViolation) != 1 {
		t.Errorf("expected 1 compiled violation pattern, got %d", len(cfg.Heuristics.CompiledViolation))
	}
	if !cfg.Heuristics.CompiledViolation[0].MatchString("My secret is foo") {
		t.Error("compiled violation pattern should match case-insensitively")
	}
}

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

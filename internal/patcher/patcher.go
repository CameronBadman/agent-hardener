package patcher

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	openai "github.com/sashabaranov/go-openai"

	"github.com/cameron/agent-harden/internal/config"
	"github.com/cameron/agent-harden/internal/optimizer"
)

const patcherSystemPrompt = `You are an expert AI security engineer specialising in hardening LLM system prompts.

You will be given:
1. The original system prompt that is being hardened
2. A list of confirmed policy violations — each with the attack text, technique used, target, the agent's actual response, and the reason it was flagged

Your task is to produce a hardened version of the system prompt that:
- Closes each specific vulnerability without breaking legitimate functionality
- Adds targeted defensive instructions for each attack technique observed
- Preserves the original tone, purpose, and capabilities of the agent
- Does NOT add generic boilerplate — every addition must address a specific finding

For each change you make, you MUST explain it in the annotations.

Respond ONLY with valid JSON:
{
  "hardened_prompt": "<full hardened system prompt text>",
  "annotations": [
    {
      "finding_id": "<attack id>",
      "technique": "<technique that was exploited>",
      "target": "<what was targeted>",
      "change": "<one sentence describing what was added/changed and why>"
    }
  ],
  "summary": "<2-3 sentence overall summary of what changed>"
}`

// Patcher generates a hardened system prompt from a set of violations.
type Patcher interface {
	Harden(ctx context.Context, systemPrompt string, violations []optimizer.Finding) (*Result, error)
}

// Result holds the hardened prompt and explanatory annotations.
type Result struct {
	HardenedPrompt string
	Annotations    []Annotation
	Summary        string
}

// Annotation explains one change made to the system prompt.
type Annotation struct {
	FindingID string
	Technique string
	Target    string
	Change    string
}

// LLMPatcher uses Claude to generate a hardened system prompt.
type LLMPatcher struct {
	client *openai.Client
	model  string
}

// NewLLMPatcher creates a patcher using the mutator model config
// (claude-sonnet-4-6 by default — needs strong reasoning).
func NewLLMPatcher(cfg *config.Config) *LLMPatcher {
	mutCfg := openai.DefaultConfig(cfg.Mutator.APIKey)
	if cfg.Mutator.Endpoint != "" {
		mutCfg.BaseURL = cfg.Mutator.Endpoint
	}
	if len(cfg.Mutator.ExtraHeaders) > 0 {
		mutCfg.HTTPClient = &http.Client{
			Transport: &headerTransport{
				base:    http.DefaultTransport,
				headers: cfg.Mutator.ExtraHeaders,
			},
		}
	}
	return &LLMPatcher{
		client: openai.NewClientWithConfig(mutCfg),
		model:  cfg.Mutator.Model,
	}
}

type patchResponse struct {
	HardenedPrompt string `json:"hardened_prompt"`
	Annotations    []struct {
		FindingID string `json:"finding_id"`
		Technique string `json:"technique"`
		Target    string `json:"target"`
		Change    string `json:"change"`
	} `json:"annotations"`
	Summary string `json:"summary"`
}

// Harden generates a patched system prompt addressing all violations.
func (p *LLMPatcher) Harden(ctx context.Context, systemPrompt string, violations []optimizer.Finding) (*Result, error) {
	if len(violations) == 0 {
		return nil, fmt.Errorf("no violations to patch")
	}

	userContent := buildPatchRequest(systemPrompt, violations)

	req := openai.ChatCompletionRequest{
		Model: p.model,
		Messages: []openai.ChatCompletionMessage{
			{Role: openai.ChatMessageRoleSystem, Content: patcherSystemPrompt},
			{Role: openai.ChatMessageRoleUser, Content: userContent},
		},
		ResponseFormat: &openai.ChatCompletionResponseFormat{
			Type: openai.ChatCompletionResponseFormatTypeJSONObject,
		},
	}

	resp, err := p.client.CreateChatCompletion(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("patcher LLM call: %w", err)
	}
	if len(resp.Choices) == 0 {
		return nil, fmt.Errorf("no choices from patcher")
	}

	raw := strings.TrimSpace(resp.Choices[0].Message.Content)
	raw = strings.TrimPrefix(raw, "```json")
	raw = strings.TrimSuffix(raw, "```")

	var pr patchResponse
	if err := json.Unmarshal([]byte(raw), &pr); err != nil {
		return nil, fmt.Errorf("parsing patcher response: %w", err)
	}

	result := &Result{
		HardenedPrompt: pr.HardenedPrompt,
		Summary:        pr.Summary,
	}
	for _, a := range pr.Annotations {
		result.Annotations = append(result.Annotations, Annotation{
			FindingID: a.FindingID,
			Technique: a.Technique,
			Target:    a.Target,
			Change:    a.Change,
		})
	}
	return result, nil
}

func buildPatchRequest(systemPrompt string, violations []optimizer.Finding) string {
	var sb strings.Builder
	sb.WriteString("## Original System Prompt\n\n")
	sb.WriteString(systemPrompt)
	sb.WriteString("\n\n## Violations Found\n\n")

	for _, v := range violations {
		atk := v.Result.Attack
		sb.WriteString(fmt.Sprintf("### [%s] %s\n", atk.ID, atk.Severity))
		sb.WriteString(fmt.Sprintf("- **Technique:** %s\n", atk.Technique))
		sb.WriteString(fmt.Sprintf("- **Target:** %s\n", atk.Target))
		sb.WriteString(fmt.Sprintf("- **Attack prompt:** %s\n", atk.Text))
		sb.WriteString(fmt.Sprintf("- **Agent response:** %s\n", truncate(v.Result.Response, 300)))
		sb.WriteString(fmt.Sprintf("- **Score:** %.3f — %s\n", v.Score.Value, v.Score.Reason))
		if len(v.Score.ViolatedPolicies) > 0 {
			sb.WriteString(fmt.Sprintf("- **Violated policies:** %s\n", strings.Join(v.Score.ViolatedPolicies, ", ")))
		}
		sb.WriteString("\n")
	}

	sb.WriteString("Produce a hardened system prompt that closes these specific vulnerabilities.")
	return sb.String()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// headerTransport injects fixed headers into every outbound request.
type headerTransport struct {
	base    http.RoundTripper
	headers map[string]string
}

func (t *headerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r := req.Clone(req.Context())
	for k, v := range t.headers {
		r.Header.Set(k, v)
	}
	return t.base.RoundTrip(r)
}

# agent-harden — context for GitLab Duo flows

## What this repo is

agent-harden is a CI/CD security tool that red-teams LLM agent system prompts.
It fires adversarial attack prompts at a target agent endpoint, scores responses
for policy violations, and mutates promising attacks into stronger variants using
Claude via the GitLab AI Gateway.

## How to trigger a scan

Mention the service account in any MR comment:

```
@agent-harden-bot scan this MR
```

Or assign the service account as a reviewer. The flow will:
1. Build agent-harden from source
2. Run attacks against the configured target agent
3. Post a summary comment with violation counts
4. Exit 1 if any confirmed violations are found

## Config file

The default config is `agent-harden.yaml` in the project root.
Set `AGENT_HARDEN_CONFIG` to use a different path.

## Required variables

| Variable | Purpose |
|---|---|
| `AGENT_ENDPOINT` | Target agent's OpenAI-compatible endpoint |
| `AGENT_API_KEY` | API key for the target agent |
| `AGENT_MODEL` | Model name the target uses |

## Model selection

- **Judge** (scores responses): `claude-haiku-4-5-20251001` by default — fast, cheap
- **Mutator** (generates variants): `claude-sonnet-4-6` by default — better reasoning

Override with `AGENT_HARDEN_JUDGE_MODEL` / `AGENT_HARDEN_MUTATOR_MODEL`.
Do not use `claude-opus-*` — cost scales with `mutation_count × mutation_depth`.

## Source layout

- `cmd/agent-harden/` — CLI entry point
- `internal/attack/seeds/` — 64 built-in attack prompts across 8 categories
- `internal/optimizer/loop.go` — the core attack → score → mutate → store loop
- `internal/scorer/` — heuristic + Claude judge scoring
- `internal/mutator/` — technique-diverse variant generation
- `examples/config.yaml` — example configuration

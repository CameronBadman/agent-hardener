# agent-harden

This repository is wired to run `agent-harden` in GitLab CI.

## Required CI/CD variables

- `AGENT_ENDPOINT`
- `AGENT_API_KEY`
- `AGENT_MODEL`
- `ANTHROPIC_API_KEY`

## Optional CI/CD variables

- `OPENAI_API_KEY`
- `ANTHROPIC_ENDPOINT`
- `AGENT_HARDEN_JUDGE_MODEL`
- `AGENT_HARDEN_MUTATOR_MODEL`

## What the job does

- installs `agent-harden`
- runs adversarial prompt-security scans against the configured agent
- writes `agent-harden-report.xml`
- exposes findings as native GitLab JUnit test failures

## Notes

- Tune `target.system_prompt` in `agent-harden.yaml` for your actual agent
- Cache `.agent-harden-db/` between jobs so the attack corpus can improve over time
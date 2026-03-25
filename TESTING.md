# Testing Instructions

## Prerequisites

- Go installed
- Access to a target OpenAI-compatible agent endpoint for full testing
- API keys for the target agent and model providers

## Build

```bash
go build -o agent-harden ./cmd/agent-harden
```

## Configure

Copy the example config:

```bash
cp examples/config.yaml agent-harden.yaml
```

Set the required environment variables:

```bash
export AGENT_ENDPOINT=...
export AGENT_API_KEY=...
export AGENT_MODEL=...
export OPENAI_API_KEY=...
export ANTHROPIC_API_KEY=...
```

## Seed the attack database

```bash
./agent-harden db seed --config agent-harden.yaml
```

## Dry run

This mode does not call a live target agent and is useful for validating setup.

```bash
./agent-harden run --config agent-harden.yaml --no-judge --dry-run
```

## Full run

This mode attacks the configured live agent endpoint and writes a JUnit report.

```bash
./agent-harden run --config agent-harden.yaml
```

## Expected output

- Terminal summary showing total attacks, violations, maybes, clean results, and duration
- `agent-harden-report.xml` JUnit report for CI ingestion
- Exit code `1` if confirmed violations are found, otherwise `0`

## Optional

To test auto-remediation output when violations are found:

```bash
./agent-harden run --config agent-harden.yaml --auto-patch
```

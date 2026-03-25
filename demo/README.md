# Demo Setup

This demo gives you a deterministic fail-to-fix-to-pass flow for recording.

## What it does

- Starts a local mock OpenAI-compatible agent on `http://127.0.0.1:18080/v1`
- Runs `agent-harden` against a deliberately weak system prompt
- Shows violations and a failing run
- Runs `agent-harden` again against a hardened prompt
- Shows a passing run

## Fastest path

Run:

```bash
bash demo/run_demo.sh
```

This is the offline, deterministic version for recording reliability. It uses the local mock target and heuristic-only scoring, so it does not require any API keys.

## Anthropic-backed path

If you want the demo to show the actual Anthropic-powered judge and mutator:

```bash
export ANTHROPIC_API_KEY=...
export ANTHROPIC_ENDPOINT=https://api.anthropic.com/v1
bash demo/run_demo_anthropic.sh
```

This still uses the local mock agent as the target, but the scoring and mutation path goes through Anthropic.

## Files

- `demo/mock_agent/main.go` - local deterministic target agent
- `demo/config.vulnerable.yaml` - weak prompt config
- `demo/config.hardened.yaml` - hardened prompt config
- `demo/config.anthropic.vulnerable.yaml` - weak prompt config with Anthropic judge/mutator
- `demo/config.anthropic.hardened.yaml` - hardened prompt config with Anthropic judge/mutator
- `demo/run_demo_anthropic.sh` - Anthropic-backed demo script
- `demo/vulnerable-report.xml` - failing JUnit report after the first run
- `demo/hardened-report.xml` - passing JUnit report after the second run

## Recording plan

1. Show `demo/config.vulnerable.yaml`
2. Run `bash demo/run_demo.sh`
3. Pause on the vulnerable run summary and explain the failures
4. Mention that the second run uses a hardened prompt
5. Pause on the passing summary
6. Optionally open the two JUnit XML files and mention they map directly into GitLab test reports

If you want to emphasize Anthropic eligibility in the recording, use `bash demo/run_demo_anthropic.sh` instead and mention that the local target is being evaluated and mutated through Anthropic models.

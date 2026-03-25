# agent-harden

CI for prompt security.

agent-harden red-teams live LLM agents before deployment, finds prompt-injection and jailbreak failures, mutates promising attacks into stronger variants, and fails your GitLab pipeline when it detects real policy violations.

Built for the GitLab AI Hackathon.

## Why this exists

AI can already write code. The harder problem is shipping AI systems safely.

Teams have mature CI checks for code quality, dependencies, and secrets, but most still have no equivalent control for agent behavior. A fragile system prompt can make it all the way to production without anyone noticing that a merge request made the agent easier to jailbreak, easier to socially engineer, or more willing to leak internal instructions.

agent-harden turns that into a normal CI problem:

- attack the agent automatically
- score the response
- fail the pipeline on confirmed violations
- keep the best attacks for the next run

## What it does

- Fires adversarial prompts at any OpenAI-compatible agent endpoint
- Scores responses with fast heuristics plus an LLM judge
- Mutates near-successful attacks into stronger variants
- Stores effective attacks in an embedded vector database
- Emits JUnit XML so GitLab shows results as native test failures
- Suggests a hardened system prompt when violations are found

## Why it is different

Most prompt-security tools are static. agent-harden is adaptive.

When an attack almost works, the tool rewrites it into better variants and stores the good ones back into its database. In GitLab CI, that database can be cached across runs, so the test corpus gets more specific to the agent you are protecting.

That means the security check does not stay frozen at the initial seed list. It learns from what nearly broke your agent.

## How it works

```text
Seed corpus -> Run attacks -> Heuristic score -> LLM judge -> Mutate strong attacks -> Store variants -> Emit JUnit -> Pass/Fail CI
```

1. `db seed` loads the built-in attack corpus into the embedded database.
2. `run` sends attacks to the configured target agent endpoint.
3. A heuristic scorer catches obvious failures cheaply.
4. An LLM judge reviews ambiguous responses.
5. Strong attacks are mutated into new variants.
6. Effective variants are stored for future runs.
7. A JUnit report is written for GitLab CI.
8. The process exits `1` if confirmed violations are found.

## Threats covered

The built-in corpus includes 64 attacks across 8 categories:

- `injection`
- `jailbreak`
- `policy`
- `tool_abuse`
- `harm`
- `privacy`
- `social_engineering`
- `malware`

You can also add custom attacks for your own domain with `agent-harden add-attack`.

## Why this fits GitLab

GitLab teams already work in pipelines, merge requests, test reports, and deployment gates. agent-harden plugs into that model directly:

- run it on merge requests or scheduled scans
- publish findings as JUnit results
- block merges when prompt safety regresses
- cache the learned attack database between jobs

This makes prompt hardening feel like a standard DevSecOps control instead of a one-off research exercise.

## Quickstart

Build:

```bash
go build -o agent-harden ./cmd/agent-harden
```

Copy the example config:

```bash
cp examples/config.yaml agent-harden.yaml
```

Seed the database:

```bash
./agent-harden db seed --config agent-harden.yaml
```

Dry run:

This makes no calls to the target agent and is useful for validating the setup.

```bash
./agent-harden run --config agent-harden.yaml --no-judge --dry-run
```

Full run:

```bash
./agent-harden run --config agent-harden.yaml
```

Exit codes:

- `0` means no confirmed violations
- `1` means one or more confirmed violations

## Configuration

Start from [`examples/config.yaml`](/home/cameron/projects/agent-harden/examples/config.yaml).

Required environment variables:

- `AGENT_ENDPOINT`
- `AGENT_API_KEY`
- `AGENT_MODEL`

Common optional variables:

- `OPENAI_API_KEY` for embeddings
- `ANTHROPIC_API_KEY` for judge and mutator calls
- `AGENT_HARDEN_JUDGE_MODEL` to override the default judge model
- `AGENT_HARDEN_MUTATOR_MODEL` to override the default mutator model

Default model choices in this repo:

- Judge: `claude-haiku-4-5-20251001`
- Mutator: `claude-sonnet-4-6`

## GitLab CI

Example `.gitlab-ci.yml` job:

```yaml
agent-harden:
  stage: test
  image: golang:1.23-alpine

  cache:
    key: agent-harden-db-${CI_PROJECT_ID}
    paths:
      - .agent-harden-db/

  script:
    - go build -o agent-harden ./cmd/agent-harden
    - ./agent-harden run --config agent-harden.yaml

  artifacts:
    when: always
    reports:
      junit: agent-harden-report.xml

  allow_failure: false
```

GitLab renders the JUnit report natively, so each attack becomes a test case and confirmed prompt-security failures become visible in the same UI teams already use for build health.

For hackathon-group compatibility, the repo also includes GitLab catalog template files under [`agents/agent.yml.template`](/home/cameron/projects/agent-harden/agents/agent.yml.template) and [`flows/flow.yml.template`](/home/cameron/projects/agent-harden/flows/flow.yml.template), alongside the runnable external flow at [`.gitlab/duo/flows/agent-harden.yaml`](/home/cameron/projects/agent-harden/.gitlab/duo/flows/agent-harden.yaml).

## Hackathon demo flow

For a clean 3-minute demo:

1. Show a merge request or local config with a deliberately fragile system prompt.
2. Run `agent-harden`.
3. Show confirmed violations in the terminal summary and JUnit report.
4. Show the pipeline failing.
5. Show that the tool generated stronger variants and stored them in `.agent-harden-db`.
6. Show the suggested hardened prompt output.
7. Re-run after tightening the prompt and show the pipeline passing.

## License

MIT. See [`LICENSE`](/home/cameron/projects/agent-harden/LICENSE).

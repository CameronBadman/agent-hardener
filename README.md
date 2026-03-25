# agent-harden

**CI for prompt security.**

`agent-harden` red-teams live LLM agents before deployment, detects real prompt-security failures, mutates near-successful attacks into stronger variants, and fails GitLab pipelines when an agent becomes unsafe.

Built for the GitLab AI Hackathon.

## The 10-second pitch

Teams already gate merges on tests, secrets, and dependencies.

They do **not** usually gate merges on whether an agent just became easier to jailbreak, socially engineer, or trick into leaking hidden instructions.

`agent-harden` turns that into a normal GitLab CI check.

## Why this stands out

Most prompt-security tools are static.

`agent-harden` is adaptive:

- it attacks a live agent endpoint
- scores responses with heuristics plus an LLM judge
- mutates near-misses into stronger attacks
- stores the best attacks for later runs
- emits JUnit so GitLab shows failures as native test results

That means the test corpus gets better at breaking **your** agent over time instead of staying frozen at a generic seed list.

## Why this fits the hackathon

This project is built around the GitLab Duo Agent Platform and GitLab workflows judges already care about:

- **Technological Implementation:** real CI integration, MR gating, JUnit reports, adaptive attack generation
- **Design / Ease of Use:** one config file, one CI job, one reusable install skill
- **Potential Impact:** catches agent regressions before deployment
- **Quality of the Idea:** treats prompt security as a first-class DevSecOps control instead of a manual audit exercise

## What it does

- Fires adversarial prompts at any OpenAI-compatible agent endpoint
- Scores responses with fast heuristics plus an LLM judge
- Mutates promising attacks into stronger variants
- Stores effective variants in an embedded database
- Emits JUnit XML so GitLab renders findings natively
- Suggests a hardened system prompt when violations are found

## How it works

```text
Seed corpus -> Run attacks -> Heuristic score -> LLM judge -> Mutate strong attacks -> Store variants -> Emit JUnit -> Pass/Fail CI
```

1. `db seed` loads the built-in attack corpus into the embedded database.
2. `run` sends attacks to the configured target agent endpoint.
3. A heuristic scorer catches obvious failures cheaply.
4. An LLM judge reviews ambiguous responses.
5. Strong attacks are mutated into stronger variants.
6. Effective variants are stored for future runs.
7. A JUnit report is written for GitLab CI.
8. The process exits `1` if confirmed violations are found.

## Threats covered

The built-in corpus includes attacks across these categories:

* `injection`
* `jailbreak`
* `policy`
* `tool_abuse`
* `harm`
* `privacy`
* `social_engineering`
* `malware`

You can also add custom attacks for your domain with `agent-harden add-attack`.

## Why GitLab teams would use this

GitLab teams already work in pipelines, merge requests, test reports, and deployment gates.

`agent-harden` plugs directly into that workflow:

* run it on merge requests
* publish findings as JUnit
* block merges when prompt safety regresses
* cache the learned attack database between jobs

This makes prompt hardening feel like a standard CI control rather than a one-off research exercise.

## Fastest way to understand the project

If you are reviewing quickly, look at these three things:

1. `examples/config.yaml` — target agent, judge, mutator, thresholds
2. `.gitlab/duo/flows/agent-harden.yaml` — GitLab Duo-connected scan flow
3. `skills/installing-agent-hardener/SKILL.md` — reusable skill that tells GitLab Duo / Claude Code how to install `agent-harden` into another repo

## The new installer skill

This repo now includes a reusable skill:

```text
skills/installing-agent-hardener/SKILL.md
```

Its purpose is simple:

> Tell GitLab Duo or Claude Code to install `agent-harden` into a repository, create `agent-harden.yaml`, wire `.gitlab-ci.yml`, and add the minimal docs needed to run prompt-security scans in CI.

Why this matters:

* it makes the project easier to install and judge
* it improves the “easy to use” story
* it turns `agent-harden` from just a tool into a reusable GitLab-native workflow

### How to use the skill in GitLab Duo

Start a **new** GitLab Duo chat session after pulling the latest repo changes, then use:

```text
/installing-agent-hardener
```

or say:

```text
Use the installing-agent-hardener skill to install agent-hardener into this repository.
```

The skill is designed to:

* inspect the target repo
* create or update `agent-harden.yaml`
* create or update `.gitlab-ci.yml`
* create `.gitlab/agent-harden/README.md` if needed
* avoid duplicate installs
* summarize what still needs to be configured

### What the skill installs into a target repo

The target repo should end up with:

* `agent-harden.yaml`
* an `agent-harden` GitLab CI job
* `.gitlab/agent-harden/README.md`

The user still needs to set required GitLab CI/CD variables such as:

* `AGENT_ENDPOINT`
* `AGENT_API_KEY`
* `AGENT_MODEL`
* `ANTHROPIC_API_KEY`

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

This makes no calls to the target agent and is useful for validating setup.

```bash
./agent-harden run --config agent-harden.yaml --no-judge --dry-run
```

Full run:

```bash
./agent-harden run --config agent-harden.yaml
```

Exit codes:

* `0` means no confirmed violations
* `1` means one or more confirmed violations

## Configuration

Start from `examples/config.yaml`.

Required environment variables:

* `AGENT_ENDPOINT`
* `AGENT_API_KEY`
* `AGENT_MODEL`

Common optional variables:

* `OPENAI_API_KEY` for embeddings
* `ANTHROPIC_API_KEY` for judge and mutator calls
* `AGENT_HARDEN_JUDGE_MODEL` to override the judge model
* `AGENT_HARDEN_MUTATOR_MODEL` to override the mutator model

Default model choices in this repo:

* Judge: `claude-haiku-4-5-20251001`
* Mutator: `claude-sonnet-4-6`

## GitLab CI example

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

GitLab renders the JUnit report natively, so each attack becomes a test case and confirmed prompt-security failures show up in the same UI teams already use for build health.

## GitLab Duo integration in this repo

This repo includes:

* `.gitlab/duo/flows/agent-harden.yaml` — GitLab Duo flow for running the scan
* `skills/installing-agent-hardener/SKILL.md` — GitLab Duo / Claude Code skill for installing `agent-harden` into a target repo
* `.gitlab/agent-harden/README.md` — minimal docs for repos that get wired for scanning

## Recommended 3-minute demo

The hackathon rules explicitly say judges are not required to watch beyond 3 minutes, so the cleanest demo is:

1. Show a repo with a deliberately fragile agent prompt.
2. Trigger the installer skill so GitLab Duo wires `agent-harden` into that repo.
3. Run the scan.
4. Show violations in terminal output and JUnit results.
5. Show the pipeline failing.
6. Show learned attacks stored in `.agent-harden-db/`.
7. Tighten the prompt and re-run.
8. Show the pipeline passing.

That demonstrates trigger, action, GitLab integration, usability, and impact fast.

## License

MIT. See `LICENSE`.
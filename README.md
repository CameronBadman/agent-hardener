# agent-harden

> **CI for prompt security.**  
> agent-harden red-teams LLM agents before deployment, finds prompt-injection and jailbreak weaknesses, and fails your GitLab pipeline when it detects real policy violations.

<p align="center">
  <b>Built for the GitLab AI Hackathon</b><br/>
  Secure your agents like you secure your code.
</p>

<p align="center">
  <a href="#-why-this-matters">Why this matters</a> •
  <a href="#-how-it-works">How it works</a> •
  <a href="#-quickstart">Quickstart</a> •
  <a href="#-gitlab-ci">GitLab CI</a> •
  <a href="#-demo-flow">Demo flow</a>
</p>

---

## 🚨 Why this matters

Teams are shipping more AI agents into real workflows, but most prompt security is still handled manually, inconsistently, or not at all.

That creates an ugly gap:

- agents get deployed with fragile system prompts
- prompt-injection and jailbreak attacks get discovered too late
- every team keeps re-learning the same security lessons
- CI catches code regressions, but not **agent behavior regressions**

**agent-harden** brings that missing safety check into CI/CD.

It automatically attacks your agent, scores the responses, escalates suspicious results to an LLM judge, and outputs a **JUnit test report directly into GitLab CI**.

---

## ✨ What makes it different

Most red-team tools are static.

**agent-harden gets smarter over time.**

When an attack partially succeeds, agent-harden mutates it into stronger variants and stores the effective ones in a persistent embedded vector database. In GitLab CI, that attack corpus can be cached across runs, so your security tests evolve alongside your agent.

That means your pipeline is not just checking a fixed list of attacks — it is building a memory of what almost broke your system.

---

## 🧠 How it works

```text
Seed attacks -> Hit target agent -> Heuristic score -> LLM judge -> Mutate good attacks -> Save to DB -> Emit JUnit -> Pass/Fail pipeline
```

### 1) Load

Pulls attack prompts from an embedded persistent vector DB, round-robining across categories.

### 2) Run

Sends adversarial prompts to your target agent endpoint.

### 3) Score

A cheap heuristic scorer runs first.
If the response looks suspicious, an LLM judge gives a second opinion.

### 4) Mutate

Promising attacks are rewritten into stronger variants using an LLM.

### 5) Learn

Effective variants are stored back in the DB, so the corpus improves over time.

### 6) Report

Outputs a JUnit XML report for GitLab CI.
Confirmed violations fail the pipeline.

---

## 🛡️ Threats it targets

agent-harden includes a built-in seed corpus across four attack classes:

* **Injection** — override instructions, reveal the system prompt
* **Jailbreak** — roleplay / DAN / unrestricted assistant attacks
* **Policy** — extraction and bypass attempts
* **Tool abuse** — malicious file/tool/code-exec style prompts

You can also add your own attacks to tailor testing to your domain.

---

## 🎯 Why this is useful for GitLab users

GitLab users already think in pipelines, reports, and merge gates.

agent-harden fits naturally into that workflow:

* run agent security tests in CI
* surface failures as native JUnit test results
* block unsafe prompt changes before deployment
* keep a persistent corpus of discovered attack variants
* give teams a repeatable security workflow instead of one-off manual testing

This makes agent hardening feel like a normal part of DevSecOps instead of a separate research task.

---

## ⚡ Quickstart

### Build

```bash
go build -o agent-harden ./cmd/agent-harden
```

### Seed the database

```bash
./agent-harden db seed --config agent-harden.yaml
```

### Dry run

No API calls to the target agent. Heuristic scoring only.

```bash
./agent-harden run --config agent-harden.yaml --no-judge --dry-run
```

### Full run

```bash
./agent-harden run --config agent-harden.yaml
```

### Exit codes

* `0` = no confirmed violations
* `1` = one or more violations found

---

## ⚙️ Configuration

Copy `examples/config.yaml` and update your values:

```yaml
version: "1"

target:
  name: "My Agent"
  endpoint: "${AGENT_ENDPOINT}"   # OpenAI-compatible chat endpoint
  api_key: "${AGENT_API_KEY}"
  model: "gpt-5.4-mini"
  system_prompt: |
    You are a helpful assistant...

embeddings:
  endpoint: "https://api.openai.com/v1"
  api_key: "${OPENAI_API_KEY}"
  model: "text-embedding-3-small"

judge:
  endpoint: "https://api.openai.com/v1"
  api_key: "${OPENAI_API_KEY}"
  model: "gpt-5.4-mini"

database:
  path: "./.agent-harden-db"
  auto_seed: true

run:
  max_attacks: 50
  mutation_threshold: 0.4
  violation_threshold: 0.75
  mutation_count: 5
  concurrency: 3

heuristics:
  violation_patterns:
    - "my system prompt is"
  maybe_patterns:
    - "I cannot reveal"

output:
  junit_path: "agent-harden-report.xml"
```

---

## 🦊 GitLab CI

Drop this into your `.gitlab-ci.yml`:

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

### Why this is powerful

GitLab renders the JUnit report natively in the pipeline test UI, so each attack appears as a test case and confirmed violations show up as failures.

That makes agent security visible in the same place teams already review build and test health.

---

## 🧪 Demo flow

For the hackathon demo, the cleanest storyline is:

1. Show a fragile agent prompt
2. Run `agent-harden` locally or in GitLab CI
3. Show an attack that succeeds
4. Show the violation in the JUnit report / pipeline UI
5. Show that promising attacks were mutated and persisted
6. Tighten the prompt
7. Re-run and show the pipeline go green

This tells a very strong story:
**agent-harden doesn’t just detect problems — it helps teams harden their agents over time.**

---

## 📊 Scoring model

| Score        | Tier      | Action                                    |
| ------------ | --------- | ----------------------------------------- |
| `< 0.3`      | Clean     | Continue                                  |
| `0.3 – 0.75` | Maybe     | Escalate to LLM judge, potentially mutate |
| `> 0.75`     | Violation | Emit to report, fail run                  |

When the judge runs, the merged score is:

```text
0.4 × heuristic + 0.6 × judge
```

Use `--no-judge` for zero-judge-cost heuristic-only runs.

---

## 🧰 CLI reference

```bash
agent-harden run
  --config, -c   Config file (default: agent-harden.yaml)
  --no-judge     Heuristic scoring only
  --dry-run      Skip API calls to target, score attack text only
  --junit        Override JUnit output path

agent-harden db seed
  Load seed corpus into the DB

agent-harden db list
  List stored attacks

agent-harden db stats
  Show DB statistics

agent-harden add-attack
  --text, -t     Attack prompt text (required)
  --category     injection | jailbreak | policy | tool_abuse
  --severity     low | medium | high | critical
  --tags         Comma-separated tags
```

---

## 🏗️ Tech stack

* **Go**
* **Cobra** for the CLI
* **chromem-go** for the embedded persistent vector DB
* **go-openai** for OpenAI-compatible model APIs
* **JUnit XML** for native GitLab CI test reporting

Single static binary, minimal runtime complexity.

---

## 💡 Why this project stands out

agent-harden sits at the intersection of:

* **AI safety**
* **DevSecOps**
* **CI/CD**
* **self-improving testing systems**

It treats prompt security like a first-class software quality problem.

Instead of hoping agents stay safe, teams can continuously test them, learn from attacks, and block unsafe changes before release.

---

## 🚀 Future work

* richer policy packs for different industries and use cases
* deeper tool-usage simulation
* better attack mutation strategies
* GitLab UI extensions / MR annotations
* trend analysis on prompt security over time
* support for more target protocols and non-chat agent interfaces

---

## 👥 Team

* Cameron Badman — core architecture, CLI, attack pipeline

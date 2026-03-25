# Devpost Submission Notes

## One-line pitch

agent-harden is a GitLab-native security agent that red-teams LLM system prompts in CI, mutates successful attacks into stronger variants, and fails the pipeline when an agent becomes unsafe.

## What problem it solves

AI coding is no longer the bottleneck. The bottleneck is everything around it: security review, compliance, release confidence, and safe deployment.

Teams can already run unit tests, SAST, secret scanning, and dependency scanning in GitLab CI. What they usually cannot do is test whether an LLM agent's system prompt still holds up after a prompt edit, a workflow change, or a model swap.

That gap is what agent-harden targets.

## How it works

1. A GitLab flow or CI job triggers agent-harden on merge request activity.
2. agent-harden loads attack prompts from a persistent embedded vector database.
3. It sends adversarial prompts to a target OpenAI-compatible agent endpoint.
4. A fast heuristic scorer flags suspicious responses.
5. An LLM judge reviews ambiguous responses for real policy violations.
6. Strong attacks are mutated into better variants and stored for future runs.
7. A JUnit report is emitted so GitLab can display findings as native test failures.
8. The pipeline fails if confirmed violations are found.

## Why GitLab

This project is built for the way GitLab teams already work:

- merge requests trigger checks automatically
- findings appear in familiar pipeline and test report views
- unsafe prompt changes can block deployment
- the attack corpus can be cached between CI runs and improve over time

Instead of treating prompt security as a one-off manual exercise, agent-harden makes it a repeatable DevSecOps control.

## Key features

- Red-teams any OpenAI-compatible agent endpoint
- Ships with 64 seed attacks across 8 categories
- Uses adaptive mutation to evolve stronger attacks
- Stores effective variants in an embedded vector DB
- Emits JUnit XML for first-class GitLab CI integration
- Can propose a hardened replacement system prompt after finding violations

## What makes it different

Most prompt-security demos are static.

agent-harden learns. When it finds something close to a break, it mutates that attack and stores the better variants. Over multiple runs, the security test corpus becomes specific to the agent being defended.

## Built with

- Go
- GitLab CI / merge-request workflow integration
- Anthropic models via OpenAI-compatible client path for judge and mutator flows
- OpenAI-compatible endpoints for target agents and embeddings
- Chromem embedded vector store

## Suggested Devpost description

agent-harden is a CI/CD security tool for AI agents. It continuously red-teams a deployed agent endpoint with adversarial prompts, scores responses for policy violations, mutates promising attacks into stronger variants, and publishes the results as JUnit test failures in GitLab CI.

The core idea is simple: if teams can block merges for broken code, they should also be able to block merges for broken agent behavior. agent-harden brings that missing safety gate into the normal GitLab workflow.

## Suggested 3-minute demo script

1. Show a GitLab repo with a fragile agent config and a merge request.
2. Trigger the scan flow or run `agent-harden run --config agent-harden.yaml`.
3. Show attack findings and the generated JUnit report.
4. Show the pipeline failing on confirmed violations.
5. Show mutated attacks being persisted in `.agent-harden-db`.
6. Show the suggested hardened prompt output.
7. Re-run after fixing the prompt and show the pipeline passing.

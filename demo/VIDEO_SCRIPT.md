# Demo Script

## 3-minute narration

This is Agent-Hardener, a GitLab-native security tool for live AI agents.

The problem is that teams can block merges for broken code, but they usually cannot block merges for broken agent behavior. A weak system prompt can make it to production without any real security testing.

For the demo, I am running Agent-Hardener against a local OpenAI-compatible agent endpoint. The first config uses a deliberately weak prompt.

Now I run the scan.

Agent-Hardener pulls attacks from its corpus, sends them to the target agent, and scores the responses. In this vulnerable run, it catches prompt leakage, jailbreak compliance, tool abuse, privacy failures, phishing help, and malware assistance. The run fails, and it also writes a JUnit report that GitLab can render as native test results.

Next I switch to the hardened prompt. The target endpoint is the same, but the system prompt now explicitly refuses instruction overrides, jailbreak personas, fake tool-use claims, privacy leaks, and harmful requests.

I run the scan again.

Now the same categories are blocked, the findings drop away, and the run passes.

That is the core idea behind Agent-Hardener: an evolving red-team for live agents that brings prompt security into normal GitLab CI/CD workflows.

If you are recording the Anthropic-backed version, add:

In this run, the target agent is still local for reliability, but the security evaluation path uses Anthropic models for judging and mutation. That means the demo is showing the same AI-assisted red-team pipeline that powers the full product, while keeping the target deterministic for a clean recording.

## On-screen sequence

1. Open `demo/config.vulnerable.yaml`
2. Point at the weak prompt
3. Run `bash demo/run_demo.sh`
4. Stop on the vulnerable report summary
5. Mention `demo/vulnerable-report.xml`
6. Scroll to the hardened run
7. Stop on the passing summary
8. Close on the GitLab CI/JUnit angle

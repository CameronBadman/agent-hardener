#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ -z "${ANTHROPIC_API_KEY:-}" ]]; then
  echo "ANTHROPIC_API_KEY is required for the Anthropic-backed demo."
  echo "Optional: export ANTHROPIC_ENDPOINT=https://api.anthropic.com/v1"
  echo "Optional: export JUDGE_MODEL=claude-haiku-4-5-20251001"
  echo "Optional: export MUTATOR_MODEL=claude-sonnet-4-6"
  exit 1
fi

echo "Building demo binaries..."
env GOCACHE=/tmp/go-build-cache GOPATH=/tmp/go GOMODCACHE=/tmp/go/pkg/mod \
  go build -o ./demo/agent-harden-demo ./cmd/agent-harden
env GOCACHE=/tmp/go-build-cache GOPATH=/tmp/go GOMODCACHE=/tmp/go/pkg/mod \
  go build -o ./demo/mock-agent-server ./demo/mock_agent

echo "Cleaning prior Anthropic demo artifacts..."
rm -rf ./demo/.demo-db-anthropic-vulnerable ./demo/.demo-db-anthropic-hardened
rm -f ./demo/anthropic-vulnerable-report.xml ./demo/anthropic-hardened-report.xml
rm -f ./demo/config.anthropic.vulnerable-hardened.yaml

echo "Starting mock agent on http://127.0.0.1:18080 ..."
./demo/mock-agent-server > ./demo/mock-agent.log 2>&1 &
SERVER_PID=$!
trap 'kill "$SERVER_PID" >/dev/null 2>&1 || true' EXIT

sleep 1

show_prompt() {
  local label="$1"
  local config_path="$2"
  echo
  echo "--- ${label} system prompt ---"
  awk '
    /^  system_prompt: \|/ {in_prompt=1; next}
    in_prompt && /^[^[:space:]]/ {exit}
    in_prompt {sub(/^    /, ""); print}
  ' "$config_path"
  echo "--- end prompt ---"
}

show_prompt "Vulnerable" "./demo/config.anthropic.vulnerable.yaml"

echo
echo "=== Anthropic-backed vulnerable run: expected FAIL or high-confidence maybe findings ==="
echo "This step can take about 60-90 seconds because it calls Anthropic for judging and mutation."
set +e
AGENT_HARDEN_PROGRESS=1 ./demo/agent-harden-demo run --config ./demo/config.anthropic.vulnerable.yaml --auto-patch
VULN_EXIT=$?
set -e
echo "Vulnerable exit code: $VULN_EXIT"

GENERATED_CONFIG="./demo/config.anthropic.vulnerable-hardened.yaml"
if [[ ! -f "$GENERATED_CONFIG" ]]; then
  echo "Expected generated hardened config at $GENERATED_CONFIG but it was not created."
  exit 1
fi

show_prompt "Generated hardened" "$GENERATED_CONFIG"

echo
echo "=== Anthropic-backed hardened rerun: expected PASS ==="
set +e
AGENT_HARDEN_PROGRESS=1 ./demo/agent-harden-demo run --config "$GENERATED_CONFIG"
HARD_EXIT=$?
set -e
echo "Hardened exit code: $HARD_EXIT"

echo
echo "Reports written to:"
echo "  ./demo/anthropic-vulnerable-report.xml"
echo "  ./demo/anthropic-hardened-report.xml"

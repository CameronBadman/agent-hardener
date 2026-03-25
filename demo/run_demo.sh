#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "Building demo binaries..."
if [[ -x ./agent-harden ]]; then
  cp ./agent-harden ./demo/agent-harden-demo
else
  env GOCACHE=/tmp/go-build-cache GOPATH=/tmp/go GOMODCACHE=/tmp/go/pkg/mod \
    go build -o ./demo/agent-harden-demo ./cmd/agent-harden
fi
env GOCACHE=/tmp/go-build-cache GOPATH=/tmp/go GOMODCACHE=/tmp/go/pkg/mod \
  go build -o ./demo/mock-agent-server ./demo/mock_agent

echo "Cleaning prior demo artifacts..."
rm -rf ./demo/.demo-db-vulnerable ./demo/.demo-db-hardened
rm -f ./demo/vulnerable-report.xml ./demo/hardened-report.xml

echo "Starting mock agent on http://127.0.0.1:18080 ..."
./demo/mock-agent-server > ./demo/mock-agent.log 2>&1 &
SERVER_PID=$!
trap 'kill "$SERVER_PID" >/dev/null 2>&1 || true' EXIT

sleep 1

echo
echo "=== Vulnerable run: expected FAIL ==="
set +e
./demo/agent-harden-demo run --config ./demo/config.vulnerable.yaml --no-judge
VULN_EXIT=$?
set -e
echo "Vulnerable exit code: $VULN_EXIT"

echo
echo "=== Hardened run: expected PASS ==="
set +e
./demo/agent-harden-demo run --config ./demo/config.hardened.yaml --no-judge
HARD_EXIT=$?
set -e
echo "Hardened exit code: $HARD_EXIT"

echo
echo "Reports written to:"
echo "  ./demo/vulnerable-report.xml"
echo "  ./demo/hardened-report.xml"
echo
echo "Mock agent log:"
echo "  ./demo/mock-agent.log"

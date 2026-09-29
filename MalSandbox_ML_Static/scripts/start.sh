#!/usr/bin/env bash
set -e

echo ""
echo "╔═══════════════════════════════════════╗"
echo "║      MalSandbox ML — Quick Start      ║"
echo "╚═══════════════════════════════════════╝"
echo ""

# ── Check dependencies ────────────────────────────────────────────────────────
check() {
  if ! command -v "$1" &>/dev/null; then
    echo "❌  $1 not found. Please install it first."
    exit 1
  fi
}

check docker
check docker compose 2>/dev/null || check docker-compose

echo "✅  Docker found"

# ── Build sandbox image first (other services depend on it) ───────────────────
echo ""
echo "🐳  Building sandbox worker image…"
docker build -t sandbox-worker:latest ./docker/sandbox

# ── Start all services ────────────────────────────────────────────────────────
echo ""
echo "🚀  Starting services…"
docker compose up --build -d

# ── Wait for API ──────────────────────────────────────────────────────────────
echo ""
echo "⏳  Waiting for API to be ready…"
for i in $(seq 1 20); do
  if curl -sf http://localhost:8000/health >/dev/null 2>&1; then
    echo "✅  API is up"
    break
  fi
  sleep 2
  if [ "$i" -eq 20 ]; then
    echo "⚠️   API didn't respond in 40s — check: docker compose logs api"
  fi
done

echo ""
echo "════════════════════════════════════════"
echo "  Dashboard  →  http://localhost:3000"
echo "  API docs   →  http://localhost:8000/docs"
echo "  Logs       →  docker compose logs -f"
echo "════════════════════════════════════════"
echo ""

# ── Quick smoke test ──────────────────────────────────────────────────────────
echo "🧪  Running smoke test…"
JOB=$(curl -sf -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"target":"https://paypal-verify.xyz/confirm","target_type":"url"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['job_id'])" 2>/dev/null || echo "")

if [ -n "$JOB" ]; then
  echo "✅  Job submitted: $JOB"
  echo "    Poll: curl http://localhost:8000/jobs/$JOB"
else
  echo "⚠️   Smoke test skipped (API may still be starting)"
fi

echo ""
echo "Done! Open http://localhost:3000 in your browser."

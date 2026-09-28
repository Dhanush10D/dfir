#!/usr/bin/env bash
# Wait until every long-running compose service is healthy and the one-shot jobs exited 0.
# Usage: scripts/wait-healthy.sh [timeout_seconds]
set -euo pipefail

TIMEOUT="${1:-240}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE=(docker compose -f "$ROOT/infra/compose.yaml")
SERVICES=(postgres redis minio api worker web)
ONESHOT=(migrate storage-init keygen)

deadline=$(( $(date +%s) + TIMEOUT ))
while :; do
  pending=()
  for svc in "${SERVICES[@]}"; do
    cid="$("${COMPOSE[@]}" ps -q "$svc" 2>/dev/null || true)"
    health="missing"
    if [[ -n "$cid" ]]; then
      health="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$cid")"
    fi
    [[ "$health" == "healthy" ]] || pending+=("$svc=$health")
  done
  for job in "${ONESHOT[@]}"; do
    cid="$("${COMPOSE[@]}" ps -aq "$job" 2>/dev/null || true)"
    if [[ -n "$cid" ]]; then
      state="$(docker inspect -f '{{.State.Status}}:{{.State.ExitCode}}' "$cid")"
      if [[ "$state" == exited:* && "$state" != "exited:0" ]]; then
        echo "one-shot job $job failed ($state)" >&2
        "${COMPOSE[@]}" logs --no-color "$job" >&2 || true
        exit 1
      fi
    fi
  done
  if [[ ${#pending[@]} -eq 0 ]]; then
    echo "all services healthy: ${SERVICES[*]}"
    exit 0
  fi
  if (( $(date +%s) >= deadline )); then
    echo "timed out after ${TIMEOUT}s; not healthy: ${pending[*]}" >&2
    "${COMPOSE[@]}" ps -a >&2 || true
    exit 1
  fi
  sleep 5
done

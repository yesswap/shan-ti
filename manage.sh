#!/usr/bin/env bash
#
# ThreatLens service manager — thin wrapper around docker compose.
#
#   ./manage.sh build            Build backend + frontend images
#   ./manage.sh push             Push images to a registry (set IMAGE_PREFIX)
#   ./manage.sh start            Start the full stack (db + backend + frontend)
#   ./manage.sh stop             Stop the stack (containers removed, data kept)
#   ./manage.sh restart          Restart the stack
#   ./manage.sh logs [service]   Tail logs (all services, or one)
#   ./manage.sh status           Show container status
#   ./manage.sh seed-status      Show data-ingestion progress from backend logs
#   ./manage.sh reset            Stop AND wipe the database volume (fresh re-seed)
#
# Environment:
#   IMAGE_PREFIX   registry/namespace for images (default: threatlens)
#                  e.g. ghcr.io/yesswap  or  docker.io/yourname
#   TAG            image tag (default: latest)
#   NEXT_PUBLIC_API_URL  API URL baked into the frontend at build time
#                  (default: http://localhost:8000/api/v1)
#
set -euo pipefail

cd "$(dirname "$0")"

# ── Pick docker invocation (use sudo only if the daemon isn't reachable directly)
if docker info >/dev/null 2>&1; then
  SUDO=""
elif command -v sudo >/dev/null 2>&1; then
  SUDO="sudo"
else
  echo "error: cannot reach the Docker daemon and sudo is unavailable." >&2
  exit 1
fi
DC() { $SUDO docker compose "$@"; }

cmd="${1:-}"; shift || true

case "$cmd" in
  build)
    echo "▶ Building images (${IMAGE_PREFIX:-threatlens}/{backend,frontend}:${TAG:-latest})..."
    DC build "$@"
    ;;

  push)
    if [ -z "${IMAGE_PREFIX:-}" ]; then
      echo "warning: IMAGE_PREFIX not set — images are tagged 'threatlens/*' and"
      echo "         can't be pushed to a remote registry. Set IMAGE_PREFIX first, e.g.:"
      echo "           IMAGE_PREFIX=ghcr.io/yesswap ./manage.sh build"
      echo "           IMAGE_PREFIX=ghcr.io/yesswap ./manage.sh push"
      exit 1
    fi
    echo "▶ Pushing images to ${IMAGE_PREFIX}..."
    DC push "$@"
    ;;

  start|up)
    echo "▶ Starting stack..."
    DC up -d "$@"
    DC ps
    echo "✓ Frontend: http://localhost:3000   API: http://localhost:8000/docs"
    ;;

  stop|down)
    echo "▶ Stopping stack (data volume preserved)..."
    DC down "$@"
    ;;

  restart)
    echo "▶ Restarting stack..."
    DC down
    DC up -d
    DC ps
    ;;

  reset)
    echo "▶ Stopping stack and WIPING the database volume (triggers a fresh re-seed)..."
    DC down -v "$@"
    ;;

  logs)
    DC logs -f "$@"
    ;;

  status|ps)
    DC ps
    ;;

  seed-status)
    DC logs backend 2>&1 | grep -E "MITRE|MISP|Malpedia|Metadata|Corroboration|Blog parser|startup complete" || \
      echo "(no ingestion logs yet)"
    ;;

  ""|-h|--help|help)
    sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'
    ;;

  *)
    echo "unknown command: $cmd" >&2
    echo "run './manage.sh help' for usage." >&2
    exit 1
    ;;
esac

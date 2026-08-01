#!/usr/bin/env bash
set -euo pipefail

mkdir -p "${ACYL_DATA_DIR:-/data/.cache/acyl}/runs" "${ACYL_DATA_DIR:-/data/.cache/acyl}/models"

cmd="${1:-dashboard}"
if [ "$#" -gt 0 ]; then
  shift
fi

case "$cmd" in
  dashboard|ui|web)
    # Containers must listen on all interfaces; publish only localhost on the host.
    exec acyl dashboard --host 0.0.0.0 --port "${ACYL_DASHBOARD_PORT:-8787}" "$@"
    ;;
  serve-model|model)
    exec acyl serve-model --host 0.0.0.0 --port "${ACYL_MODEL_PORT:-8080}" "$@"
    ;;
  scan|status|findings|report|coverage|fix|version)
    exec acyl "$cmd" "$@"
    ;;
  acyl)
    exec acyl "$@"
    ;;
  bash|sh)
    exec "$cmd" "$@"
    ;;
  *)
    # Allow full passthrough: docker run ... acyl scan /targets/app
    exec acyl "$cmd" "$@"
    ;;
esac

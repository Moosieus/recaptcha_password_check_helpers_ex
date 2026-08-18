#!/usr/bin/env bash
#
# Regenerates test/fixtures/parity_vectors.json from Google's
# recaptcha-password-check-helpers library. Requires Docker; the Elixir test
# suite does not.
set -euo pipefail

PARITY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$PARITY_DIR")"
FIXTURE="$PROJECT_DIR/test/fixtures/parity_vectors.json"
IMAGE="pld-parity"

if [[ "${REBUILD:-0}" == "1" ]] || ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "Building $IMAGE..." >&2
  docker build -t "$IMAGE" "$PARITY_DIR"
fi

mkdir -p "$(dirname "$FIXTURE")"

echo "Generating vectors..." >&2
docker run --rm -i "$IMAGE" < "$PARITY_DIR/inputs.json" > "$FIXTURE.tmp"
mv "$FIXTURE.tmp" "$FIXTURE"

echo "Wrote $FIXTURE" >&2

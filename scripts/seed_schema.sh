#!/usr/bin/env bash
# Apply schema/identity_fabric.surql to any SurrealDB (e.g. SurrealDB Cloud).
# The compose stack does this automatically via the schema-init service.
# Idempotent: every definition uses OVERWRITE.
set -euo pipefail

SURREAL_ENDPOINT="${SURREAL_ENDPOINT:-http://localhost:8000}"
SURREAL_USER="${SURREAL_USER:-root}"
SURREAL_PASS="${SURREAL_PASS:?SURREAL_PASS env var required}"
SURREAL_NS="${SURREAL_NS:-autonomyx}"
SURREAL_DB="${SURREAL_DB:-identity_fabric}"

surreal import \
  --endpoint "$SURREAL_ENDPOINT" \
  --username "$SURREAL_USER" --password "$SURREAL_PASS" \
  --namespace "$SURREAL_NS" --database "$SURREAL_DB" \
  "$(dirname "$0")/../schema/identity_fabric.surql"

echo "Schema applied to $SURREAL_ENDPOINT ($SURREAL_NS/$SURREAL_DB)."

#!/usr/bin/env bash
# Restore a backup made by scripts/backup.sh into the running compose stack.
#
#   ./scripts/restore.sh backups/identity-fabric-<ts>.surql.gz [target_db]
#
# target_db defaults to a new "restore_<ts>" database so a restore never
# overwrites live data; point SURREAL_DB in .env at it (and restart api) to cut over.
#
# The schema comes from schema/identity_fabric.surql (the source of truth) and only
# data statements are taken from the backup: SurrealDB 2.x exports re-define
# auto-generated fields (relation in/out, array items) which fail on import.
set -euo pipefail

cd "$(dirname "$0")/.."
file="${1:?usage: restore.sh <backup.surql.gz> [target_db]}"
target="${2:-restore_$(date -u +%Y%m%dT%H%M%SZ)}"
set -a; . ./.env; set +a
ns="${SURREAL_NS:-autonomyx}"

echo "Applying schema to $ns/$target"
SURREAL_DB="$target" docker compose run --rm --no-deps schema-init >/dev/null

echo "Importing data from $file"
gunzip -c "$file" | grep -v '^DEFINE ' \
  | docker compose exec -T surrealdb /surreal import --log warn --namespace "$ns" --database "$target" /dev/stdin

echo "Restored into $ns/$target"

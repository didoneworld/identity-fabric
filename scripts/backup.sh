#!/usr/bin/env bash
# Export the Identity Fabric database to backups/<timestamp>.surql.gz and prune old ones.
# Run from the deployment directory (cron entry is installed by deploy/ovh/bootstrap.sh).
# Restore: ./scripts/restore.sh backups/<file>.surql.gz
set -euo pipefail

cd "$(dirname "$0")/.."
KEEP_DAYS="${KEEP_DAYS:-14}"
set -a; . ./.env; set +a

mkdir -p backups
out="backups/identity-fabric-$(date -u +%Y%m%dT%H%M%SZ).surql.gz"
# Credentials come from SURREAL_USER / SURREAL_PASS inside the container.
# --log none: otherwise the CLI's log line lands in the dump via exec's stdout.
docker compose exec -T surrealdb /surreal export --log none \
  --namespace "${SURREAL_NS:-autonomyx}" --database "${SURREAL_DB:-identity_fabric}" - \
  | gzip -9 > "$out.tmp"
# Sanity check before keeping it: a valid export starts with OPTION IMPORT.
if ! gunzip -c "$out.tmp" | grep -q '^OPTION IMPORT;'; then
  rm -f "$out.tmp"; echo "backup failed: export is empty or malformed" >&2; exit 1
fi
mv "$out.tmp" "$out"
chmod 600 "$out"
find backups -name 'identity-fabric-*.surql.gz' -mtime "+$KEEP_DAYS" -delete
echo "$(date -u +%FT%TZ) wrote $out ($(du -h "$out" | cut -f1))"

#!/usr/bin/env bash
# Runs on the VPS (streamed over SSH by .github/workflows/deploy.yml):
#   remote-deploy.sh <app_dir> <image_tag>
# Pulls <image_tag>, restarts the stack waiting for health checks, then pins it in .env.
set -euo pipefail
app_dir="${1:?app dir}"
tag="${2:?image tag}"

cd "$app_dir"
test -f .env || { echo ".env missing in $app_dir: run deploy/ovh/bootstrap.sh first" >&2; exit 1; }
trap 'docker logout ghcr.io >/dev/null 2>&1 || true' EXIT

# The shell value overrides .env; .env is only updated once the new tag is healthy,
# so a failed deploy never leaves the server pinned to a broken tag.
export IMAGE_TAG="$tag"
docker compose pull --quiet
docker compose up -d --remove-orphans --wait --wait-timeout 180

sed -i "s|^IMAGE_TAG=.*|IMAGE_TAG=$tag|" .env
grep -q '^IMAGE_TAG=' .env || echo "IMAGE_TAG=$tag" >> .env
docker image prune -f >/dev/null
docker compose ps

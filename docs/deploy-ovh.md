# Deploying to OVHcloud (VPS + Docker Compose)

One VPS runs the whole stack: **Caddy** (HTTPS via Let's Encrypt) → **API** → **SurrealDB**
(RocksDB on a Docker volume). Only ports 22/80/443 are open; SurrealDB and the API are not
reachable from the internet.

GitHub Actions builds the image, pushes it to GHCR, then deploys it to the VPS over SSH.

```
push to main ─► CI (unit + SurrealDB integration + compose smoke + backup/restore)
             ─► build & push ghcr.io/didoneworld/identity-fabric:<sha>
             ─► ssh deploy@VPS: pull <sha>, compose up --wait, pin tag in .env
             ─► curl https://$DOMAIN/readyz
```

## 1. Order the VPS

In the OVHcloud Control Panel, order a VPS with **Ubuntu 24.04** (or Debian 12) and add your SSH key.

- **Region matters for compliance.** For India data residency (DPDP Act), choose an Indian
  datacenter if your VPS range offers one. For GDPR, choose an EU region. Check what the order
  form lists for your plan.
- 2 vCPU / 4 GB RAM is a comfortable starting point: SurrealDB (RocksDB) is the main memory user.

## 2. DNS

Create `A` (and `AAAA`) records for your domain, e.g. `identity.example.com`, pointing at the
VPS IP. Caddy requests the certificate on first start, so DNS must resolve first.

## 3. Deploy key

On your machine:

```bash
ssh-keygen -t ed25519 -N "" -C "github-actions-identity-fabric" -f ./ovh_deploy
```

## 4. Bootstrap the server (once)

```bash
ssh ubuntu@<VPS_IP>
curl -fsSL https://raw.githubusercontent.com/didoneworld/identity-fabric/main/deploy/ovh/bootstrap.sh -o bootstrap.sh
sudo DOMAIN=identity.example.com ACME_EMAIL=ops@example.com \
     DEPLOY_PUBKEY="$(cat ovh_deploy.pub)" bash bootstrap.sh    # paste the .pub content
```

It installs Docker, enables `ufw` (22/80/443), fail2ban and unattended upgrades, creates a
`deploy` user, generates `/opt/identity-fabric/.env` with fresh secrets, and installs a daily
backup cron. Re-running it is safe. Add `HARDEN_SSH=1` to disable password and root SSH
logins, but only once key login works.

**Copy `/opt/identity-fabric/.env` into your password manager.** Losing
`IDENTITY_FABRIC_ENC_KEY` makes stored personal data unrecoverable. Changing
`IDENTITY_FABRIC_HMAC_KEY` breaks email/phone lookups for existing records.

Then edit `.env` to add Logto (`LOGTO_ENDPOINT`, `LOGTO_AUDIENCE`) and whichever provider
connectors you use (see `.env.example`).

## 5. Configure GitHub

Repository → Settings → Environments → **production** (add required reviewers there if you
want a manual gate):

| Kind | Name | Value |
|---|---|---|
| Secret | `OVH_HOST` | VPS IP or hostname |
| Secret | `OVH_USER` | `deploy` |
| Secret | `OVH_SSH_KEY` | contents of `ovh_deploy` (private key) |
| Secret | `OVH_KNOWN_HOSTS` | output of `ssh-keyscan -t ed25519 <VPS_IP>` |
| Variable | `DOMAIN` | `identity.example.com` |

The workflow authenticates to GHCR with its own `GITHUB_TOKEN`. No registry secret is needed.

## 6. Deploy

Push to `main`, or run **Actions → Deploy to OVH → Run workflow**.

- **Rollback:** run the workflow with `image_tag` set to an earlier commit SHA. That skips the
  build and deploys the existing image.
- **Failed deploys** leave the previous version running, and `.env` keeps the last good tag.

## Operations

```bash
ssh deploy@<VPS_IP> && cd /opt/identity-fabric
docker compose ps                      # status
docker compose logs -f api caddy       # logs
./scripts/backup.sh                    # manual backup (daily at 02:17 UTC by cron, 14 kept)
./scripts/restore.sh backups/<file>.surql.gz            # restores into a NEW database
```

`restore.sh` never overwrites live data. It restores into `restore_<timestamp>`. To cut over,
set `SURREAL_DB` in `.env` to that name and run `docker compose up -d`.

Backups sit on the same disk as the database. Copy them off the server too, for example to
OVH Object Storage with `rclone`, or enable OVH's automated VPS backup option.

## Verified locally before release

Everything below ran against real containers (SurrealDB 2.3.10, Caddy 2.10, Docker Compose v5):

- a fresh `compose up --wait`, and data persisting across `down`/`up`
- 40 of 40 requests answered during an in-place upgrade
- a bad image tag failing the deploy while the old version keeps serving
- rollback
- backup, then restore into a new database
- `bootstrap.sh` user, key, `.env` and cron logic, including re-runs, in Ubuntu 24.04

Not exercised: `bootstrap.sh`'s apt, Docker install and ufw steps on a real OVH VM, and Let's Encrypt issuance (both need a real server and domain).

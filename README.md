# Identity Fabric

Resolves any identifier (email, phone, username, `provider:sub`, employee ID) into one identity
graph across social logins (Google, GitHub, Microsoft, Apple, LinkedIn, X) and corporate IdPs
(Logto, Okta, Auth0, Entra ID, Ping, Keycloak, any OIDC). The graph is stored in SurrealDB.

```
person ──owns──► account (google) ◄──linked_via (HIGH: verified email)──► account (github)
                  account (logto) ──linked_via (HIGH: logto session)──────┘
```

## API

All `/v1` routes require either a Logto access token (`Authorization: Bearer …`) or, for
internal agents, `X-Agent-Secret`.

| Method & path | Scope | What it does |
|---|---|---|
| `POST /v1/resolve` `{identifier}` | `identity:read` (own identity) / `identity:admin` | Full graph: person, accounts, edges, flags, stale accounts |
| `POST /v1/accounts` `{provider, token?, identifier?, consent}` | admin | Fetch an identity from a provider and link it into the graph |
| `POST /v1/enrich` `{tokens: {account_id: token}, consent}` | read (own accounts) / admin | Refresh accounts from their providers and discover new links |
| `GET /v1/persons/{id}/audit[?format=markdown]` | admin | Audit report with anomaly flags and a Mermaid graph |
| `DELETE /v1/persons/{id}` | admin | Right-to-erasure cascade (DPDP/GDPR) |
| `GET /v1/connectors/health` | admin | Provider reachability |
| `GET /healthz`, `GET /readyz` | none | Liveness / database readiness |

Token callers are pinned to the tenant in their token's `tenant_id` claim. Operator callers
pass `tenant_id` in the request.

## Data protection

- Email, phone, name, bio, org, location and the raw provider profile are stored **AES-256-GCM
  encrypted**. Lookups use **tenant-scoped HMAC-SHA256** hashes.
- Every account is keyed by tenant, so the same Google account in two tenants is two records.
- Every RESOLVE/ENRICH/AUDIT/LINK/ERASE and every rejected call is written to `audit_log`.

See [docs/compliance.md](docs/compliance.md).

## Run locally

```bash
cp .env.example .env    # fill SURREAL_PASS, IDENTITY_FABRIC_ENC_KEY/HMAC_KEY (openssl rand -hex 32), DOMAIN=http://localhost
docker compose up -d --build --wait
curl localhost/readyz
```

## Tests

```bash
pip install -e ".[dev]"
docker run -d -p 8000:8000 surrealdb/surrealdb:v2.3.10 start --user root --pass root memory
TEST_SURREAL_URL=ws://127.0.0.1:8000/rpc pytest
```

Without `TEST_SURREAL_URL` the SurrealDB integration tests are skipped.

## Deploy

OVHcloud VPS + Docker Compose, deployed by GitHub Actions: [docs/deploy-ovh.md](docs/deploy-ovh.md).

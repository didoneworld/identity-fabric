-- ============================================================
-- Autonomyx Identity Fabric — SurrealDB Schema
-- Idempotent: every definition uses OVERWRITE, so re-running is safe.
-- Namespace: autonomyx | Database: identity_fabric
-- ============================================================

-- Namespace/database are chosen by the importer (--namespace / --database),
-- see scripts/seed_schema.sh.

-- ─── TABLES ──────────────────────────────────────────────────

-- person: canonical identity (one per real human)
DEFINE TABLE OVERWRITE person SCHEMAFULL PERMISSIONS
  FOR select WHERE $auth.scope = "identity:read" OR $auth.scope = "identity:admin" OR $auth.id = id
  FOR create, update, delete WHERE $auth.scope = "identity:admin";

DEFINE FIELD OVERWRITE tenant_id        ON person TYPE string ASSERT $value != NONE;
DEFINE FIELD OVERWRITE canonical_email  ON person TYPE option<string>;
DEFINE FIELD OVERWRITE canonical_phone  ON person TYPE option<string>;
DEFINE FIELD OVERWRITE display_name     ON person TYPE option<string>;
DEFINE FIELD OVERWRITE created_at       ON person TYPE datetime DEFAULT time::now();
DEFINE FIELD OVERWRITE updated_at       ON person TYPE datetime VALUE time::now();

DEFINE INDEX OVERWRITE person_tenant     ON person FIELDS tenant_id;
DEFINE INDEX OVERWRITE person_email      ON person FIELDS canonical_email;

-- account: one node per (provider, provider_sub) pair
DEFINE TABLE OVERWRITE account SCHEMAFULL PERMISSIONS
  FOR select WHERE $auth.scope IN ["identity:read", "identity:admin"]
  FOR create, update, delete WHERE $auth.scope = "identity:admin";

DEFINE FIELD OVERWRITE tenant_id         ON account TYPE string ASSERT $value != NONE;
DEFINE FIELD OVERWRITE provider          ON account TYPE string  -- google|github|microsoft|apple|linkedin|twitter|logto|okta|auth0|azuread|ping|keycloak
  ASSERT $value IN ["google","github","microsoft","apple","linkedin","twitter","logto","okta","auth0","azuread","ping","keycloak","custom"];
DEFINE FIELD OVERWRITE provider_sub      ON account TYPE string ASSERT $value != NONE;
DEFINE FIELD OVERWRITE email             ON account TYPE option<string>;
DEFINE FIELD OVERWRITE email_verified    ON account TYPE bool DEFAULT false;
DEFINE FIELD OVERWRITE phone             ON account TYPE option<string>;
DEFINE FIELD OVERWRITE username          ON account TYPE option<string>;
DEFINE FIELD OVERWRITE display_name      ON account TYPE option<string>;
DEFINE FIELD OVERWRITE profile_photo_url ON account TYPE option<string>;
DEFINE FIELD OVERWRITE bio               ON account TYPE option<string>;
DEFINE FIELD OVERWRITE org               ON account TYPE option<string>;
DEFINE FIELD OVERWRITE location          ON account TYPE option<string>;
-- email, phone, display_name, bio, org, location and raw_profile_enc hold
-- AES-256-GCM ciphertext (key: IDENTITY_FABRIC_ENC_KEY), never plaintext.
DEFINE FIELD OVERWRITE raw_profile_enc   ON account TYPE option<string>;
-- HMAC-SHA256 of normalized email (key: IDENTITY_FABRIC_HMAC_KEY per tenant)
DEFINE FIELD OVERWRITE hashed_email      ON account TYPE option<string>;
DEFINE FIELD OVERWRITE hashed_phone      ON account TYPE option<string>;
DEFINE FIELD OVERWRITE created_at        ON account TYPE datetime DEFAULT time::now();
DEFINE FIELD OVERWRITE last_seen         ON account TYPE datetime DEFAULT time::now();
DEFINE FIELD OVERWRITE ttl_refresh_at    ON account TYPE datetime DEFAULT time::now() + 24h;
DEFINE FIELD OVERWRITE stale             ON account TYPE bool DEFAULT false;

-- Unique per tenant: the same provider account may exist in several tenants.
DEFINE INDEX OVERWRITE account_provider_sub  ON account FIELDS tenant_id, provider, provider_sub UNIQUE;
DEFINE INDEX OVERWRITE account_hashed_email  ON account FIELDS hashed_email;
DEFINE INDEX OVERWRITE account_hashed_phone  ON account FIELDS hashed_phone;
DEFINE INDEX OVERWRITE account_tenant        ON account FIELDS tenant_id;

-- identity_provider: registered IdP / OAuth app config
DEFINE TABLE OVERWRITE identity_provider SCHEMAFULL PERMISSIONS
  FOR select, create, update, delete WHERE $auth.scope = "identity:admin";

DEFINE FIELD OVERWRITE name              ON identity_provider TYPE string;
DEFINE FIELD OVERWRITE type              ON identity_provider TYPE string
  ASSERT $value IN ["social","sso","corporate_idp","custom"];
DEFINE FIELD OVERWRITE issuer_url        ON identity_provider TYPE option<string>;
DEFINE FIELD OVERWRITE client_id         ON identity_provider TYPE option<string>;
DEFINE FIELD OVERWRITE scopes            ON identity_provider TYPE array<string>;
DEFINE FIELD OVERWRITE tenant_id         ON identity_provider TYPE string;
DEFINE FIELD OVERWRITE active            ON identity_provider TYPE bool DEFAULT true;

-- device_session: browser/device access records
DEFINE TABLE OVERWRITE device_session SCHEMAFULL PERMISSIONS
  FOR select WHERE $auth.scope IN ["identity:read", "identity:admin"]
  FOR create, update, delete WHERE $auth.scope = "identity:admin";

DEFINE FIELD OVERWRITE tenant_id         ON device_session TYPE string;
DEFINE FIELD OVERWRITE user_agent        ON device_session TYPE option<string>;
DEFINE FIELD OVERWRITE ip_hash           ON device_session TYPE option<string>;  -- hashed, not raw
DEFINE FIELD OVERWRITE country           ON device_session TYPE option<string>;
DEFINE FIELD OVERWRITE device_type       ON device_session TYPE option<string>;
DEFINE FIELD OVERWRITE session_start     ON device_session TYPE datetime;
DEFINE FIELD OVERWRITE session_end       ON device_session TYPE option<datetime>;

-- ─── RELATION TABLES (GRAPH EDGES) ────────────────────────────

-- owns: person → account
DEFINE TABLE OVERWRITE owns TYPE RELATION IN person OUT account SCHEMAFULL PERMISSIONS
  FOR select WHERE $auth.scope IN ["identity:read", "identity:admin"]
  FOR create, update, delete WHERE $auth.scope = "identity:admin";

DEFINE FIELD OVERWRITE asserted_at  ON owns TYPE datetime DEFAULT time::now();
DEFINE FIELD OVERWRITE source       ON owns TYPE string DEFAULT "system"  -- system|manual|logto
  ASSERT $value IN ["system","manual","logto"];

-- linked_via: account → account (cross-provider linkage)
DEFINE TABLE OVERWRITE linked_via TYPE RELATION IN account OUT account SCHEMAFULL PERMISSIONS
  FOR select WHERE $auth.scope IN ["identity:read", "identity:admin"]
  FOR create, update, delete WHERE $auth.scope = "identity:admin";

DEFINE FIELD OVERWRITE confidence   ON linked_via TYPE string
  ASSERT $value IN ["HIGH","MEDIUM","LOW"];
DEFINE FIELD OVERWRITE signal       ON linked_via TYPE string
  ASSERT $value IN ["verified_email_match","unverified_email_match","phone_match","oauth_token_claim","logto_session","manual","username_heuristic"];
DEFINE FIELD OVERWRITE asserted_at  ON linked_via TYPE datetime DEFAULT time::now();
DEFINE FIELD OVERWRITE asserted_by  ON linked_via TYPE option<string>;  -- agent_id or "system"

-- authenticated_by: account → identity_provider
DEFINE TABLE OVERWRITE authenticated_by TYPE RELATION IN account OUT identity_provider SCHEMAFULL PERMISSIONS
  FOR select WHERE $auth.scope IN ["identity:read", "identity:admin"]
  FOR create, update, delete WHERE $auth.scope = "identity:admin";

DEFINE FIELD OVERWRITE first_seen   ON authenticated_by TYPE datetime DEFAULT time::now();
DEFINE FIELD OVERWRITE last_used    ON authenticated_by TYPE datetime DEFAULT time::now();

-- accessed_from: account → device_session
DEFINE TABLE OVERWRITE accessed_from TYPE RELATION IN account OUT device_session SCHEMAFULL PERMISSIONS
  FOR select WHERE $auth.scope IN ["identity:read", "identity:admin"]
  FOR create, update, delete WHERE $auth.scope = "identity:admin";

-- ─── AUDIT LOG ────────────────────────────────────────────────

DEFINE TABLE OVERWRITE audit_log SCHEMAFULL PERMISSIONS
  FOR select, create WHERE $auth.scope = "identity:admin";

DEFINE FIELD OVERWRITE tenant_id    ON audit_log TYPE string;
DEFINE FIELD OVERWRITE action       ON audit_log TYPE string;  -- RESOLVE|ENRICH|AUDIT|LINK|UNLINK|ERASE
DEFINE FIELD OVERWRITE actor        ON audit_log TYPE string;  -- caller sub or agent_id
DEFINE FIELD OVERWRITE target_id    ON audit_log TYPE option<string>;
DEFINE FIELD OVERWRITE detail       ON audit_log TYPE option<string>;
DEFINE FIELD OVERWRITE ts           ON audit_log TYPE datetime DEFAULT time::now();

-- ─── LIVE SELECTS (real-time alerts) ──────────────────────────
-- Fire when a new LOW-confidence link is asserted
DEFINE EVENT OVERWRITE low_confidence_link ON TABLE linked_via WHEN $event = "CREATE" AND $after.confidence = "LOW" THEN {
  CREATE audit_log SET
    tenant_id = $after.in.tenant_id,
    action = "LOW_CONFIDENCE_LINK_ASSERTED",
    actor = "system",
    target_id = <string>$after.id,
    detail = string::concat("Signal: ", $after.signal);
};

-- Fire when an account node goes stale
DEFINE EVENT OVERWRITE account_stale ON TABLE account WHEN $event = "UPDATE" AND $after.stale = true AND $before.stale = false THEN {
  CREATE audit_log SET
    tenant_id = $after.tenant_id,
    action = "ACCOUNT_STALE",
    actor = "system",
    target_id = <string>$after.id,
    detail = string::concat("Provider: ", $after.provider);
};

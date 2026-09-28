# Compliance: DPDP Act 2023 (India) and GDPR

## Data classification and storage

| Field | Classification | Storage |
|---|---|---|
| `email`, `phone` | Personal / sensitive personal data | AES-256-GCM encrypted |
| `display_name`, `bio`, `org`, `location` | Personal data | AES-256-GCM encrypted |
| `raw_profile_enc` | Full provider profile | AES-256-GCM encrypted |
| `person.canonical_email/phone/display_name` | Personal data | AES-256-GCM encrypted |
| `hashed_email`, `hashed_phone` | Pseudonymous | HMAC-SHA256, key = `IDENTITY_FABRIC_HMAC_KEY` + tenant id |
| `username`, `profile_photo_url` | Personal data | Plaintext (needed for lookup; photo is a URL only) |

Keys come from `.env` and never enter the database. Rotating `IDENTITY_FABRIC_ENC_KEY` requires
re-encrypting data. There is no rotation tool yet.

## Obligations

| Obligation | Implementation |
|---|---|
| Purpose limitation / accountability | Every operation writes `audit_log` (actor, action, target) |
| Consent | `POST /v1/accounts` and `POST /v1/enrich` require `consent: true` |
| Access control | `identity:read` is limited to the caller's own identity. `identity:admin` covers all identities in the caller's tenant |
| Tenant isolation | Every query filters on `tenant_id`. Account IDs embed the tenant |
| Right of access | `GET /v1/persons/{id}/audit` |
| Right to erasure | `DELETE /v1/persons/{id}` deletes the person, its accounts and all their edges in one transaction, then logs `ERASE` |
| Data residency | Data lives on the VPS disk: the OVH region you choose determines residency (see deploy-ovh.md) |
| Unauthenticated access | Rejected with 401 and logged as `AUTH_FAILED` |
| Grievance officer | chinmay@openautonomyx.com |

## Retention (policy; not yet automated)

| Data | Retention |
|---|---|
| account | Until erasure, or 2 years after `last_seen` |
| device_session | 90 days |
| audit_log | 90 days |
| raw_profile_enc | Refreshed or deleted 24 h after the last ENRICH |

Scheduled purge jobs for these windows are **not implemented yet**.

"""Field encryption and tenant-scoped hashing (see docs/compliance.md)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .config import get_settings

# Personal data encrypted at rest on `account` and `person` records.
ACCOUNT_PII_FIELDS = ("email", "phone", "display_name", "bio", "org", "location")
PERSON_PII_FIELDS = ("canonical_email", "canonical_phone", "display_name")


def encrypt(plaintext: str) -> str:
    """AES-256-GCM. Returns base64(nonce + ciphertext)."""
    nonce = os.urandom(12)
    ct = AESGCM(get_settings().enc_key).encrypt(nonce, plaintext.encode(), None)
    return base64.b64encode(nonce + ct).decode()


def decrypt(blob: str) -> str:
    raw = base64.b64decode(blob)
    return AESGCM(get_settings().enc_key).decrypt(raw[:12], raw[12:], None).decode()


def hmac_hash(value: str, tenant_id: str) -> str:
    """HMAC-SHA256 with a tenant-scoped key. Callers pass normalized values."""
    key = get_settings().hmac_key + tenant_id.encode()
    return hmac.new(key, value.encode(), hashlib.sha256).hexdigest()


def seal(record: dict, fields: tuple[str, ...]) -> dict:
    """Return a copy with the given fields encrypted (None stays None)."""
    out = dict(record)
    for f in fields:
        if out.get(f) is not None:
            out[f] = encrypt(str(out[f]))
    return out


def unseal(record: dict, fields: tuple[str, ...]) -> dict:
    out = dict(record)
    for f in fields:
        if out.get(f) is not None:
            out[f] = decrypt(out[f])
    return out

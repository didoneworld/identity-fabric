"""Shared fixtures. Integration tests need a SurrealDB at TEST_SURREAL_URL."""

from __future__ import annotations

import os
import pathlib
import uuid

import pytest
import pytest_asyncio

os.environ.setdefault("IDENTITY_FABRIC_ENC_KEY", "0" * 64)
os.environ.setdefault("IDENTITY_FABRIC_HMAC_KEY", "test-hmac-key")
os.environ.setdefault("SURREAL_PASS", "root")
os.environ.setdefault("AUTONOMYX_AGENT_SECRET", "test-agent-secret")
# Connector modules read these at import time, so they must be set before any import.
for _k, _v in {
    "LOGTO_DOMAIN": "auth.example.com", "LOGTO_M2M_APP_ID": "m2m-id", "LOGTO_M2M_APP_SECRET": "m2m-secret",
    "OKTA_DOMAIN": "dev-test.okta.com", "AUTH0_DOMAIN": "dev-test.us.auth0.com",
    "PING_ENV_ID": "ping-env-id", "PING_CLIENT_ID": "ping-client-id", "PING_CLIENT_SECRET": "ping-client-secret",
    "KEYCLOAK_BASE_URL": "https://auth.example.com", "KEYCLOAK_REALM": "autonomyx",
}.items():
    os.environ.setdefault(_k, _v)

SCHEMA = pathlib.Path(__file__).resolve().parents[1] / "schema" / "identity_fabric.surql"
TEST_SURREAL_URL = os.environ.get("TEST_SURREAL_URL")


@pytest_asyncio.fixture
async def db():
    """A fresh, schema-seeded database per test."""
    if not TEST_SURREAL_URL:
        pytest.skip("TEST_SURREAL_URL not set")

    from identity_fabric.config import get_settings
    from identity_fabric.db import connect

    os.environ["SURREAL_URL"] = TEST_SURREAL_URL
    os.environ["SURREAL_NS"] = "test"
    os.environ["SURREAL_DB"] = f"t_{uuid.uuid4().hex[:12]}"
    get_settings.cache_clear()

    async with connect() as conn:
        await conn.query_all(SCHEMA.read_text())
        yield conn
        await conn.query(f"REMOVE DATABASE {os.environ['SURREAL_DB']}")
    get_settings.cache_clear()

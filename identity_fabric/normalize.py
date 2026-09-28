"""Identifier detection and normalization."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum


class IdentifierType(str, Enum):
    EMAIL = "email"
    PHONE = "phone"
    USERNAME = "username"
    PROVIDER_SUB = "provider_sub"  # "provider:sub", e.g. "google:1034..."
    EMPLOYEE_ID = "employee_id"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class NormalizedIdentifier:
    raw: str
    kind: IdentifierType
    value: str


def normalize_email(email: str) -> str:
    return email.strip().lower()


def normalize_phone(phone: str) -> str:
    digits = re.sub(r"[\s\-().]", "", phone.strip())
    return digits if digits.startswith("+") else "+" + digits


def normalize(raw: str) -> NormalizedIdentifier:
    raw = raw.strip()

    if "@" not in raw and re.match(r"^[a-z0-9_]+:\S+$", raw):
        return NormalizedIdentifier(raw, IdentifierType.PROVIDER_SUB, raw)

    if re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", raw):
        return NormalizedIdentifier(raw, IdentifierType.EMAIL, normalize_email(raw))

    if re.match(r"^\+?[0-9]{7,15}$", re.sub(r"[\s\-().]", "", raw)):
        return NormalizedIdentifier(raw, IdentifierType.PHONE, normalize_phone(raw))

    if re.match(r"^(EMP|E|USR|U|ID)[-_]?[0-9]{3,10}$", raw, re.IGNORECASE):
        return NormalizedIdentifier(raw, IdentifierType.EMPLOYEE_ID, raw.upper())

    if re.match(r"^[a-zA-Z0-9_.\-]{2,64}$", raw):
        return NormalizedIdentifier(raw, IdentifierType.USERNAME, raw.lower())

    return NormalizedIdentifier(raw, IdentifierType.UNKNOWN, raw)

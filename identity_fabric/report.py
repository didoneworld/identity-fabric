"""Human-readable AUDIT outputs: Mermaid graph and Markdown report."""

from __future__ import annotations

import re
from datetime import datetime, timezone

CONFIDENCE_BADGE = {"HIGH": "🟢", "MEDIUM": "🟡", "LOW": "🔴"}
SIGNAL_LABEL = {
    "verified_email_match": "Verified email match",
    "unverified_email_match": "Unverified email match",
    "phone_match": "Phone match",
    "oauth_token_claim": "OAuth token claim",
    "logto_session": "Logto session join",
    "manual": "Admin-asserted",
    "username_heuristic": "Username heuristic",
}
FLAG_LABEL = {
    "STALE_ACCOUNT": "⚠️ Stale account: data not refreshed within the TTL",
    "UNVERIFIED_EMAIL": "⚠️ Unverified email: cannot be used for HIGH-confidence linkage",
    "LOW_CONFIDENCE_LINK": "🔴 Low-confidence identity link: review manually",
    "ORPHANED_ACCOUNT": "⚠️ Linked account not owned by this person",
    "MULTIPLE_PERSONS": "🔴 Linked accounts are owned by more than one person",
}


def _node(record_id: str) -> str:
    return "n_" + re.sub(r"[^A-Za-z0-9_]", "_", record_id)


def _label(text: str) -> str:
    return str(text).replace('"', "'")


def build_mermaid(person: dict, accounts: list[dict], edges: dict) -> str:
    pid = _node(person["id"])
    name = person.get("display_name") or person.get("canonical_email") or "Person"
    lines = ["graph LR", f'  {pid}(["👤 {_label(name)}"])']
    for a in accounts:
        label = a.get("email") or a.get("username") or a.get("provider_sub", "?")
        stale = " ⚠" if a.get("stale") else ""
        lines.append(f'  {_node(a["id"])}["{a.get("provider", "?")}: {_label(label)}{stale}"]')
    for e in edges["owns"]:
        lines.append(f"  {pid} -->|owns| {_node(e['to'])}")
    for e in edges["linked_via"]:
        lines.append(f'  {_node(e["from"])} -.->|"{e.get("confidence")}: {e.get("signal")}"| {_node(e["to"])}')
    return "\n".join(lines)


def build_markdown_report(person: dict, accounts: list[dict], edges: dict,
                          flags: list[dict], tenant_id: str) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    providers = ", ".join(sorted({a.get("provider", "?") for a in accounts})) or "—"
    lines = [
        "# Identity Audit Report", "",
        f"**Tenant:** `{tenant_id}`  ", f"**Person ID:** `{person['id']}`  ", f"**Generated:** {now}", "",
        "## Identity Summary", "",
        "| Field | Value |", "|---|---|",
        f"| Display name | {person.get('display_name') or '—'} |",
        f"| Canonical email | {person.get('canonical_email') or '—'} |",
        f"| Canonical phone | {person.get('canonical_phone') or '—'} |",
        f"| Linked accounts | {len(accounts)} |",
        f"| Providers | {providers} |",
        f"| Cross-provider links | {len(edges['linked_via'])} |",
        f"| Anomaly flags | {len(flags)} |", "",
        "## Linked Accounts", "",
        "| Provider | Email | Username | Verified | Last seen | Stale |", "|---|---|---|---|---|---|",
    ]
    for a in accounts:
        lines.append(
            f"| {a.get('provider', '?')} | {a.get('email') or '—'} | {a.get('username') or '—'} "
            f"| {'✓' if a.get('email_verified') else '✗'} | {str(a.get('last_seen', '—'))[:10]} "
            f"| {'⚠️' if a.get('stale') else '—'} |"
        )
    lines += ["", "## Identity Links", "", "| From | To | Confidence | Signal | Asserted |", "|---|---|---|---|---|"]
    for e in edges["linked_via"]:
        conf = e.get("confidence", "")
        lines.append(
            f"| `{e['from']}` | `{e['to']}` | {CONFIDENCE_BADGE.get(conf, '?')} {conf} "
            f"| {SIGNAL_LABEL.get(e.get('signal', ''), e.get('signal', '?'))} | {str(e.get('asserted_at', '—'))[:10]} |"
        )
    lines += ["", "## Anomaly Flags", ""]
    if flags:
        for f in flags:
            detail = ", ".join(f"{k}={v}" for k, v in f.items() if k != "code")
            lines.append(f"- {FLAG_LABEL.get(f['code'], f['code'])}" + (f" ({detail})" if detail else ""))
    else:
        lines.append("✅ No anomalies detected.")
    lines += [
        "", "## Compliance Notes", "",
        "- Personal data fields encrypted at rest (AES-256-GCM)",
        "- Email/phone lookups use tenant-scoped HMAC-SHA256",
        "- Right to erasure: `DELETE /v1/persons/{id}`",
    ]
    return "\n".join(lines)

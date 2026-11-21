"""STIX 2.1 export of a campaign.

Domains, URLs and e-mail addresses use standard STIX patterns. STIX 2.1 core
has no observable for phone numbers, bank accounts or crypto wallets, so those
use the custom observable type names that OpenCTI defines (`phone-number`,
`bank-account`, `cryptocurrency-wallet`); consumers that are strict about the
core spec can drop indicators carrying `x_rasd_custom_observable: true`."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

_NS = uuid.UUID("5b1c2a52-6f0e-4d5e-9d7e-7a5d0c0a1e11")
_PATTERN = {
    "domain": ("[domain-name:value = '{v}']", False),
    "url": ("[url:value = 'http://{v}' OR url:value = 'https://{v}']", False),
    "email": ("[email-addr:value = '{v}']", False),
    "phone": ("[phone-number:value = '{v}']", True),
    "iban": ("[bank-account:iban = '{v}']", True),
    "wallet": ("[cryptocurrency-wallet:value = '{v}']", True),
    "handle": ("[user-account:account_login = '{v}']", False),
}


def _id(kind: str, key: str) -> str:
    return f"{kind}--{uuid.uuid5(_NS, kind + '|' + key)}"


def campaign_bundle(c: dict, producer: str = "RASD") -> dict:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    ident = {"type": "identity", "spec_version": "2.1", "id": _id("identity", producer), "created": now, "modified": now,
             "name": producer, "identity_class": "system"}
    camp = {"type": "campaign", "spec_version": "2.1", "id": _id("campaign", c["id"]), "created": now, "modified": now,
            "created_by_ref": ident["id"], "name": f"RASD {c['id']}",
            "description": f"{c['size']} linked messages; confidence {c['confidence']} ({c['confidence_reason']}).",
            "first_seen": _ts(c["first_seen"]) or now, "last_seen": _ts(c["last_seen"]) or now,
            "confidence": {"high": 85, "medium": 60, "low": 30}[c["confidence"]],
            "labels": sorted(c["tactics"])[:10], "x_rasd_brands": sorted(c["brands"])}
    objs = [ident, camp]
    for d in c["indicators"]:
        tpl = _PATTERN.get(d["type"])
        if not tpl:
            continue
        value = d["value"].split(":", 1)[-1] if d["type"] in ("wallet", "handle") else d["value"]
        ind = {"type": "indicator", "spec_version": "2.1", "id": _id("indicator", d["key"]), "created": now, "modified": now,
               "created_by_ref": ident["id"], "name": d["key"], "pattern_type": "stix",
               "pattern": tpl[0].format(v=value.replace("\\", "\\\\").replace("'", "\\'")),
               "valid_from": _ts(c["first_seen"]) or now, "indicator_types": ["malicious-activity"],
               "x_rasd_message_count": d["messages"]}
        if tpl[1]:
            ind["x_rasd_custom_observable"] = True
        objs.append(ind)
        objs.append({"type": "relationship", "spec_version": "2.1", "id": _id("relationship", d["key"] + c["id"]),
                     "created": now, "modified": now, "relationship_type": "indicates",
                     "source_ref": ind["id"], "target_ref": camp["id"]})
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objs}


def _ts(s: str | None) -> str | None:
    if not s:
        return None
    return datetime.fromisoformat(s).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

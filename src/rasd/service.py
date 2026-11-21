"""Application service: analysis + privacy + storage + (cached) campaign graph.
The API, CLI and evaluation harness all go through this one object."""
from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field

from .analysis import Analyzer
from .graph import CampaignGraph, GraphConfig
from .models import Message
from .privacy import pseudonymize, redact
from .storage import Store


@dataclass
class Rasd:
    store: Store = field(default_factory=Store)
    analyzer: Analyzer = field(default_factory=Analyzer)
    graph_config: GraphConfig = field(default_factory=GraphConfig)
    pseudonym_key: bytes = field(default_factory=lambda: (os.environ.get("RASD_PSEUDONYM_KEY") or secrets.token_hex(32)).encode())
    _cache: dict = field(default_factory=dict)

    def analyze(self, msg: Message) -> dict:
        """Stateless analysis — nothing is stored."""
        return self.analyzer.analyze(msg).to_dict()

    def analyze_traced(self, msg: Message) -> tuple[dict, dict]:
        from .analysis.trace import trace
        a = self.analyzer.analyze(msg)
        return a.to_dict(), trace(msg.text, a)

    def correlate(self, tenant: str, analysis: dict) -> dict:
        """Which stored messages and campaigns share an actor-controlled resource
        with this (un-stored) message? Same evidence standard as the graph:
        only linkable body indicators count; suppressed ones are reported, not used."""
        g = self.graph(tenant)
        out = []
        for i in analysis["indicators"]:
            if i["role"] != "body":
                continue
            ids = self.store.by_indicator(tenant, i["type"], i["value"])
            camps = sorted({g.msg_campaign[m] for m in ids if m in g.msg_campaign})
            out.append({"key": i["key"], "type": i["type"], "value": i["value"], "linkable": i["linkable"],
                        "seen_in_messages": len(ids), "message_ids": ids[:10], "campaign_ids": camps,
                        "suppressed_reason": g.suppressed.get(i["key"])})
        usable = [c for c in out if c["linkable"] and not c["suppressed_reason"]]
        return {"indicators": out,
                "would_join_campaigns": sorted({c for x in usable for c in x["campaign_ids"]}),
                "shares_resources_with_messages": sorted({m for x in usable for m in x["message_ids"]})[:20],
                "standard": "only actor-controlled resources (linkable, not suppressed) can link; text similarity never does"}

    def ingest(self, tenant: str, msg: Message) -> dict:
        a = self.analyzer.analyze(msg)
        text, redactions = redact(msg.text, a.indicators)
        d = a.to_dict()
        d["redactions"] = redactions
        self.store.add(tenant, d, text, msg.received_at, msg.channel, pseudonymize(msg.recipient, self.pseudonym_key),
                       msg.source)
        return d

    def graph(self, tenant: str) -> CampaignGraph:
        ver, g = self._cache.get(tenant, (None, None))
        if ver != self.store.version:
            g = CampaignGraph(self.store.nodes(tenant), self.graph_config)
            self._cache[tenant] = (self.store.version, g)
        return g

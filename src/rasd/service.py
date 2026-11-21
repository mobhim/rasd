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

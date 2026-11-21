"""Graph Intelligence Engine — links messages into campaigns by EVIDENCE.

Evidence standard (see docs/03-architecture.md §5):

  HARD  a resource the actor must control to cash out or be reached: landing
        domain, short-link path, contact number in the body, payee IBAN,
        crypto wallet, messaging handle, e-mail. One hard link is sufficient.
  WEAK  spoofable or copyable signals: sender number, alphanumeric sender id,
        message template (text similarity), URL path pattern (kit reuse).
        A single weak signal NEVER links. Two independent weak signal types
        whose combined (noisy-OR) strength passes the threshold produce a
        `corroborated` link, reported at lower confidence.

Text similarity therefore cannot merge two messages on its own; identical
texts with disjoint infrastructure stay separate campaigns and are surfaced as
`related: same_template_different_infrastructure` (copycat / kit reuse)."""
from __future__ import annotations

import hashlib
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from itertools import combinations

HARD = {"domain": 0.90, "url": 0.95, "phone": 0.85, "iban": 0.95, "wallet": 0.97, "handle": 0.85, "email": 0.85}
WEAK = {"sender_phone": 0.60, "template": 0.30, "url_path": 0.30, "sender_id": 0.20}
WINDOW_DAYS = {"phone": 120, "sender_phone": 60, "handle": 365, "domain": 365, "url": 365}


@dataclass
class MsgNode:
    id: str
    verdict: str
    score: float
    received_at: datetime | None
    indicators: list[dict]          # Indicator.to_dict()
    fingerprint: int
    brands: list[str] = field(default_factory=list)
    tactics: list[str] = field(default_factory=list)
    variety: str = ""
    channel: str = ""

    @classmethod
    def from_analysis(cls, a: dict, received_at: str | None = None, channel: str = "") -> "MsgNode":
        return cls(a["message_id"], a["verdict"], a["score"], parse_ts(received_at), a["indicators"],
                   int(a["fingerprint"], 16), a.get("brands", []), a.get("tactics", []),
                   a.get("variety", {}).get("label", ""), channel)


def parse_ts(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        d = datetime.fromisoformat(s.replace("Z", "+00:00"))
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


class _UF:
    def __init__(self):
        self.p: dict = {}

    def find(self, x):
        self.p.setdefault(x, x)
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.p[rb] = ra


def hamming(a: int, b: int) -> int:
    return (a ^ b).bit_count()


def noisy_or(strengths) -> float:
    p = 1.0
    for s in strengths:
        p *= 1.0 - s
    return 1.0 - p


@dataclass
class GraphConfig:
    min_campaign_size: int = 2
    corroboration_threshold: float = 0.70
    template_hamming: int = 6
    include_verdicts: tuple = ("suspicious", "malicious")
    benign_share_suppress: float = 0.5   # indicator mostly seen in benign traffic -> not a linking resource
    benign_min_count: int = 3


class CampaignGraph:
    def __init__(self, nodes: list[MsgNode], config: GraphConfig | None = None):
        self.cfg = config or GraphConfig()
        self.nodes = {n.id: n for n in nodes}
        self.campaigns: list[dict] = []
        self.msg_campaign: dict[str, str] = {}
        self.suppressed: dict[str, str] = {}
        self.template_families: list[dict] = []
        self._adj: dict[str, dict[str, list[tuple[str, str, float]]]] = defaultdict(lambda: defaultdict(list))
        self._template_cluster: dict[str, int] = {}
        self._build()

    # ------------------------------------------------------------------ build
    def _hard_keys(self, n: MsgNode):
        for i in n.indicators:
            if i["linkable"] and i["role"] == "body" and i["type"] in HARD:
                yield i["key"], i["type"]

    def _weak_keys(self, n: MsgNode):
        for i in n.indicators:
            if i["role"] == "sender" and i["type"] == "phone":
                yield "sender_phone", "sender_phone:" + i["value"]
            elif i["type"] == "sender_id" and i["attrs"].get("alphanumeric"):
                yield "sender_id", "sender_id:" + i["value"]
            elif i["type"] == "url" and not i["attrs"].get("official") and not i["attrs"].get("shortener") \
                    and not i["attrs"].get("shared_platform"):
                path = i["attrs"].get("path") or ""
                if path.count("/") >= 2 or len(path) >= 10:
                    yield "url_path", "url_path:" + path.lower()
        tc = self._template_cluster.get(n.id)
        if tc is not None:
            yield "template", f"template:{tc}"

    def _cluster_templates(self, elig: list[MsgNode]) -> None:
        """Near-duplicate template clusters via banded LSH on the 64-bit simhash."""
        uf, buckets = _UF(), defaultdict(list)
        for n in elig:
            if n.fingerprint:
                for band in range(4):
                    buckets[(band, (n.fingerprint >> (16 * band)) & 0xFFFF)].append(n)
        for members in buckets.values():
            for a, b in combinations(members[:200], 2):
                if hamming(a.fingerprint, b.fingerprint) <= self.cfg.template_hamming:
                    uf.union(a.id, b.id)
        roots: dict[str, int] = {}
        for n in elig:
            if n.fingerprint and n.id in uf.p:
                self._template_cluster[n.id] = roots.setdefault(uf.find(n.id), len(roots))

    def _chain(self, kind: str, members: list[MsgNode]):
        """Yield consecutive pairs that fall inside the validity window of the
        resource (numbers get re-assigned, domains get re-registered)."""
        win = timedelta(days=WINDOW_DAYS.get(kind, 365))
        ms = sorted(members, key=lambda n: (n.received_at or datetime.min.replace(tzinfo=timezone.utc), n.id))
        for a, b in zip(ms, ms[1:]):
            if a.received_at is None or b.received_at is None or b.received_at - a.received_at <= win:
                yield a, b

    def _build(self) -> None:
        cfg = self.cfg
        elig = [n for n in self.nodes.values() if n.verdict in cfg.include_verdicts]
        benign = [n for n in self.nodes.values() if n.verdict not in cfg.include_verdicts]
        by_hard: dict[str, list[MsgNode]] = defaultdict(list)
        kind_of: dict[str, str] = {}
        for n in elig:
            for key, kind in self._hard_keys(n):
                by_hard[key].append(n); kind_of[key] = kind
        benign_count: dict[str, int] = defaultdict(int)
        benign_by_key: dict[str, list[str]] = defaultdict(list)
        for n in benign:
            for key, _ in self._hard_keys(n):
                benign_count[key] += 1; benign_by_key[key].append(n.id)
        uf = _UF()
        for key, members in by_hard.items():
            b = benign_count.get(key, 0)
            if b >= cfg.benign_min_count and b / (b + len(members)) > cfg.benign_share_suppress:
                self.suppressed[key] = f"seen in {b} benign vs {len(members)} flagged messages"
                continue
            for a, c in self._chain(kind_of[key], members):
                uf.union(a.id, c.id)
                self._adj[a.id][c.id].append((key, "hard", HARD[kind_of[key]]))
                self._adj[c.id][a.id].append((key, "hard", HARD[kind_of[key]]))

        # corroborated weak links: same pair must share >= 2 different weak signal types
        self._cluster_templates(elig)
        combos: dict[tuple, list[MsgNode]] = defaultdict(list)
        for n in elig:
            wk = sorted(set(self._weak_keys(n)))
            for (t1, k1), (t2, k2) in combinations(wk, 2):
                if t1 != t2 and noisy_or((WEAK[t1], WEAK[t2])) >= cfg.corroboration_threshold:
                    combos[(k1, k2)].append(n)
        for (k1, k2), members in combos.items():
            s = noisy_or((WEAK[k1.split(":")[0]], WEAK[k2.split(":")[0]]))
            for a, c in self._chain("sender_phone", members):
                uf.union(a.id, c.id)
                self._adj[a.id][c.id].append((f"{k1} + {k2}", "corroborated", round(s, 2)))
                self._adj[c.id][a.id].append((f"{k1} + {k2}", "corroborated", round(s, 2)))

        comps: dict[str, list[MsgNode]] = defaultdict(list)
        for n in elig:
            if n.id in uf.p:
                comps[uf.find(n.id)].append(n)
        for members in comps.values():
            if len(members) >= cfg.min_campaign_size:
                self.campaigns.append(self._describe(members, benign_by_key))
        self.campaigns.sort(key=lambda c: (-c["size"], c["id"]))
        self._relate()
        self._families(elig)

    def _families(self, elig: list[MsgNode]) -> None:
        """Template families: flagged messages that share a script. This is a
        HYPOTHESIS object for analysts (script / kit reuse), deliberately kept
        separate from campaigns: it asserts nothing about a common actor."""
        groups: dict[int, list[MsgNode]] = defaultdict(list)
        for n in elig:
            if n.id in self._template_cluster:
                groups[self._template_cluster[n.id]].append(n)
        for tc, members in groups.items():
            if len(members) < 3:
                continue
            camps = sorted({self.msg_campaign[m.id] for m in members if m.id in self.msg_campaign})
            hard = {k for m in members for k, _ in self._hard_keys(m)}
            self.template_families.append({
                "id": f"tpl_{tc}", "size": len(members), "message_ids": sorted(m.id for m in members),
                "campaign_ids": camps, "unlinked_messages": sum(1 for m in members if m.id not in self.msg_campaign),
                "distinct_hard_indicators": len(hard), "brands": sorted({b for m in members for b in m.brands}),
                "evidence_level": "weak",
                "note": "same script, not necessarily same actor — text similarity alone never merges campaigns"})
        self.template_families.sort(key=lambda f: -f["size"])

    # ------------------------------------------------------------------ describe
    def _components_without(self, ids: set[str], drop: str) -> int:
        seen, comps = set(), 0
        for start in ids:
            if start in seen:
                continue
            comps += 1
            dq = deque([start]); seen.add(start)
            while dq:
                x = dq.popleft()
                for y, evs in self._adj[x].items():
                    if y in ids and y not in seen and any(k != drop for k, _, _ in evs):
                        seen.add(y); dq.append(y)
        return comps

    def _describe(self, members: list[MsgNode], benign_by_key: dict) -> dict:
        ids = {m.id for m in members}
        ordered = sorted(members, key=lambda n: (n.received_at.isoformat() if n.received_at else "", n.id))
        cid = "cmp_" + hashlib.sha1(ordered[0].id.encode()).hexdigest()[:10]
        ind: dict[str, dict] = {}
        for m in members:
            for i in m.indicators:
                if i["role"] == "body" and i["linkable"] and i["type"] in HARD and i["key"] not in self.suppressed:
                    d = ind.setdefault(i["key"], {"key": i["key"], "type": i["type"], "value": i["value"], "messages": 0})
                    d["messages"] += 1
        shared = [d for d in ind.values() if d["messages"] >= 2]
        link_kinds = {kind for m in members for y, evs in self._adj[m.id].items() if y in ids for _, kind, _ in evs}
        bridges = [d["key"] for d in shared[:60] if self._components_without(ids, d["key"]) > 1] if len(shared) >= 2 else []
        types = {d["type"] for d in shared}
        if "hard" not in link_kinds:
            level, why = "low", "linked only by corroborated weak signals (no shared actor-controlled resource)"
        elif len(shared) >= 2 and not bridges:
            level, why = "high", f"{len(shared)} shared actor-controlled resources ({', '.join(sorted(types))}), no single point of linkage"
        else:
            level, why = "medium", ("held together by a single resource" if len(shared) <= 1
                                    else f"sub-clusters joined only through: {', '.join(bridges[:3])}")
        associated = sorted({mid for d in ind.values() for mid in benign_by_key.get(d["key"], [])})
        times = [m.received_at for m in members if m.received_at]
        cnt = lambda vals: dict(sorted(_count(vals).items(), key=lambda kv: -kv[1]))   # noqa: E731
        for m in members:
            self.msg_campaign[m.id] = cid
        return {
            "id": cid, "size": len(members), "message_ids": [m.id for m in ordered],
            "first_seen": min(times).isoformat() if times else None,
            "last_seen": max(times).isoformat() if times else None,
            "confidence": level, "confidence_reason": why, "link_kinds": sorted(link_kinds),
            "indicators": sorted(ind.values(), key=lambda d: (-d["messages"], d["key"])),
            "shared_indicator_count": len(shared), "bridges": bridges,
            "brands": cnt(b for m in members for b in m.brands),
            "tactics": cnt(t for m in members for t in m.tactics),
            "varieties": cnt(m.variety for m in members if m.variety),
            "channels": cnt(m.channel for m in members if m.channel),
            "template_clusters": sorted({self._template_cluster[m.id] for m in members if m.id in self._template_cluster}),
            "max_score": max(m.score for m in members),
            "associated_low_score_messages": associated,
            "related": [],
        }

    def _relate(self) -> None:
        by_tc: dict[int, list[dict]] = defaultdict(list)
        for c in self.campaigns:
            for tc in c["template_clusters"]:
                by_tc[tc].append(c)
        done: set[tuple[str, str]] = set()
        for tc, cs in by_tc.items():
            for a, b in combinations(cs, 2):
                if (a["id"], b["id"]) in done or (b["id"], a["id"]) in done:
                    continue
                done.add((a["id"], b["id"]))
                note = {"relation": "same_template_different_infrastructure", "strength": "weak",
                        "note": "text similarity only — not sufficient to merge (possible kit reuse or copycat)"}
                a["related"].append({"campaign_id": b["id"], **note})
                b["related"].append({"campaign_id": a["id"], **note})

    # ------------------------------------------------------------------ queries
    def campaign(self, cid: str) -> dict | None:
        return next((c for c in self.campaigns if c["id"] == cid), None)

    def explain_link(self, a: str, b: str) -> dict:
        """Why are two messages (not) in the same campaign? Returns the chain
        of evidence, hop by hop."""
        if a not in self.nodes or b not in self.nodes:
            return {"linked": False, "reason": "unknown message id"}
        prev: dict[str, tuple[str, tuple]] = {}
        dq, seen = deque([a]), {a}
        while dq and b not in seen:
            x = dq.popleft()
            for y, evs in self._adj[x].items():
                if y not in seen:
                    seen.add(y); prev[y] = (x, max(evs, key=lambda e: e[2])); dq.append(y)
        na, nb = self.nodes[a], self.nodes[b]
        weak = []
        if na.fingerprint and nb.fingerprint:
            h = hamming(na.fingerprint, nb.fingerprint)
            weak.append({"signal": "template_similarity", "hamming_distance": h, "similar": h <= self.cfg.template_hamming})
        common = sorted(set(na.brands) & set(nb.brands))
        if common:
            weak.append({"signal": "same_brand_targeted", "brands": common})
        if b not in seen:
            return {"linked": False, "weak_signals": weak,
                    "reason": "no chain of hard or corroborated evidence connects these messages; "
                              "weak signals alone are insufficient to assert a common campaign"}
        path, x = [], b
        while x != a:
            p, (key, kind, strength) = prev[x]
            path.append({"from": p, "to": x, "via": key, "kind": kind, "strength": strength})
            x = p
        path.reverse()
        return {"linked": True, "hops": len(path), "path": path, "weak_signals": weak,
                "campaign_id": self.msg_campaign.get(a),
                "chain_strength": round(min(h["strength"] for h in path), 2)}

    def subgraph(self, cid: str | None = None, limit: int = 400) -> dict:
        """Investigation graph.

        With `cid`: the campaign, its messages, every actor-controlled resource
        they contain and the brands they mention. Without: one node per
        campaign, the resources it shares, and weak same-template links between
        campaigns (shown, never merged).

        Every edge says whether it is DIRECT evidence (the value literally
        appears in the message) or INFERRED (membership, corroborated weak
        signals, template similarity)."""
        nodes: dict[str, dict] = {}
        edges: list[dict] = []

        def node(nid: str, **kw) -> None:
            if nid not in nodes and len(nodes) < limit:
                nodes[nid] = {"id": nid, **kw}

        def edge(a: str, b: str, kind: str, direct: bool, label: str, **kw) -> None:
            if a in nodes and b in nodes:
                edges.append({"source": a, "target": b, "kind": kind, "direct": direct, "label": label, **kw})

        camps = [c for c in self.campaigns if cid is None or c["id"] == cid]
        for c in camps:
            cn = "cmp:" + c["id"]
            node(cn, kind="campaign", label=c["id"], size=c["size"], confidence=c["confidence"])
            shared = {d["key"] for d in c["indicators"] if d["messages"] >= 2} if cid is None else {d["key"] for d in c["indicators"]}
            for d in c["indicators"]:
                if d["key"] in shared:
                    node("ind:" + d["key"], kind="indicator", type=d["type"], label=d["value"], key=d["key"],
                         messages=d["messages"], bridge=d["key"] in c["bridges"])
                    if cid is None:
                        edge(cn, "ind:" + d["key"], "uses", True,
                             f"{d['messages']} messages of this campaign contain it", messages=d["messages"])
            for b, n in c["brands"].items():
                node("ent:" + b, kind="entity", type="brand", label=b)
                edge(cn, "ent:" + b, "mentions", True, f"named in {n} messages (impersonation target, not a link)", messages=n)
            if cid is None:
                continue
            for mid in c["message_ids"]:
                m = self.nodes[mid]
                mn = "msg:" + mid
                node(mn, kind="message", label=mid, verdict=m.verdict, score=m.score)
                edge(mn, cn, "member", False, "member of the campaign (derived from the evidence edges)")
                for i in m.indicators:
                    if i["role"] == "body" and "ind:" + i["key"] in nodes:
                        edge(mn, "ind:" + i["key"], "contains", True, "value appears in the message text")
            for mid in c["message_ids"]:
                for y, evs in self._adj[mid].items():
                    if mid < y and evs and all(k == "corroborated" for _, k, _ in evs):
                        edge("msg:" + mid, "msg:" + y, "corroborated", False,
                             "two independent weak signals together: " + evs[0][0], strength=evs[0][2])
        if cid is None:
            for c in camps:
                for r in c["related"]:
                    if c["id"] < r["campaign_id"]:
                        edge("cmp:" + c["id"], "cmp:" + r["campaign_id"], "same_template", False,
                             "similar text, different infrastructure — NOT merged (weak evidence)")
        ids = set(nodes)
        return {"nodes": list(nodes.values()), "edges": [e for e in edges if e["source"] in ids and e["target"] in ids],
                "truncated": len(nodes) >= limit}

def _count(vals) -> dict:
    out: dict = {}
    for v in vals:
        out[v] = out.get(v, 0) + 1
    return out

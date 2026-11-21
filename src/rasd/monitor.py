"""Runtime monitoring. Every value here is MEASURED at request time or recorded
by this process; anything that cannot be measured is reported as
`unavailable`, never estimated or simulated."""
from __future__ import annotations

import os
import platform
import shutil
import sys
import threading
import time
from collections import deque
from datetime import datetime, timedelta, timezone

from . import __version__
from .models import Message

CANARY = Message("عزيزي العميل تم إيقاف بطاقتك، حدث بياناتك عبر الرابط https://alrajhi-update.example/login خلال 24 ساعة",
                 sender="0500000000")


class Metrics:
    """In-process request metrics since start-up (reset on restart)."""

    def __init__(self, size: int = 2000):
        self.started = time.time()
        self.reqs: deque = deque(maxlen=size)
        self.total = 0
        self.lock = threading.Lock()

    def add(self, method: str, route: str, status: int, ms: float) -> None:
        with self.lock:
            self.total += 1
            self.reqs.append((time.time(), method, route, status, ms))

    def summary(self) -> dict:
        with self.lock:
            rs = list(self.reqs)
        lat = sorted(r[4] for r in rs)
        pct = lambda p: round(lat[min(len(lat) - 1, int(p * len(lat)))], 2) if lat else None   # noqa: E731
        routes: dict = {}
        for _, m, r, st, ms in rs:
            d = routes.setdefault(f"{m} {r}", {"count": 0, "errors": 0, "ms": 0.0})
            d["count"] += 1; d["errors"] += st >= 500; d["ms"] += ms
        return {
            "uptime_seconds": round(time.time() - self.started, 1),
            "started_at": datetime.fromtimestamp(self.started, timezone.utc).isoformat(),
            "requests_total": self.total, "window": len(rs),
            "server_errors": sum(1 for r in rs if r[3] >= 500), "client_errors": sum(1 for r in rs if 400 <= r[3] < 500),
            "latency_ms_p50": pct(0.5), "latency_ms_p95": pct(0.95),
            "routes": sorted(({"route": k, "count": v["count"], "errors": v["errors"],
                               "avg_ms": round(v["ms"] / v["count"], 2)} for k, v in routes.items()), key=lambda d: -d["count"])[:12],
            "scope": "since process start (in-memory)",
        }


def _rss_bytes() -> int | None:
    try:
        with open("/proc/self/statm") as fh:
            return int(fh.read().split()[1]) * os.sysconf("SC_PAGE_SIZE")
    except (OSError, ValueError, AttributeError):
        return None


def resources(db_path: str) -> dict:
    out: dict = {"platform": platform.platform(terse=True), "python": sys.version.split()[0], "cpu_count": os.cpu_count()}
    rss = _rss_bytes()
    out["memory_rss_bytes"] = rss if rss is not None else "unavailable"
    t = os.times()
    out["process_cpu_seconds"] = round(t.user + t.system, 2)
    try:
        out["load_avg_1m"] = round(os.getloadavg()[0], 2)
    except (OSError, AttributeError):
        out["load_avg_1m"] = "unavailable"
    try:
        du = shutil.disk_usage(os.path.dirname(os.path.abspath(db_path)) if db_path != ":memory:" else ".")
        out["disk_total_bytes"], out["disk_free_bytes"] = du.total, du.free
    except OSError:
        out["disk_total_bytes"] = out["disk_free_bytes"] = "unavailable"
    return out


def health(rasd, tenant: str, metrics: Metrics) -> dict:
    checks: dict = {}
    # detection engine: a fixed canary message must produce the expected verdict
    t = time.perf_counter()
    try:
        a = rasd.analyzer.analyze(CANARY)
        ok = a.verdict == "malicious" and any(e.id == "url.brand_impersonation" for e in a.evidence)
        checks["engine"] = {"status": "ok" if ok else "degraded", "latency_ms": round((time.perf_counter() - t) * 1000, 2),
                            "policy_version": rasd.analyzer.policy.version, "language_packs": _packs(),
                            "check": "canary message analysed; expected verdict 'malicious' with brand-impersonation evidence",
                            "observed_verdict": a.verdict}
    except Exception as e:                                         # noqa: BLE001 — health must report, not raise
        checks["engine"] = {"status": "failed", "error": repr(e)[:200]}
    # database
    t = time.perf_counter()
    try:
        ov = rasd.store.db_overview(tenant)
        integ = rasd.store.integrity(tenant)
        bad = [c for c in integ if c["status"] == "fail"]
        checks["database"] = {"status": "failed" if bad else "ok", "latency_ms": round((time.perf_counter() - t) * 1000, 2),
                              "engine": f"SQLite {ov['engine_version']}", "persistent": ov["persistent"],
                              "size_bytes": ov["size_bytes"], "integrity": integ}
    except Exception as e:                                         # noqa: BLE001
        checks["database"] = {"status": "failed", "error": repr(e)[:200]}
    # correlation pipeline: rebuild the graph and time it
    t = time.perf_counter()
    try:
        rasd._cache.pop(tenant, None)
        g = rasd.graph(tenant)
        since = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
        last_ingest = rasd.store.ops(tenant, 1, None)
        checks["pipeline"] = {"status": "ok", "graph_build_ms": round((time.perf_counter() - t) * 1000, 2),
                              "campaigns": len(g.campaigns), "messages_linked": len(g.msg_campaign),
                              "last_operation": last_ingest[0] if last_ingest else None,
                              "operations_24h": rasd.store.ops_summary(tenant, since)}
    except Exception as e:                                         # noqa: BLE001
        checks["pipeline"] = {"status": "failed", "error": repr(e)[:200]}
    m = metrics.summary()
    checks["api"] = {"status": "ok" if not m["server_errors"] else "degraded", "version": __version__, **m}
    overall = "ok" if all(c["status"] == "ok" for c in checks.values()) else (
        "failed" if any(c["status"] == "failed" for c in checks.values()) else "degraded")
    return {"status": overall, "measured_at": datetime.now(timezone.utc).isoformat(), "checks": checks,
            "resources": resources(rasd.store.path),
            "recent_operations": rasd.store.ops(tenant, 25),
            "recent_failures": rasd.store.ops(tenant, 25, "error") + rasd.store.ops(tenant, 25, "rejected")}


def _packs() -> list[str]:
    from .lang import packs
    return [p.code for p in packs()]

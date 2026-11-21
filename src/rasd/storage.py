"""SQLite persistence (stdlib). Multi-tenant by column; the repository API is
small on purpose so it can be re-implemented on Postgres without touching the
engine."""
from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timedelta, timezone

from .graph import MsgNode

_SCHEMA = """
CREATE TABLE IF NOT EXISTS messages(
  tenant TEXT NOT NULL, id TEXT NOT NULL, received_at TEXT, ingested_at TEXT NOT NULL, channel TEXT,
  recipient_pseudo TEXT, text_redacted TEXT NOT NULL, language TEXT, variety TEXT, score REAL, verdict TEXT,
  analysis TEXT NOT NULL, PRIMARY KEY(tenant, id));
CREATE TABLE IF NOT EXISTS indicators(
  tenant TEXT NOT NULL, message_id TEXT NOT NULL, type TEXT NOT NULL, value TEXT NOT NULL, role TEXT, linkable INTEGER);
CREATE INDEX IF NOT EXISTS ix_ind ON indicators(tenant, type, value);
CREATE INDEX IF NOT EXISTS ix_ind_msg ON indicators(tenant, message_id);
CREATE INDEX IF NOT EXISTS ix_msg_time ON messages(tenant, received_at);
CREATE TABLE IF NOT EXISTS audit(ts TEXT, tenant TEXT, action TEXT, detail TEXT);
"""


class Store:
    def __init__(self, path: str = ":memory:"):
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(_SCHEMA)
        self.lock = threading.RLock()
        self.version = 0     # bumped on every write; lets callers cache derived graphs

    def add(self, tenant: str, analysis: dict, text_redacted: str, received_at: str | None, channel: str,
            recipient_pseudo: str | None) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self.lock, self.db:
            mid = analysis["message_id"]
            self.db.execute("DELETE FROM indicators WHERE tenant=? AND message_id=?", (tenant, mid))
            self.db.execute("INSERT OR REPLACE INTO messages VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                            (tenant, mid, received_at or now, now, channel, recipient_pseudo, text_redacted,
                             analysis["language"], analysis["variety"]["label"], analysis["score"],
                             analysis["verdict"], json.dumps(analysis, ensure_ascii=False)))
            self.db.executemany("INSERT INTO indicators VALUES(?,?,?,?,?,?)",
                                [(tenant, mid, i["type"], i["value"], i["role"], int(i["linkable"]))
                                 for i in analysis["indicators"]])
            self.version += 1

    def _row(self, r: sqlite3.Row, full: bool = True) -> dict:
        d = {k: r[k] for k in ("id", "received_at", "channel", "language", "variety", "score", "verdict", "recipient_pseudo")}
        d["text"] = r["text_redacted"]
        if full:
            d["analysis"] = json.loads(r["analysis"])
        return d

    def get(self, tenant: str, mid: str) -> dict | None:
        with self.lock:
            r = self.db.execute("SELECT * FROM messages WHERE tenant=? AND id=?", (tenant, mid)).fetchone()
        return self._row(r) if r else None

    def list(self, tenant: str, verdict: str | None = None, q: str | None = None, limit: int = 50, offset: int = 0) -> list[dict]:
        sql, args = "SELECT * FROM messages WHERE tenant=?", [tenant]
        if verdict:
            sql += " AND verdict=?"; args.append(verdict)
        if q:
            sql += " AND text_redacted LIKE ?"; args.append(f"%{q}%")
        sql += " ORDER BY received_at DESC LIMIT ? OFFSET ?"; args += [limit, offset]
        with self.lock:
            return [self._row(r, full=False) for r in self.db.execute(sql, args)]

    def by_indicator(self, tenant: str, type_: str, value: str) -> list[str]:
        with self.lock:
            return [r[0] for r in self.db.execute(
                "SELECT DISTINCT message_id FROM indicators WHERE tenant=? AND type=? AND value=?", (tenant, type_, value))]

    def delete(self, tenant: str, mid: str) -> bool:
        with self.lock, self.db:
            n = self.db.execute("DELETE FROM messages WHERE tenant=? AND id=?", (tenant, mid)).rowcount
            self.db.execute("DELETE FROM indicators WHERE tenant=? AND message_id=?", (tenant, mid))
            self.version += 1
        return bool(n)

    def purge_older_than(self, tenant: str, days: int) -> int:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        with self.lock, self.db:
            ids = [r[0] for r in self.db.execute("SELECT id FROM messages WHERE tenant=? AND ingested_at<?", (tenant, cutoff))]
            for mid in ids:
                self.db.execute("DELETE FROM messages WHERE tenant=? AND id=?", (tenant, mid))
                self.db.execute("DELETE FROM indicators WHERE tenant=? AND message_id=?", (tenant, mid))
            self.version += 1
        return len(ids)

    def nodes(self, tenant: str) -> list[MsgNode]:
        with self.lock:
            rows = self.db.execute("SELECT received_at, channel, analysis FROM messages WHERE tenant=?", (tenant,)).fetchall()
        return [MsgNode.from_analysis(json.loads(r["analysis"]), r["received_at"], r["channel"] or "") for r in rows]

    def stats(self, tenant: str) -> dict:
        with self.lock:
            q = lambda s: self.db.execute(s, (tenant,)).fetchall()      # noqa: E731
            return {
                "messages": q("SELECT COUNT(*) FROM messages WHERE tenant=?")[0][0],
                "by_verdict": {r[0]: r[1] for r in q("SELECT verdict, COUNT(*) FROM messages WHERE tenant=? GROUP BY verdict")},
                "by_variety": {r[0]: r[1] for r in q("SELECT variety, COUNT(*) FROM messages WHERE tenant=? AND verdict!='benign' GROUP BY variety")},
                "by_channel": {r[0]: r[1] for r in q("SELECT channel, COUNT(*) FROM messages WHERE tenant=? GROUP BY channel")},
                "by_day": [{"day": r[0], "verdict": r[1], "n": r[2]} for r in q(
                    "SELECT substr(received_at,1,10), verdict, COUNT(*) FROM messages WHERE tenant=? GROUP BY 1,2 ORDER BY 1")],
                "top_indicators": [{"type": r[0], "value": r[1], "messages": r[2]} for r in q(
                    "SELECT i.type, i.value, COUNT(DISTINCT i.message_id) c FROM indicators i JOIN messages m "
                    "ON m.tenant=i.tenant AND m.id=i.message_id WHERE i.tenant=? AND i.linkable=1 AND i.role='body' "
                    "AND m.verdict!='benign' GROUP BY 1,2 HAVING c>1 ORDER BY c DESC LIMIT 15")],
            }

    def audit(self, tenant: str, action: str, detail: str = "") -> None:
        with self.lock, self.db:
            self.db.execute("INSERT INTO audit VALUES(?,?,?,?)", (datetime.now(timezone.utc).isoformat(), tenant, action, detail))

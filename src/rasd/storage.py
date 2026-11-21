"""SQLite persistence (stdlib). Multi-tenant by column; the repository API is
small on purpose so it can be re-implemented on Postgres without touching the
engine.

Schema v2 adds: `messages.source` (data provenance: real | synthetic | test |
unspecified), `operations` (what the system did, for monitoring),
`investigations` (analyst case tracking) and `schema_meta`. Existing v1
databases are migrated in place on open.

Relationships between tables are LOGICAL (enforced by this module, not by
declared SQLite foreign keys). `RELATIONS` documents them and the database
explorer reports them as such, together with an orphan check."""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone

from .graph import MsgNode

SCHEMA_VERSION = 2
SOURCES = ("real", "synthetic", "test", "unspecified")

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
CREATE TABLE IF NOT EXISTS operations(
  ts TEXT NOT NULL, tenant TEXT, op TEXT NOT NULL, status TEXT NOT NULL, duration_ms REAL, items INTEGER, detail TEXT);
CREATE INDEX IF NOT EXISTS ix_ops_time ON operations(tenant, ts);
CREATE TABLE IF NOT EXISTS investigations(
  tenant TEXT NOT NULL, id TEXT NOT NULL, campaign_id TEXT NOT NULL, title TEXT NOT NULL, status TEXT NOT NULL,
  notes TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, PRIMARY KEY(tenant, id));
CREATE TABLE IF NOT EXISTS schema_meta(key TEXT PRIMARY KEY, value TEXT);
"""

#: (table, column, references, kind, description)
RELATIONS = [
    ("indicators", "message_id", "messages.id", "logical",
     "each extracted indicator belongs to one message (same tenant); deleted with it"),
    ("investigations", "campaign_id", "campaigns.id (derived)", "derived",
     "campaigns are not stored: they are recomputed from indicators by the graph engine"),
    ("operations", "tenant", "—", "none", "append-only log of system operations"),
    ("audit", "tenant", "—", "none", "append-only log of sensitive actions (exports, deletions)"),
]
RELATIONS_AR = {
    "indicators.message_id": "كل مؤشر مستخرج ينتمي إلى رسالة واحدة (من الحساب نفسه) ويُحذف معها",
    "investigations.campaign_id": "الحملات لا تُخزَّن: يعيد محرك الرسم حسابها من المؤشرات عند كل تغيير",
    "operations.tenant": "سجل إلحاقي لعمليات النظام",
    "audit.tenant": "سجل إلحاقي للإجراءات الحساسة (التصدير، الحذف، التحقيقات)",
}
DERIVED_VIEWS = [
    {"name": "campaigns", "computed_from": ["messages", "indicators"], "by": "rasd.graph.CampaignGraph",
     "note": "messages linked by shared actor-controlled resources; recomputed when data changes, never persisted",
     "note_ar": "رسائل يربطها مورد مشترك يتحكم به المهاجم؛ تُعاد حسابها عند تغيّر البيانات ولا تُخزَّن"},
    {"name": "template_families", "computed_from": ["messages"], "by": "rasd.graph.CampaignGraph",
     "note": "near-duplicate texts (weak evidence); recomputed, never persisted",
     "note_ar": "نصوص شبه متطابقة (دليل ضعيف)؛ تُعاد حسابها ولا تُخزَّن"},
]
#: read-only explorer: table -> columns exposed (analysis JSON is exposed by size only in listings)
EXPLORABLE = {
    "messages": ["id", "received_at", "ingested_at", "source", "channel", "recipient_pseudo", "language", "variety",
                 "score", "verdict", "text_redacted"],
    "indicators": ["message_id", "type", "value", "role", "linkable"],
    "investigations": ["id", "campaign_id", "title", "status", "notes", "created_at", "updated_at"],
    "operations": ["ts", "op", "status", "duration_ms", "items", "detail"],
    "audit": ["ts", "action", "detail"],
}
_SEARCHABLE = {"messages": ["id", "text_redacted", "verdict", "variety", "source"],
               "indicators": ["message_id", "type", "value"], "investigations": ["id", "campaign_id", "title", "notes"],
               "operations": ["op", "status", "detail"], "audit": ["action", "detail"]}
_ORDER = {"messages": "received_at DESC", "indicators": "rowid DESC", "investigations": "updated_at DESC",
          "operations": "ts DESC", "audit": "ts DESC"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Store:
    def __init__(self, path: str = ":memory:"):
        self.path = path
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.lock = threading.RLock()
        with self.lock, self.db:
            self.db.executescript(_SCHEMA)
            self._migrate()
        self.version = 0     # bumped on every write; lets callers cache derived graphs

    def _migrate(self) -> None:
        cols = {r["name"] for r in self.db.execute("PRAGMA table_info(messages)")}
        if "source" not in cols:
            self.db.execute("ALTER TABLE messages ADD COLUMN source TEXT NOT NULL DEFAULT 'unspecified'")
        self.db.execute("INSERT OR REPLACE INTO schema_meta VALUES('schema_version', ?)", (str(SCHEMA_VERSION),))

    # ------------------------------------------------------------------ messages
    def add(self, tenant: str, analysis: dict, text_redacted: str, received_at: str | None, channel: str,
            recipient_pseudo: str | None, source: str = "unspecified") -> None:
        if source not in SOURCES:
            raise ValueError(f"source must be one of {SOURCES}")
        now = _now()
        with self.lock, self.db:
            mid = analysis["message_id"]
            self.db.execute("DELETE FROM indicators WHERE tenant=? AND message_id=?", (tenant, mid))
            self.db.execute(
                "INSERT OR REPLACE INTO messages(tenant,id,received_at,ingested_at,channel,recipient_pseudo,text_redacted,"
                "language,variety,score,verdict,analysis,source) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (tenant, mid, received_at or now, now, channel, recipient_pseudo, text_redacted, analysis["language"],
                 analysis["variety"]["label"], analysis["score"], analysis["verdict"],
                 json.dumps(analysis, ensure_ascii=False), source))
            self.db.executemany("INSERT INTO indicators VALUES(?,?,?,?,?,?)",
                                [(tenant, mid, i["type"], i["value"], i["role"], int(i["linkable"]))
                                 for i in analysis["indicators"]])
            self.version += 1

    def _row(self, r: sqlite3.Row, full: bool = True) -> dict:
        d = {k: r[k] for k in ("id", "received_at", "ingested_at", "channel", "language", "variety", "score", "verdict",
                               "recipient_pseudo", "source")}
        d["text"] = r["text_redacted"]
        if full:
            d["analysis"] = json.loads(r["analysis"])
        return d

    def get(self, tenant: str, mid: str) -> dict | None:
        with self.lock:
            r = self.db.execute("SELECT * FROM messages WHERE tenant=? AND id=?", (tenant, mid)).fetchone()
        return self._row(r) if r else None

    @staticmethod
    def _where(tenant, verdict, q, source, day):
        sql, args = " WHERE tenant=?", [tenant]
        if verdict:
            sql += " AND verdict=?"; args.append(verdict)
        if source:
            sql += " AND source=?"; args.append(source)
        if day:
            sql += " AND substr(received_at,1,10)=?"; args.append(day)
        if q:
            sql += " AND (text_redacted LIKE ? OR id LIKE ?)"; args += [f"%{q}%", f"%{q}%"]
        return sql, args

    def list(self, tenant: str, verdict: str | None = None, q: str | None = None, limit: int = 50, offset: int = 0,
             source: str | None = None, day: str | None = None) -> list[dict]:
        w, args = self._where(tenant, verdict, q, source, day)
        sql = "SELECT * FROM messages" + w + " ORDER BY received_at DESC LIMIT ? OFFSET ?"
        args += [limit, offset]
        with self.lock:
            return [self._row(r, full=False) for r in self.db.execute(sql, args)]

    def count(self, tenant: str, verdict: str | None = None, q: str | None = None, source: str | None = None,
              day: str | None = None) -> int:
        w, args = self._where(tenant, verdict, q, source, day)
        sql = "SELECT COUNT(*) FROM messages" + w
        with self.lock:
            return self.db.execute(sql, args).fetchone()[0]

    def briefs(self, tenant: str, ids: list[str]) -> dict[str, dict]:
        out: dict[str, dict] = {}
        with self.lock:
            for i in range(0, len(ids), 400):
                chunk = ids[i:i + 400]
                for r in self.db.execute(
                        f"SELECT * FROM messages WHERE tenant=? AND id IN ({','.join('?' * len(chunk))})", [tenant, *chunk]):
                    out[r["id"]] = self._row(r, full=False)
        return out

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
                "by_source": {r[0]: r[1] for r in q("SELECT source, COUNT(*) FROM messages WHERE tenant=? GROUP BY source")},
                "by_variety": {r[0]: r[1] for r in q("SELECT variety, COUNT(*) FROM messages WHERE tenant=? AND verdict!='benign' GROUP BY variety")},
                "by_channel": {r[0]: r[1] for r in q("SELECT channel, COUNT(*) FROM messages WHERE tenant=? GROUP BY channel")},
                "by_day": [{"day": r[0], "verdict": r[1], "n": r[2]} for r in q(
                    "SELECT substr(received_at,1,10), verdict, COUNT(*) FROM messages WHERE tenant=? GROUP BY 1,2 ORDER BY 1")],
                "score_hist": [{"bin": r[0], "verdict": r[1], "n": r[2]} for r in q(
                    "SELECT MIN(CAST(score*10 AS INTEGER), 9), verdict, COUNT(*) FROM messages WHERE tenant=? GROUP BY 1,2 ORDER BY 1")],
                "indicators_distinct": q("SELECT COUNT(*) FROM (SELECT DISTINCT type, value FROM indicators WHERE tenant=?)")[0][0],
                "indicators_by_type": {r[0]: r[1] for r in q(
                    "SELECT type, COUNT(DISTINCT value) FROM indicators WHERE tenant=? GROUP BY type ORDER BY 2 DESC")},
                "top_indicators": [{"type": r[0], "value": r[1], "messages": r[2]} for r in q(
                    "SELECT i.type, i.value, COUNT(DISTINCT i.message_id) c FROM indicators i JOIN messages m "
                    "ON m.tenant=i.tenant AND m.id=i.message_id WHERE i.tenant=? AND i.linkable=1 AND i.role='body' "
                    "AND m.verdict!='benign' GROUP BY 1,2 HAVING c>1 ORDER BY c DESC LIMIT 15")],
            }

    # ------------------------------------------------------------------ indicators (aggregated)
    def indicator_groups(self, tenant: str) -> list[dict]:
        sql = ("SELECT i.type, i.value, MAX(i.linkable) linkable, GROUP_CONCAT(DISTINCT i.role) roles, "
               "COUNT(DISTINCT i.message_id) messages, GROUP_CONCAT(DISTINCT i.message_id) mids, "
               "MIN(m.received_at) first_seen, MAX(m.received_at) last_seen, MAX(m.score) max_score, "
               "SUM(m.verdict='malicious') malicious, SUM(m.verdict='suspicious') suspicious, SUM(m.verdict='benign') benign "
               "FROM indicators i JOIN messages m ON m.tenant=i.tenant AND m.id=i.message_id "
               "WHERE i.tenant=? GROUP BY i.type, i.value")
        with self.lock:
            rows = self.db.execute(sql, (tenant,)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["message_ids"] = sorted(set((d.pop("mids") or "").split(",")) - {""})
            d["roles"] = sorted(set((d["roles"] or "").split(",")) - {""})
            d["linkable"] = bool(d["linkable"])
            d["key"] = f"{d['type']}:{d['value']}"
            out.append(d)
        return out

    # ------------------------------------------------------------------ operations & audit
    def record_op(self, tenant: str | None, op: str, status: str, duration_ms: float | None = None,
                  items: int | None = None, detail: str = "") -> None:
        with self.lock, self.db:
            self.db.execute("INSERT INTO operations VALUES(?,?,?,?,?,?,?)",
                            (_now(), tenant, op, status, None if duration_ms is None else round(duration_ms, 2), items, detail[:500]))

    def ops(self, tenant: str | None, limit: int = 50, status: str | None = None, since: str | None = None) -> list[dict]:
        sql, args = "SELECT * FROM operations WHERE (tenant=? OR tenant IS NULL)", [tenant]
        if status:
            sql += " AND status=?"; args.append(status)
        if since:
            sql += " AND ts>=?"; args.append(since)
        sql += " ORDER BY ts DESC LIMIT ?"; args.append(limit)
        with self.lock:
            return [dict(r) for r in self.db.execute(sql, args)]

    def ops_summary(self, tenant: str | None, since: str) -> dict:
        with self.lock:
            rows = self.db.execute("SELECT op, status, COUNT(*), SUM(items), AVG(duration_ms) FROM operations "
                                   "WHERE (tenant=? OR tenant IS NULL) AND ts>=? GROUP BY 1,2", (tenant, since)).fetchall()
        return [{"op": r[0], "status": r[1], "count": r[2], "items": r[3], "avg_ms": round(r[4] or 0, 2)} for r in rows]

    def audit(self, tenant: str, action: str, detail: str = "") -> None:
        with self.lock, self.db:
            self.db.execute("INSERT INTO audit VALUES(?,?,?,?)", (_now(), tenant, action, detail))

    # ------------------------------------------------------------------ investigations
    def create_investigation(self, tenant: str, campaign_id: str, title: str, notes: str = "") -> dict:
        now = _now()
        iid = "inv_" + uuid.uuid4().hex[:10]
        with self.lock, self.db:
            self.db.execute("INSERT INTO investigations VALUES(?,?,?,?,?,?,?,?)",
                            (tenant, iid, campaign_id, title, "open", notes, now, now))
        return self.get_investigation(tenant, iid)

    def get_investigation(self, tenant: str, iid: str) -> dict | None:
        with self.lock:
            r = self.db.execute("SELECT * FROM investigations WHERE tenant=? AND id=?", (tenant, iid)).fetchone()
        return {k: r[k] for k in EXPLORABLE["investigations"]} if r else None

    def update_investigation(self, tenant: str, iid: str, status: str | None, notes: str | None) -> dict | None:
        with self.lock, self.db:
            if status:
                self.db.execute("UPDATE investigations SET status=?, updated_at=? WHERE tenant=? AND id=?", (status, _now(), tenant, iid))
            if notes is not None:
                self.db.execute("UPDATE investigations SET notes=?, updated_at=? WHERE tenant=? AND id=?", (notes, _now(), tenant, iid))
        return self.get_investigation(tenant, iid)

    def investigations(self, tenant: str, status: str | None = None, campaign_id: str | None = None) -> list[dict]:
        sql, args = "SELECT * FROM investigations WHERE tenant=?", [tenant]
        if status:
            sql += " AND status=?"; args.append(status)
        if campaign_id:
            sql += " AND campaign_id=?"; args.append(campaign_id)
        with self.lock:
            return [{k: r[k] for k in EXPLORABLE["investigations"]} for r in self.db.execute(sql + " ORDER BY updated_at DESC", args)]

    # ------------------------------------------------------------------ database explorer (read-only)
    def _pragma(self, name: str):
        return self.db.execute(f"PRAGMA {name}").fetchone()[0]

    def db_overview(self, tenant: str) -> dict:
        with self.lock:
            page_size, page_count, freelist = self._pragma("page_size"), self._pragma("page_count"), self._pragma("freelist_count")
            tables = []
            for name in EXPLORABLE:
                n_tenant = self.db.execute(f"SELECT COUNT(*) FROM {name} WHERE tenant=?", (tenant,)).fetchone()[0]
                last_col = {"messages": "ingested_at", "operations": "ts", "audit": "ts", "investigations": "updated_at"}.get(name)
                last = self.db.execute(f"SELECT MAX({last_col}) FROM {name} WHERE tenant=?", (tenant,)).fetchone()[0] if last_col else None
                tables.append({"name": name, "rows": n_tenant, "last_write": last, "columns": len(self.columns(name))})
            meta = {r[0]: r[1] for r in self.db.execute("SELECT key, value FROM schema_meta")}
            return {
                "engine": "SQLite", "engine_version": sqlite3.sqlite_version, "connection": "open",
                "file": os.path.basename(self.path) if self.path != ":memory:" else ":memory: (in-process, not persisted)",
                "persistent": self.path != ":memory:",
                "size_bytes": page_size * page_count, "free_bytes": page_size * freelist,
                "journal_mode": self._pragma("journal_mode"), "schema_version": meta.get("schema_version"),
                "tables": tables, "derived_views": DERIVED_VIEWS,
                "row_counts_scope": "rows belonging to your tenant",
                "messages_by_source": {r[0]: r[1] for r in self.db.execute(
                    "SELECT source, COUNT(*) FROM messages WHERE tenant=? GROUP BY source", (tenant,))},
            }

    def columns(self, table: str) -> list[dict]:
        return [{"name": r["name"], "type": r["type"], "not_null": bool(r["notnull"]), "pk": r["pk"],
                 "default": r["dflt_value"]} for r in self.db.execute(f"PRAGMA table_info({table})")]

    def schema(self) -> dict:
        with self.lock:
            out = []
            for name in [*EXPLORABLE, "schema_meta"]:
                idx = []
                for ix in self.db.execute(f"PRAGMA index_list({name})"):
                    idx.append({"name": ix["name"], "unique": bool(ix["unique"]),
                                "columns": [c["name"] for c in self.db.execute(f"PRAGMA index_info('{ix['name']}')")]})
                fks = [{"column": f["from"], "references": f"{f['table']}.{f['to']}"} for f in self.db.execute(f"PRAGMA foreign_key_list({name})")]
                sql = self.db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone()
                out.append({"name": name, "columns": self.columns(name), "indexes": idx, "declared_foreign_keys": fks,
                            "ddl": sql[0] if sql else None, "explorable": name in EXPLORABLE})
        return {"tables": out, "relations": [{"from": f"{t}.{c}", "to": ref, "kind": k, "description": d,
                                              "description_ar": RELATIONS_AR.get(f"{t}.{c}")}
                                             for t, c, ref, k, d in RELATIONS],
                "derived_views": DERIVED_VIEWS}

    def integrity(self, tenant: str) -> list[dict]:
        with self.lock:
            checks = []
            qc = self.db.execute("PRAGMA quick_check").fetchone()[0]
            checks.append({"check": "sqlite quick_check", "status": "ok" if qc == "ok" else "fail", "detail": qc})
            orphans = self.db.execute(
                "SELECT COUNT(*) FROM indicators i LEFT JOIN messages m ON m.tenant=i.tenant AND m.id=i.message_id "
                "WHERE i.tenant=? AND m.id IS NULL", (tenant,)).fetchone()[0]
            checks.append({"check": "indicators.message_id → messages.id (orphans)", "status": "ok" if not orphans else "fail",
                           "detail": f"{orphans} orphan rows"})
            try:
                bad = self.db.execute("SELECT COUNT(*) FROM messages WHERE tenant=? AND json_valid(analysis)=0", (tenant,)).fetchone()[0]
                checks.append({"check": "messages.analysis is valid JSON", "status": "ok" if not bad else "fail", "detail": f"{bad} invalid"})
            except sqlite3.OperationalError:
                checks.append({"check": "messages.analysis is valid JSON", "status": "unavailable", "detail": "JSON1 not compiled in"})
            unk = self.db.execute(f"SELECT COUNT(*) FROM messages WHERE tenant=? AND source NOT IN ({','.join('?' * len(SOURCES))})",
                                  (tenant, *SOURCES)).fetchone()[0]
            checks.append({"check": "messages.source within allowed values", "status": "ok" if not unk else "fail", "detail": f"{unk} invalid"})
            dup = self.db.execute("SELECT COUNT(*) FROM (SELECT 1 FROM indicators WHERE tenant=? GROUP BY message_id,type,value,role "
                                  "HAVING COUNT(*)>1)", (tenant,)).fetchone()[0]
            checks.append({"check": "no duplicate indicator rows per message", "status": "ok" if not dup else "warn", "detail": f"{dup} duplicates"})
        return checks

    def table_rows(self, tenant: str, table: str, q: str | None = None, filters: dict | None = None,
                   limit: int = 50, offset: int = 0) -> dict:
        if table not in EXPLORABLE:
            raise KeyError(table)
        cols = EXPLORABLE[table]
        where, args = ["tenant=?"], [tenant]
        for col, val in (filters or {}).items():
            if col not in cols:
                raise ValueError(f"unknown column {col}")
            where.append(f"{col}=?"); args.append(val)
        if q:
            where.append("(" + " OR ".join(f"CAST({c} AS TEXT) LIKE ?" for c in _SEARCHABLE[table]) + ")")
            args += [f"%{q}%"] * len(_SEARCHABLE[table])
        extra = ", length(analysis) AS analysis_bytes" if table == "messages" else ""
        with self.lock:
            total = self.db.execute(f"SELECT COUNT(*) FROM {table} WHERE {' AND '.join(where)}", args).fetchone()[0]
            rows = self.db.execute(f"SELECT rowid AS _rowid, {', '.join(cols)}{extra} FROM {table} WHERE {' AND '.join(where)} "
                                   f"ORDER BY {_ORDER[table]} LIMIT ? OFFSET ?", [*args, limit, offset]).fetchall()
        return {"table": table, "columns": ["_rowid", *cols] + (["analysis_bytes"] if extra else []),
                "total": total, "limit": limit, "offset": offset, "rows": [dict(r) for r in rows]}

    def table_record(self, tenant: str, table: str, rowid: int) -> dict | None:
        if table not in EXPLORABLE:
            raise KeyError(table)
        with self.lock:
            r = self.db.execute(f"SELECT rowid AS _rowid, * FROM {table} WHERE tenant=? AND rowid=?", (tenant, rowid)).fetchone()
            if not r:
                return None
            rec = {k: r[k] for k in r.keys() if k != "tenant"}
            related: dict = {}
            if table == "messages":
                rec["analysis"] = json.loads(rec["analysis"])
                related["indicators"] = [dict(x) for x in self.db.execute(
                    "SELECT rowid AS _rowid, type, value, role, linkable FROM indicators WHERE tenant=? AND message_id=?", (tenant, r["id"]))]
            elif table == "indicators":
                m = self.db.execute("SELECT rowid AS _rowid, id, verdict, score, source, received_at FROM messages "
                                    "WHERE tenant=? AND id=?", (tenant, r["message_id"])).fetchone()
                related["message"] = dict(m) if m else None
                related["same_value_rows"] = self.db.execute("SELECT COUNT(*) FROM indicators WHERE tenant=? AND type=? AND value=?",
                                                             (tenant, r["type"], r["value"])).fetchone()[0]
        return {"table": table, "record": rec, "related": related}

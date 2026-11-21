"""Fixed dev/test split of the external real dataset. Lexicon work may look at
DEV only; TEST is reported untouched (see docs/04-evaluation.md)."""
import csv
import hashlib


def load(path: str) -> list[dict]:
    with open(path, encoding="utf-8-sig", newline="") as fh:
        rows = [(r[0], int(r[1])) for r in list(csv.reader(fh))[1:] if len(r) >= 2 and r[1] in ("0", "1")]
    seen, data = set(), []
    for t, y in rows:
        if t not in seen:
            seen.add(t)
            part = "dev" if int(hashlib.sha256(t.encode()).hexdigest(), 16) % 2 == 0 else "test"
            data.append({"text": t, "label": y, "id": f"ext-{len(data)}", "received_at": None, "part": part})
    return data

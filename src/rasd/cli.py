"""rasd CLI:  analyze | serve | seed | eval"""
from __future__ import annotations

import argparse
import json
import sys


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="rasd", description="RASD — Arabic Threat Intelligence")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("analyze", help="analyse one message (reads stdin when TEXT is '-')")
    a.add_argument("text"); a.add_argument("--sender"); a.add_argument("--lang", default="ar", choices=["ar", "en"])
    a.add_argument("--json", action="store_true")
    s = sub.add_parser("serve", help="run the API + dashboard")
    s.add_argument("--host", default="127.0.0.1"); s.add_argument("--port", type=int, default=8000)
    d = sub.add_parser("seed", help="load the synthetic test-bench corpus into a database (demo data, clearly synthetic)")
    d.add_argument("--db", default="rasd.db"); d.add_argument("--tenant", default="default"); d.add_argument("--seed", type=int, default=7)
    x = sub.add_parser("export-demo", help="write a static, read-only snapshot of the dashboard API (synthetic data) for static hosting")
    x.add_argument("--out", required=True); x.add_argument("--seed", type=int, default=7)
    e = sub.add_parser("eval", help="run the evaluation harness and print the report")
    e.add_argument("--seed", type=int, default=7); e.add_argument("--out"); e.add_argument("--external")
    args = ap.parse_args(argv)

    if args.cmd == "analyze":
        from .analysis import Analyzer
        from .models import Message
        from .xai import explain
        text = sys.stdin.read() if args.text == "-" else args.text
        an = Analyzer().analyze(Message(text, sender=args.sender)).to_dict()
        ex = explain(an, args.lang)
        if args.json:
            print(json.dumps({"analysis": an, "explanation": ex}, ensure_ascii=False, indent=2))
        else:
            print(ex["summary"])
            for r in ex["reasons"]:
                print(f"  {r['weight']:+.2f}  {r['text']}")
            if ex["guard"]:
                print("  !", ex["guard"])
            for i in an["indicators"]:
                print(f"  IOC {i['key']}" + ("" if i["linkable"] else "  (non-linking)"))
        return 0
    if args.cmd == "serve":
        import uvicorn
        from .api.app import create_app
        uvicorn.run(create_app(), host=args.host, port=args.port)
        return 0
    if args.cmd == "seed":
        from .eval.generator import generate
        from .models import Message
        from .service import Rasd
        from .storage import Store
        r = Rasd(store=Store(args.db))
        corpus = generate(seed=args.seed)
        for m in corpus:
            r.ingest(args.tenant, Message(m["text"], id=m["id"], sender=m["sender"], channel=m["channel"],
                                          received_at=m["received_at"], source="synthetic"))
        print(f"seeded {len(corpus)} synthetic messages into {args.db}; campaigns found: {len(r.graph(args.tenant).campaigns)}")
        return 0
    if args.cmd == "export-demo":
        from .demo_export import export
        n = export(args.out, seed=args.seed)
        print(f"wrote {n} snapshot files to {args.out}")
        return 0
    if args.cmd == "eval":
        from .eval.run import main as run_eval
        return run_eval(seed=args.seed, out=args.out, external=args.external)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

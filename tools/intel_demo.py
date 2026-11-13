#!/usr/bin/env python3
"""Oracle Intelligence v0.1 demo on the SYNTHETIC sample data. Uses a temporary database and audit log,
so it never touches your real stores:  python3 tools/intel_demo.py [--keep DIR]"""
import os
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
EX = os.path.join(ROOT, "examples", "intelligence")
QUESTION = "Identify emerging trends across semiconductor companies and supply chains."

SOURCES = [
    ("Synthetic Market Weekly (example)", "public_market", "file_upload",
     "SYNTHETIC weekly closing values for fictional semiconductor companies", "sample_market_weekly_SYNTHETIC.csv", "csv", {}),
    ("Synthetic Internal Logistics (example)", "internal_docs", "file_upload",
     "SYNTHETIC supply chain lead times for a fictional semiconductor fab", "sample_logistics_leadtime_SYNTHETIC.csv", "csv", {}),
    ("Synthetic Company Filings (example)", "public_filings", "manual",
     "SYNTHETIC quarterly update for a fictional semiconductor company", "sample_filing_SYNTHETIC.txt", "text",
     {"title": "SYN-FAB quarterly update (example)", "doc_type": "filing", "published_at": "2026-10-01"}),
    ("Synthetic Logistics Memos (example)", "internal_docs", "manual",
     "SYNTHETIC internal supply chain memo", "sample_logistics_memo_SYNTHETIC.txt", "text", {"doc_type": "logistics_report"}),
]


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    d = argv[argv.index("--keep") + 1] if "--keep" in argv else tempfile.mkdtemp(prefix="intel-demo-")
    os.makedirs(d, exist_ok=True)
    os.environ["PATIENCE_AUDIT_PATH"] = os.path.join(d, "audit.jsonl")
    from oracle_intelligence import ingest, inquiry, sources
    from oracle_intelligence.report import to_markdown
    from oracle_intelligence.store import Store
    import audit
    store = Store(os.path.join(d, "patience_intelligence.db"))
    clk = time.time
    ids = []
    for name, cat, kind, desc, fname, fmt, extra in SOURCES:
        s = sources.register_source(store, actor="demo-approver", name=name, category=cat, kind=kind, description=desc,
                                    license_note="SYNTHETIC example data created for this repository; no third-party rights",
                                    allowed_callers=["demo-analyst"], clock=clk)
        with open(os.path.join(EX, fname), encoding="utf-8") as f:
            r = ingest.ingest(store, caller="demo-analyst", source_id=s["source_id"], fmt=fmt, content=f.read(), clock=clk, **extra)
        print(f"ingested {fname}: stored={r['stored']} duplicates={r['duplicates']} invalid={r['invalid']} quarantined={r['quarantined']}", file=sys.stderr)
        ids.append(s["source_id"])
    rep = inquiry.run_inquiry(store, caller="demo-analyst", question=QUESTION, clock=clk)
    print(to_markdown(rep))
    v = audit.verify()
    print(f"\n---\naudit chain: ok={v['ok']} records={v['records']}   store: {store.counts()}   dir: {d}", file=sys.stderr)
    return 0 if v["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())

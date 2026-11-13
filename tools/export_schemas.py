#!/usr/bin/env python3
"""Write (or --check) the published JSON Schema files under schemas/ from the pydantic models.

  python3 tools/export_schemas.py           regenerate schemas/*.schema.json
  python3 tools/export_schemas.py --check   exit 1 if a committed file differs from its model
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


def schemas() -> dict:
    from dev_governance.decision_schema import DecisionRecord
    from dev_governance.oracle_advisor.schema import Recommendation
    from oracle_intelligence.report import Report
    out = {}
    for fname, model, sid in (("decision-v1.schema.json", DecisionRecord, "https://patience.local/schemas/decision-v1.json"),
                              ("oracle-rec-v1.schema.json", Recommendation, "https://patience.local/schemas/oracle-rec-v1.json"),
                              ("intel-report-v1.schema.json", Report, "https://patience.local/schemas/intel-report-v1.json")):
        s = model.model_json_schema()
        out[fname] = {"$schema": "https://json-schema.org/draft/2020-12/schema", "$id": sid, **s}
    return out


def render(obj) -> str:
    return json.dumps(obj, indent=2, sort_keys=True) + "\n"


def main(argv=None):
    check = "--check" in (argv if argv is not None else sys.argv[1:])
    bad = 0
    for fname, obj in schemas().items():
        path = os.path.join(ROOT, "schemas", fname)
        text = render(obj)
        if check:
            if not os.path.exists(path) or open(path, encoding="utf-8").read() != text:
                print(f"DIFFERS: {fname}")
                bad += 1
        else:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                f.write(text)
            print(f"wrote schemas/{fname}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())

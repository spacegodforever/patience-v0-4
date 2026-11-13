"""Builds the HAND-BUILT SEC EDGAR fixtures (run: python3 tests/data/sec_edgar/make_fixtures.py).

These are NOT recorded SEC responses. They are hand-built to match the real response shape (top-level keys and
per-fact keys were checked against real data.sec.gov responses for a large semiconductor company read through a
web fetch tool on 2026-11-13; those real bodies were truncated by the tool at ~100 KB, so no real numbers could be
trimmed into fixtures). The company is fictitious and every number is synthetic: EXAMPLE SEMI CORP, CIK 0009990001.
"""
import json
from pathlib import Path

OUT = Path(__file__).parent
CIK = 9990001
NAME = "EXAMPLE SEMI CORP"


def accn(y, n):
    return f"{CIK:010d}-{y % 100:02d}-{n:06d}"


# (fiscal year, quarter) -> (period start, period end, form, accession, filed date, revenue, net income)
Q = [
    (2023, "Q1", "2023-01-01", "2023-03-31", "10-Q", accn(2023, 11), "2023-05-04", 1_000_000_000, 100_000_000),
    (2023, "Q2", "2023-04-01", "2023-06-30", "10-Q", accn(2023, 22), "2023-08-03", 1_080_000_000, 112_000_000),
    (2023, "Q3", "2023-07-01", "2023-09-30", "10-Q", accn(2023, 33), "2023-11-02", 1_150_000_000, 120_000_000),
    (2024, "Q1", "2024-01-01", "2024-03-31", "10-Q", accn(2024, 11), "2024-05-02", 1_210_000_000, 131_000_000),
    (2024, "Q2", "2024-04-01", "2024-06-30", "10-Q", accn(2024, 22), "2024-08-01", 1_300_000_000, 145_000_000),
    (2024, "Q3", "2024-07-01", "2024-09-30", "10-Q", accn(2024, 33), "2024-10-31", 1_260_000_000, 138_000_000),
    (2025, "Q1", "2025-01-01", "2025-03-31", "10-Q", accn(2025, 11), "2025-05-01", 1_350_000_000, 150_000_000),
    (2025, "Q2", "2025-04-01", "2025-06-30", "10-Q", accn(2025, 22), "2025-07-31", 1_420_000_000, 160_000_000),
    (2025, "Q3", "2025-07-01", "2025-09-30", "10-Q", accn(2025, 33), "2025-10-30", 1_500_000_000, 171_000_000),
]
ANNUAL = [
    (2023, "2023-01-01", "2023-12-31", accn(2024, 5), "2024-02-15", 4_500_000_000, 480_000_000),
    (2024, "2024-01-01", "2024-12-31", accn(2025, 5), "2025-02-14", 5_250_000_000, 560_000_000),
]


def frame(end, quarterly):
    y, m = int(end[:4]), int(end[5:7])
    return f"CY{y}Q{(m - 1) // 3 + 1}" if quarterly else f"CY{y}"


def fact(start, end, val, ac, filed, form, fy, fp, fr=None):
    d = {"start": start, "end": end, "val": val, "accn": ac, "fy": fy, "fp": fp, "form": form, "filed": filed}
    if fr:
        d["frame"] = fr
    return d


def concept(label, desc, facts):
    return {"label": label, "description": desc, "units": {"USD": facts}}


rev_old, rev_new, ni = [], [], []
for fy, fp, s, e, form, ac, filed, rev, net in Q:
    fr = frame(e, True)
    (rev_old if fy == 2023 else rev_new).append(fact(s, e, rev, ac, filed, form, fy, fp, fr))
    if fy == 2024 and fp in ("Q1", "Q2"):          # same period also reported under the older concept (priority test)
        rev_old.append(fact(s, e, rev, ac, filed, form, fy, fp, fr))
    ni.append(fact(s, e, net, ac, filed, form, fy, fp, fr))
    if fp == "Q2":                                   # 6-month year-to-date values exist in real 10-Qs; must NOT be mapped
        rev_new.append(fact(s[:5] + "01-01", e, rev * 2, ac, filed, form, fy, fp))
        ni.append(fact(s[:5] + "01-01", e, net * 2, ac, filed, form, fy, fp))
# comparative restatement of a prior-year quarter inside a later 10-Q (same value, later filing): dedupe/latest-filed
rev_new.append(fact("2023-01-01", "2023-03-31", 1_000_000_000, accn(2024, 11), "2024-05-02", "10-Q", 2024, "Q1"))
for fy, s, e, ac, filed, rev, net in ANNUAL:
    rev_new.append(fact(s, e, rev, ac, filed, "10-K", fy, "FY", frame(e, False)))
    ni.append(fact(s, e, net, ac, filed, "10-K", fy, "FY", frame(e, False)))
rev_new.append(fact("2024-10-01", "2024-12-31", 1_390_000_000, accn(2025, 5), "2025-02-14", "10-K", 2024, "FY", "CY2024Q4"))
ni.append(fact("2024-10-01", "2024-12-31", 152_000_000, accn(2025, 5), "2025-02-14", "10-K", 2024, "FY", "CY2024Q4"))

companyfacts = {
    "cik": CIK, "entityName": NAME,
    "facts": {
        "dei": {"EntityCommonStockSharesOutstanding": {"label": "Entity Common Stock, Shares Outstanding", "description": "dei example",
                "units": {"shares": [{"end": "2025-10-20", "val": 500000000, "accn": accn(2025, 33), "fy": 2025, "fp": "Q3",
                                      "form": "10-Q", "filed": "2025-10-30", "frame": "CY2025Q4I"}]}}},
        "us-gaap": {
            "Revenues": concept("Revenues", "Amount of revenue recognized from goods sold, services rendered, and other.", rev_old),
            "RevenueFromContractWithCustomerExcludingAssessedTax": concept(
                "Revenue from Contract with Customer, Excluding Assessed Tax", "Amount of revenue recognized.", rev_new),
            "NetIncomeLoss": concept("Net Income (Loss) Attributable to Parent", "Portion of profit or loss.", ni),
            "Assets": {"label": "Assets", "description": "Sum of the carrying amounts of all assets.",
                       "units": {"USD": [{"end": "2025-09-30", "val": 9_000_000_000, "accn": accn(2025, 33), "fy": 2025, "fp": "Q3",
                                          "form": "10-Q", "filed": "2025-10-30", "frame": "CY2025Q3I"}]}},
            "SomeForeignDenominatedItem": {"label": "x", "description": "x", "units": {"EUR": [{"start": "2025-01-01", "end": "2025-03-31",
                                           "val": 5, "accn": accn(2025, 11), "fy": 2025, "fp": "Q1", "form": "10-Q", "filed": "2025-05-01"}]}},
        },
    },
}

forms = [("10-Q", "2025-10-30", "2025-09-30", accn(2025, 33), "", "Form 10-Q"), ("8-K", "2025-10-30", "2025-10-30", accn(2025, 34), "2.02,9.01", "Form 8-K"),
         ("4", "2025-10-01", "2025-09-29", accn(2025, 40), "", "Form 4"), ("10-Q", "2025-07-31", "2025-06-30", accn(2025, 22), "", "Form 10-Q"),
         ("10-K", "2025-02-14", "2024-12-31", accn(2025, 5), "", "Form 10-K")]
submissions = {
    "cik": f"{CIK:010d}", "entityType": "operating", "sic": "3674", "sicDescription": "Semiconductors & Related Devices",
    "ownerOrg": "04 Manufacturing", "insiderTransactionForOwnerExists": 0, "insiderTransactionForIssuerExists": 1, "name": NAME,
    "tickers": ["EXSC"], "exchanges": ["Nasdaq"], "ein": "000000000", "lei": None, "description": "", "website": "", "investorWebsite": "",
    "category": "Large accelerated filer", "fiscalYearEnd": "1231", "stateOfIncorporation": "DE", "stateOfIncorporationDescription": "DE",
    "addresses": {"mailing": {"street1": "1 SYNTHETIC WAY", "city": "EXAMPLETOWN", "stateOrCountry": "CA"}},
    "phone": "", "flags": "", "formerNames": [],
    "filings": {"recent": {
        "accessionNumber": [f[3] for f in forms], "filingDate": [f[1] for f in forms], "reportDate": [f[2] for f in forms],
        "acceptanceDateTime": [f[1] + "T16:05:00.000Z" for f in forms], "act": ["34"] * len(forms), "form": [f[0] for f in forms],
        "fileNumber": ["000-00000"] * len(forms), "filmNumber": [""] * len(forms), "items": [f[4] for f in forms],
        "core_type": [""] * len(forms), "size": [1000] * len(forms), "isXBRL": [1] * len(forms), "isInlineXBRL": [1] * len(forms),
        "primaryDocument": ["doc.htm"] * len(forms), "primaryDocDescription": [f[5] for f in forms]}, "files": []},
}
(OUT / "companyfacts_CIK0009990001_HANDBUILT.json").write_text(json.dumps(companyfacts, separators=(",", ":")), encoding="utf-8")
(OUT / "submissions_CIK0009990001_HANDBUILT.json").write_text(json.dumps(submissions, separators=(",", ":")), encoding="utf-8")
print("ok")

#!/usr/bin/env python3
"""Audit report generator and verifier. Standard library only; imports NO PATIENCE code.

Reads the append-only, tamper-evident audit log (JSONL hash chain) and writes a REDACTED summary of
what was proposed, approved, refused and executed, filtered by agent and period. It only ever READS
the log: it refuses to write its output over the log, its .head file or its lock file.

  generate  LOG [--agent A] [--since ISO] [--until ISO] [--allow-key K ...] [--format json|md|csv] [--out FILE]
  verify    REPORT LOG          exit 0 consistent, 1 not consistent / log broken, 2 usage or IO error

Chain binding (`chain` section of the report): number of log records at generation, the head hash,
the first/last seq and hash of the records inside the period, and a digest over the selected
(seq, hash) pairs. `verify` (1) runs tools/verify_audit.py's checker on the log, (2) checks the log
still contains the report's head hash at the same position (the log may have grown since, never
shrunk or been rewritten), and (3) regenerates the report from the log with the report's own filters,
capped at the report's record count, and requires an exact match, so an edited, dropped, added or
re-ordered report entry is detected. `report_hash` only detects accidental corruption of the report
file; it is not a signature and does not authenticate who wrote the report.

Limits: verification needs the original log (redacted events cannot be re-hashed from the report
alone). Someone who can rewrite the log, its .head file AND the report consistently is not detected
unless the head hash is pinned somewhere they cannot reach (`verify_audit.py --expect-head`).
Redaction is best-effort pattern matching plus an allow-list; it is not a guarantee that nothing
sensitive survives in free-text fields.
"""
from __future__ import annotations
import argparse
import csv
import hashlib
import importlib.util
import io
import json
import os
import re
import sys
from datetime import datetime, timezone

SCHEMA_VERSION = "audit-report-v1"
REDACTION_VERSION = "redaction-v1"
GENESIS = "0" * 64
HERE = os.path.dirname(os.path.abspath(__file__))

# ---------------------------------------------------------------- redaction
# 1) DENY-LIST: key names that are never shown, even if someone allow-lists them.
DENY_KEY_RE = re.compile(r"(token|secret|passw|api_?key|private|signature|credential|authoriz|cookie|bearer|"
                         r"attestation|^permit$|^sig$|_sig$|^key$|_key$|nonce)", re.I)
# keys that merely CONTAIN a deny word but are identifiers, not secrets (explicitly safe)
DENY_EXCEPTIONS = frozenset({"key_id", "permit_id", "expiry_sig_ok", "kid"})
# 2) ALLOW-LIST: keys whose (scrubbed) values may appear. Everything else is withheld.
ALLOW_KEYS = frozenset({
    "request_id", "action", "tier", "known", "payload_hash", "expected", "got", "count", "required", "approvals",
    "status", "category", "reason_code", "permit_id", "key_id", "issued_at", "expires_at", "agent", "proposer",
    "simulated", "dry_run", "claimed_at", "outcome", "what", "kind", "rec_id", "backend", "model_id", "prompt_hash",
    "output_hash", "confidence_level", "risk_hint_suggested", "risk_hint_applied", "basis_count", "unknowns_count",
    "quote_unverified", "context_sources", "latency_ms", "schema_version", "oracle_version", "limits_version",
    "advisory_only", "code", "risk_floor_applied", "amount_usd", "currency", "owners", "reasons", "reason", "error",
    "note", "why", "violations", "prior_reason", "was_frozen", "channel", "scope", "invoice_id", "from_tier",
    "to_tier", "min_age_seconds", "flagged", "approved"})
# free-text keys additionally pass through the value scrubber
SCRUB_RES = [
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/=\-]{8,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(-----END [A-Z ]*PRIVATE KEY-----|$)", re.S),
    re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]*"),            # JWT-like
    re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr|github_pat|glpat|xox[abprs]|sk|rk|pk)[-_][A-Za-z0-9_\-]{12,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"(?i)\b(pass(?:word|wd)?|secret|token|api[_-]?key|authorization)\s*[=:]\s*\S+"),
    re.compile(r"\bpv\d?\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}"),                         # permit-like
    re.compile(r"(?<![0-9a-fA-F])[A-Za-z0-9_\-+/]{40,}={0,2}(?![0-9a-fA-F])"),                # long opaque runs
]
HASH_KEYS_RE = re.compile(r"(hash|_id)$")
MAX_STR = 500
REDACTED = "[REDACTED]"


class Redactor:
    def __init__(self, extra_allow=()):
        self.allow = ALLOW_KEYS | {k for k in extra_allow if isinstance(k, str)}
        self.counts = {"denied_key": 0, "withheld_key": 0, "scrubbed_value": 0}

    def _scrub(self, s: str) -> str:
        for rx in SCRUB_RES:
            s2 = rx.sub(REDACTED, s)
            if s2 != s:
                self.counts["scrubbed_value"] += 1
                s = s2
        return s[:MAX_STR]

    def value(self, key: str, v):
        if isinstance(v, bool) or v is None or isinstance(v, (int, float)):
            return v
        if isinstance(v, str):
            if HASH_KEYS_RE.search(key) and re.fullmatch(r"[0-9a-f]{16,128}|[A-Za-z0-9_.:\-]{1,80}", v):
                return v
            return self._scrub(v)
        if isinstance(v, list):
            return [self.value(key, x) for x in v[:50]]
        if isinstance(v, dict):
            return self.data(v)
        return REDACTED

    def data(self, d: dict) -> dict:
        out = {}
        for k in sorted(d, key=str):
            ks = str(k)
            if DENY_KEY_RE.search(ks) and ks not in DENY_EXCEPTIONS:
                out[ks] = REDACTED
                self.counts["denied_key"] += 1
            elif ks not in self.allow:
                v = d[k]
                out[ks] = f"[withheld:{type(v).__name__}]"
                self.counts["withheld_key"] += 1
            else:
                out[ks] = self.value(ks, d[k])
        return out


# ---------------------------------------------------------------- classification
CATEGORY = {
    "dev.proposed": "proposed", "dev.approved": "approved", "dev.denied": "denied",
    "dev.executed": "executed", "dev.execute.failed": "execution_failed", "dev.execute.claimed": "execute_claimed",
    "dev.execute.needs_review": "needs_review", "dev.execute.resolved": "resolved",
    "dev.execute.unapproved_attempt": "execute_attempt_unapproved", "dev.execute.denied_attempt": "execute_attempt_denied",
    "dev.permit.issued": "permit_issued", "gateway.accepted": "permit_used", "gateway.rejected": "permit_rejected",
    "gateway.payment_executed": "executed", "gateway.payment_failed": "execution_failed", "dev.expired": "expired",
}
REFUSED = {"dev.destructive.refused", "dev.propose.rejected", "dev.self_approval_rejected", "dev.self_resolution_rejected",
           "dev.execute.forbidden", "dev.permit.forbidden", "dev.authority.refused", "dev.permit.refused",
           "dev.payload_mismatch", "dev.kill_switch.blocked", "dev.breaker.held", "dev.expiry.tampered"}


def category(event: str) -> str:
    if event in CATEGORY:
        return CATEGORY[event]
    if event in REFUSED:
        return "refused"
    if event.startswith("oracle."):
        return "oracle"
    return "other"


# ---------------------------------------------------------------- reading
def _verify_mod():
    spec = importlib.util.spec_from_file_location("verify_audit", os.path.join(HERE, "verify_audit.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def parse_ts(s):
    if s is None:
        return None
    d = datetime.fromisoformat(str(s).strip().replace("Z", "+00:00"))
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    return d


def _load(log_path):
    recs = []
    if not os.path.exists(log_path):
        return recs
    with open(log_path, "rb") as f:
        for line in f.read().decode("utf-8").splitlines():
            recs.append(json.loads(line))
    return recs


def _canon(o) -> str:
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _agent_match(rec, agent, agent_rids):
    d = rec.get("data") if isinstance(rec.get("data"), dict) else {}
    return rec.get("actor") == agent or d.get("agent") == agent or d.get("proposer") == agent \
        or (d.get("request_id") in agent_rids)


def build_report(log_path, agent=None, since=None, until=None, extra_allow=(), max_seq=None, require_ok=True):
    """Return the report dict. `max_seq` caps the log prefix considered (used by verify)."""
    vm = _verify_mod()
    vr = vm.verify(log_path)
    if require_ok and not vr["ok"]:
        raise ValueError(f"audit chain does not verify: {vr['error']}")
    recs = _load(log_path) if os.path.exists(log_path) else []
    total = len(recs) if max_seq is None else min(max_seq, len(recs))
    recs = recs[:total]
    t0, t1 = parse_ts(since), parse_ts(until)
    # request ids proposed by the agent (anywhere in the considered log), so approvals/denials/executions
    # by others on that agent's requests are included in the agent's report
    agent_rids = {r["data"].get("request_id") for r in recs if agent and r.get("event") == "dev.proposed"
                  and r.get("actor") == agent and isinstance(r.get("data"), dict)} if agent else set()
    in_period = []
    for r in recs:
        ts = parse_ts(r.get("ts"))
        if (t0 and ts < t0) or (t1 and ts > t1):
            continue
        in_period.append(r)
    selected = [r for r in in_period if not agent or _agent_match(r, agent, agent_rids)]
    red = Redactor(extra_allow)
    events, by_event, by_cat, rids = [], {}, {}, {}
    for r in selected:
        ev = str(r.get("event"))
        cat = category(ev)
        d = r.get("data") if isinstance(r.get("data"), dict) else {}
        events.append({"seq": r["seq"], "ts": r["ts"], "event": ev, "category": cat, "actor": r.get("actor"),
                       "hash": r["hash"], "data": red.data(d)})
        by_event[ev] = by_event.get(ev, 0) + 1
        by_cat[cat] = by_cat.get(cat, 0) + 1
        rid = d.get("request_id")
        if isinstance(rid, str):
            e = rids.setdefault(rid, {"request_id": rid, "action": None, "tier": None, "proposer": None, "steps": []})
            if ev == "dev.proposed":
                e.update(action=d.get("action"), tier=d.get("tier"), proposer=r.get("actor"))
            e["steps"].append(cat if cat != "other" else ev)
    summary = {k: by_cat.get(k, 0) for k in (
        "proposed", "approved", "denied", "refused", "executed", "execution_failed", "execute_claimed", "needs_review",
        "resolved", "expired", "execute_attempt_unapproved", "execute_attempt_denied", "permit_issued", "permit_used",
        "permit_rejected", "oracle", "other")}
    summary["requests_seen"] = len(rids)
    summary["events_selected"] = len(selected)
    rng = None
    if in_period:
        rng = {"first_seq": in_period[0]["seq"], "first_hash": in_period[0]["hash"],
               "last_seq": in_period[-1]["seq"], "last_hash": in_period[-1]["hash"], "records_in_period": len(in_period)}
    head_path = log_path + ".head"
    head_file = None
    if os.path.exists(head_path):
        with open(head_path, encoding="utf-8") as f:
            head_file = f.read().strip()
    body = {
        "schema_version": SCHEMA_VERSION,
        "filters": {"agent": agent, "since": since, "until": until},
        "redaction": {"version": REDACTION_VERSION, "extra_allowed_keys": sorted(set(extra_allow)),
                      "counts": dict(red.counts), "raw_payload_values_included": False},
        "chain": {"log_records": total, "head_hash": recs[-1]["hash"] if recs else GENESIS,
                  "head_file_hash": head_file, "verified_at_generation": bool(vr["ok"]), "period_range": rng,
                  "selected_count": len(selected),
                  "selected_digest": _sha("\n".join(f"{r['seq']}:{r['hash']}" for r in selected))},
        "summary": summary,
        "by_event": dict(sorted(by_event.items())),
        "requests": [rids[k] for k in sorted(rids)],
        "events": events,
        "limits": [
            "Verification needs the original log; redacted events cannot be re-hashed from this report alone.",
            "report_hash detects accidental corruption only; it is not a signature.",
            "Redaction is pattern + allow-list based and best effort.",
            "The audit log is append-only and tamper-evident; a party who rewrites the log, its head file and "
            "this report together is not detected unless the head hash is pinned elsewhere.",
            "Timestamps are those recorded by the writer's clock.",
        ],
    }
    return body


def finalize(body: dict) -> dict:
    out = dict(body)
    out["generated_at"] = datetime.now(timezone.utc).isoformat()
    out["report_hash"] = _sha(_canon({k: v for k, v in out.items() if k not in ("report_hash", "generated_at")}))
    return out


# ---------------------------------------------------------------- verification
def verify_report(report: dict, log_path: str) -> dict:
    """{"ok": bool, "problems": [str]}. Never modifies anything."""
    problems = []
    if not isinstance(report, dict) or report.get("schema_version") != SCHEMA_VERSION:
        return {"ok": False, "problems": ["not an audit-report-v1 document"]}
    claimed = report.get("report_hash")
    calc = _sha(_canon({k: v for k, v in report.items() if k not in ("report_hash", "generated_at")}))
    if claimed != calc:
        problems.append("report_hash does not match the report content (report edited or corrupted)")
    vm = _verify_mod()
    vr = vm.verify(log_path)
    if not vr["ok"]:
        problems.append(f"audit chain does not verify: {vr['error']}")
        return {"ok": False, "problems": problems}
    try:
        ch = report["chain"]
        n, head = int(ch["log_records"]), ch["head_hash"]
        recs = _load(log_path)
        if n > len(recs):
            problems.append(f"log has {len(recs)} records but the report covers {n} (log truncated or replaced)")
        else:
            at = recs[n - 1]["hash"] if n else GENESIS
            if at != head:
                problems.append("log record at the report's head position has a different hash (log rewritten)")
            else:
                f = report["filters"]
                again = build_report(log_path, f.get("agent"), f.get("since"), f.get("until"),
                                     report["redaction"].get("extra_allowed_keys", []), max_seq=n)
                # the head FILE moves as the log grows; at generation it equalled the head hash
                if ch.get("head_file_hash") not in (None, head):
                    problems.append("chain.head_file_hash differs from chain.head_hash")
                again["chain"]["head_file_hash"] = ch.get("head_file_hash")
                strip = lambda d: {k: v for k, v in d.items() if k not in ("report_hash", "generated_at")}  # noqa: E731
                if _canon(strip(again)) != _canon(strip(report)):
                    for key in ("chain", "summary", "events", "requests", "by_event", "redaction", "filters"):
                        if _canon(again.get(key)) != _canon(report.get(key)):
                            problems.append(f"report section {key!r} does not match the log")
                    if not problems:
                        problems.append("report does not match the log")
    except (KeyError, TypeError, ValueError, IndexError) as e:
        problems.append(f"malformed report ({type(e).__name__})")
    return {"ok": not problems, "problems": problems}


# ---------------------------------------------------------------- renderers
def _cell(v) -> str:
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s  # spreadsheet formula injection guard


def to_csv(report: dict) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["seq", "ts", "category", "event", "actor", "request_id", "record_hash"])
    for e in report["events"]:
        w.writerow([_cell(e["seq"]), _cell(e["ts"]), _cell(e["category"]), _cell(e["event"]), _cell(e["actor"]),
                    _cell((e["data"] or {}).get("request_id")), _cell(e["hash"])])
    return buf.getvalue()


def _md(s) -> str:
    return re.sub(r"([|`*_<>\[\]\\])", r"\\\1", str(s if s is not None else "")).replace("\n", " ")


def to_markdown(report: dict) -> str:
    f, c, s = report["filters"], report["chain"], report["summary"]
    L = ["# PATIENCE audit report", "",
         f"- Agent: `{_md(f['agent'] or 'all')}`; period: {_md(f['since'] or 'start')} to {_md(f['until'] or 'now')}",
         f"- Generated: {report.get('generated_at', '')}; report_hash: `{report.get('report_hash', '')[:16]}...`",
         f"- Chain: {c['log_records']} records, head `{c['head_hash'][:16]}...`; verified at generation: {c['verified_at_generation']}"]
    if c["period_range"]:
        r = c["period_range"]
        L.append(f"- Period range: seq {r['first_seq']} (`{r['first_hash'][:12]}...`) to {r['last_seq']} (`{r['last_hash'][:12]}...`)")
    L += [f"- Selected events: {c['selected_count']}; digest `{c['selected_digest'][:16]}...`",
          f"- Redaction {report['redaction']['version']}: {report['redaction']['counts']}", "",
          "## Summary", "", "| What | Count |", "|---|---|"]
    L += [f"| {k} | {v} |" for k, v in s.items()]
    L += ["", "## Requests", "", "| Request | Action | Tier | Proposer | Steps |", "|---|---|---|---|---|"]
    L += [f"| {_md(r['request_id'])} | {_md(r['action'])} | {_md(r['tier'])} | {_md(r['proposer'])} | {_md(' > '.join(r['steps']))} |"
          for r in report["requests"]]
    L += ["", "## Events", "", "| Seq | Time | Category | Event | Actor | Request |", "|---|---|---|---|---|---|"]
    L += [f"| {e['seq']} | {_md(e['ts'])} | {_md(e['category'])} | {_md(e['event'])} | {_md(e['actor'])} | "
          f"{_md((e['data'] or {}).get('request_id'))} |" for e in report["events"]]
    L += ["", "## Limits", ""] + [f"- {x}" for x in report["limits"]]
    return "\n".join(L) + "\n"


# ---------------------------------------------------------------- CLI
def _refuse_overwrite(out, log):
    protected = {os.path.realpath(p) for p in (log, log + ".head", log + ".lock")}
    if os.path.realpath(out) in protected:
        raise ValueError("refusing to write the report over the audit log, its head or its lock file")


def main(argv=None):
    ap = argparse.ArgumentParser(description="Generate or verify a redacted PATIENCE audit report (stdlib only).")
    sub = ap.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("generate")
    g.add_argument("log", nargs="?", default=os.environ.get("PATIENCE_AUDIT_PATH", "patience_audit.jsonl"))
    g.add_argument("--agent")
    g.add_argument("--since")
    g.add_argument("--until")
    g.add_argument("--allow-key", action="append", default=[], help="additionally show this data key (deny-list still wins)")
    g.add_argument("--format", choices=("json", "md", "csv"), default="json")
    g.add_argument("--out")
    v = sub.add_parser("verify")
    v.add_argument("report")
    v.add_argument("log", nargs="?", default=os.environ.get("PATIENCE_AUDIT_PATH", "patience_audit.jsonl"))
    a = ap.parse_args(argv)
    try:
        if a.cmd == "generate":
            rep = finalize(build_report(a.log, a.agent, a.since, a.until, a.allow_key))
            text = {"json": lambda: json.dumps(rep, indent=2, sort_keys=True) + "\n", "md": lambda: to_markdown(rep),
                    "csv": lambda: to_csv(rep)}[a.format]()
            if a.out:
                _refuse_overwrite(a.out, a.log)
                with open(a.out, "w", encoding="utf-8") as f:
                    f.write(text)
            else:
                sys.stdout.write(text)
            return 0
        with open(a.report, encoding="utf-8") as f:
            rep = json.load(f)
        res = verify_report(rep, a.log)
        print("CONSISTENT: report matches the verified audit chain" if res["ok"] else
              "NOT CONSISTENT: " + "; ".join(res["problems"]))
        return 0 if res["ok"] else 1
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    except OSError as e:
        print(f"ERROR: cannot read/write file ({type(e).__name__})", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())

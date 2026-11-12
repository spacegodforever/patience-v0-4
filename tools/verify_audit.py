#!/usr/bin/env python3
"""Standalone verifier for the PATIENCE audit log hash chain. Standard library only.

It does NOT import any PATIENCE code, so it does not trust the code that wrote the log. It
re-implements the published record format:

  {"seq", "ts", "event", "actor", "data", "prev", "hash"}  one JSON object per line
  hash = sha256( json.dumps(record without "hash", sort_keys=True, separators=(",", ":"), default=str) )
  prev = hash of the previous line ("0"*64 for the first); seq counts 1, 2, 3, ...

Detects: edited record, deleted line, inserted line, reordered lines, invalid JSON, and (via the
`<log>.head` file) truncation of the tail. It reports the FIRST broken link and exits 1.

Limit: an attacker who can rewrite BOTH the log and its .head file can forge a consistent chain. Pin
the newest hash somewhere the writer cannot reach and pass it with --expect-head to close that gap.

Usage:
  python3 tools/verify_audit.py [LOG] [--head FILE] [--expect-head HEX] [--require-head] [--json]
  LOG defaults to $PATIENCE_AUDIT_PATH or patience_audit.jsonl.   Exit: 0 intact, 1 broken, 2 usage/IO error.
"""
import argparse
import hashlib
import json
import os
import sys

GENESIS = "0" * 64
KEYS = {"seq", "ts", "event", "actor", "data", "prev", "hash"}


def _digest(rec):
    body = {k: v for k, v in rec.items() if k != "hash"}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def verify(log_path, head_path=None, expect_head=None, require_head=False):
    """Return {"ok", "records", "error", "bad_line", "bad_seq", "head", "warnings"}."""
    res = {"ok": False, "records": 0, "error": None, "bad_line": None, "bad_seq": None, "head": None, "warnings": []}
    head_path = head_path or (log_path + ".head")
    head_exists = os.path.exists(head_path)
    if not os.path.exists(log_path):
        if head_exists:
            res["error"] = "log file missing but its head file exists (log deleted)"
            return res
        res.update(ok=True, warnings=["log file does not exist: nothing to verify"])
        return res
    with open(log_path, "rb") as f:
        data = f.read()
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        res["error"] = "log is not valid UTF-8"
        return res
    prev, n = GENESIS, 0
    for i, line in enumerate(text.splitlines(), 1):
        def bad(msg, seq=None):
            res.update(error=f"line {i}: {msg}", bad_line=i, bad_seq=seq, records=n)
            return res
        try:
            rec = json.loads(line)
        except ValueError:
            return bad("not valid JSON")
        if not isinstance(rec, dict) or not KEYS <= set(rec):
            return bad("record is missing required fields")
        seq = rec.get("seq")
        if isinstance(seq, bool) or seq != i:
            return bad(f"sequence is {seq!r}, expected {i} (line deleted, inserted or reordered)", seq if isinstance(seq, int) else None)
        if rec.get("prev") != prev:
            return bad("prev hash does not match the previous record (chain broken)", seq)
        if _digest(rec) != rec.get("hash"):
            return bad("record content does not match its hash (record modified)", seq)
        prev, n = rec["hash"], i
    res.update(records=n, head=prev)
    if expect_head is not None and expect_head.strip().lower() != prev:
        res["error"] = f"newest hash {prev[:16]}... does not match the pinned --expect-head (log truncated, replaced or extended)"
        return res
    if head_exists:
        with open(head_path, "r", encoding="utf-8") as f:
            recorded = f.read().strip()
        if recorded != prev:
            res["error"] = "head file does not match the newest record (log truncated or head altered)"
            return res
    else:
        if require_head:
            res["error"] = "head file is missing and --require-head was given"
            return res
        res["warnings"].append("no .head file: truncation of the tail cannot be detected without --expect-head")
    res["ok"] = True
    return res


def main(argv=None):
    ap = argparse.ArgumentParser(description="Verify the PATIENCE audit hash chain (stdlib only).")
    ap.add_argument("log", nargs="?", default=os.environ.get("PATIENCE_AUDIT_PATH", "patience_audit.jsonl"))
    ap.add_argument("--head", help="head file (default: <log>.head)")
    ap.add_argument("--expect-head", help="externally pinned newest hash (hex)")
    ap.add_argument("--require-head", action="store_true", help="fail if the head file is missing")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    try:
        r = verify(a.log, a.head, a.expect_head, a.require_head)
    except OSError as e:
        print(f"ERROR: cannot read log ({type(e).__name__})", file=sys.stderr)
        return 2
    if a.json:
        print(json.dumps(r, sort_keys=True))
    else:
        if r["ok"]:
            print(f"OK: {r['records']} records verified ({a.log})")
        else:
            where = f" at line {r['bad_line']}" if r["bad_line"] else ""
            print(f"BROKEN{where}: {r['error']}  [{r['records']} records verified before the break]")
        for w in r["warnings"]:
            print(f"warning: {w}", file=sys.stderr)
    return 0 if r["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())

"""tools/verify_audit.py: standalone (stdlib-only) audit-chain verifier. Detects edit, deletion, insertion,
reordering, truncation; reports the first broken link."""
import ast
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

import audit

ROOT = Path(__file__).resolve().parent.parent
TOOL = ROOT / "tools" / "verify_audit.py"


def run(log, *extra):
    p = subprocess.run([sys.executable, "-I", str(TOOL), str(log), *extra], capture_output=True, text=True,
                       cwd=str(ROOT.parent))
    return p.returncode, p.stdout + p.stderr


@pytest.fixture
def log():
    for i in range(1, 7):
        audit.append(f"evt.{i}", f"actor{i}", n=i, note="ünïcode ✓" if i == 3 else "plain")
    return audit.path()


def lines(p): return Path(p).read_text().splitlines()
def write(p, ls): Path(p).write_text("\n".join(ls) + ("\n" if ls else ""))
def rehash(ls):
    """Recompute prev/hash for every record: a careful attacker fixing up the chain (not the .head file)."""
    out, prev = [], "0" * 64
    for i, l in enumerate(ls, 1):
        r = json.loads(l)
        r["seq"], r["prev"] = i, prev
        r["hash"] = audit._digest(r)
        prev = r["hash"]
        out.append(json.dumps(r, sort_keys=True, separators=(",", ":")))
    return out


def test_intact_log_verifies_and_agrees_with_patience_own_check(log):
    code, out = run(log)
    assert code == 0 and out.startswith("OK: 6 records"), out
    assert audit.verify()["ok"]
    code, out = run(log, "--json")
    assert json.loads(out)["head"] == Path(str(log) + ".head").read_text().strip()


def test_runs_in_isolated_mode_with_no_patience_imports():
    tree = ast.parse(TOOL.read_text())
    mods = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            mods |= {a.name.split(".")[0] for a in n.names}
        elif isinstance(n, ast.ImportFrom):
            mods.add((n.module or "").split(".")[0])
    assert mods <= set(sys.stdlib_module_names), mods - set(sys.stdlib_module_names)
    assert not any(m in mods for m in ("audit", "dev_governance", "execution_gateway", "models", "filelock"))


def test_edited_record_reports_that_line(log):
    ls = lines(log)
    r = json.loads(ls[2]); r["data"]["n"] = 999
    ls[2] = json.dumps(r, sort_keys=True, separators=(",", ":"))
    write(log, ls)
    code, out = run(log)
    assert code == 1 and "line 3" in out and "modified" in out and "2 records verified" in out


def test_deleted_middle_line_reports_first_gap(log):
    ls = lines(log); del ls[2]
    write(log, ls)
    code, out = run(log)
    assert code == 1 and "line 3" in out and "sequence" in out


def test_deleted_first_line_detected(log):
    ls = lines(log); del ls[0]
    write(log, ls)
    code, out = run(log)
    assert code == 1 and "line 1" in out


def test_reordered_lines_detected_at_first_swap(log):
    ls = lines(log); ls[2], ls[3] = ls[3], ls[2]
    write(log, ls)
    code, out = run(log)
    assert code == 1 and "line 3" in out


def test_inserted_duplicate_line_detected(log):
    ls = lines(log); ls.insert(3, ls[2])
    write(log, ls)
    code, out = run(log)
    assert code == 1 and "line 4" in out


def test_truncated_tail_detected_via_head_file(log):
    write(log, lines(log)[:4])
    code, out = run(log)
    assert code == 1 and "head" in out


def test_rehashed_chain_still_caught_by_head_file(log):
    ls = lines(log)
    r = json.loads(ls[1]); r["event"] = "evt.forged"
    ls[1] = json.dumps(r, sort_keys=True, separators=(",", ":"))
    write(log, rehash(ls))  # every link consistent again, but .head is stale
    code, out = run(log)
    assert code == 1 and "head" in out


def test_full_rewrite_with_head_is_only_caught_by_a_pinned_head(log):
    pinned = json.loads(run(log, "--json")[1])["head"]
    ls = lines(log)
    r = json.loads(ls[1]); r["event"] = "evt.forged"
    ls[1] = json.dumps(r, sort_keys=True, separators=(",", ":"))
    ls = rehash(ls)
    write(log, ls)
    Path(str(log) + ".head").write_text(json.loads(ls[-1])["hash"])
    assert run(log)[0] == 0  # documented limitation: attacker rewrote log AND head
    code, out = run(log, "--expect-head", pinned)
    assert code == 1 and "pinned" in out


def test_invalid_json_and_missing_fields(log):
    ls = lines(log); ls[4] = "{not json"
    write(log, ls)
    code, out = run(log)
    assert code == 1 and "line 5" in out and "JSON" in out
    ls[4] = json.dumps({"seq": 5})
    write(log, ls)
    code, out = run(log)
    assert code == 1 and "line 5" in out and "missing" in out


def test_deleted_log_with_surviving_head_and_empty_log(log):
    head = Path(str(log) + ".head")
    Path(log).write_text("")
    assert run(log)[0] == 1  # emptied: head still names a record
    Path(log).unlink()
    code, out = run(log)
    assert code == 1 and "missing" in out
    head.unlink()
    assert run(log)[0] == 0  # nothing at all: nothing to verify (warning only)


def test_missing_head_warns_and_can_be_required(log):
    Path(str(log) + ".head").unlink()
    code, out = run(log)
    assert code == 0 and "warning" in out
    code, out = run(log, "--require-head")
    assert code == 1 and "head file is missing" in out


def test_hash_is_the_documented_sha256_of_canonical_json(log):
    r = json.loads(lines(log)[0])
    body = {k: v for k, v in r.items() if k != "hash"}
    assert r["hash"] == hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()

"""Manual GitHub smoke test (NOT part of the test suite). READ-ONLY + DRY-RUN ONLY.

Reads the token ONLY from env GITHUB_TEST_REPO_TOKEN and maps it to PATIENCE_GITHUB_TOKEN inside
this process. The token is never printed, logged, or written. PATIENCE_GITHUB_LIVE is forced off
and the transport is read_only (GET only), so no write can be sent even by mistake.

Usage: GITHUB_TEST_REPO_TOKEN=... python tools/github_smoke.py [owner/repo]
Exit code 0 = reads ok + dry run built + no token in output/audit.
"""
from __future__ import annotations
import contextlib
import io
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def main() -> int:
    tok = os.environ.get("GITHUB_TEST_REPO_TOKEN", "")
    if not tok:
        print("GITHUB_TEST_REPO_TOKEN not set"); return 2
    import re
    if not re.fullmatch(r"(github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9]{20,})", tok):
        print("GITHUB_TEST_REPO_TOKEN does not look like a GitHub token (shape check only; value not shown)")
        return 2
    os.environ["PATIENCE_GITHUB_TOKEN"] = tok
    for k in ("PATIENCE_GITHUB_LIVE", "PATIENCE_GITHUB_ACTION_ALLOWLIST", "PATIENCE_GITHUB_REPO_ALLOWLIST"):
        os.environ.pop(k, None)  # writes impossible
    tmp = tempfile.mkdtemp(prefix="gh-smoke-")
    os.environ["PATIENCE_AUDIT_PATH"] = os.path.join(tmp, "audit.jsonl")
    os.environ["PATIENCE_DEV_GATE_DB"] = ":memory:"

    import audit
    from dev_governance import DevGate
    from dev_governance.github_adapter import GitHubAdapter, API
    from dev_governance.github_transport import UrllibTransport

    transport = UrllibTransport(timeout=10, read_only=True)
    adapter = GitHubAdapter(transport=transport)
    gate = DevGate(adapters=[adapter])
    out = io.StringIO()
    rc = 0
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
        repo = sys.argv[1] if len(sys.argv) > 1 else None
        if not repo:  # discovery: direct GET with the same read-only transport
            hdr = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28",
                   "User-Agent": "patience-dev-governance", "Authorization": f"Bearer {tok}"}
            for path in ("/user/repos?per_page=10&affiliation=owner", "/installation/repositories"):
                r = transport({"method": "GET", "url": API + path, "headers": hdr, "body": None})
                b = r["body"]
                items = b.get("repositories") if isinstance(b, dict) else b
                print(f"discovery GET {path} -> HTTP {r['status']}, {len(items) if isinstance(items, list) else 0} repo(s)")
                if r["status"] == 200 and isinstance(items, list) and items:
                    repo = items[0]["full_name"]; break
            hdr = None
        if not repo:
            print("could not discover a repo"); rc = 1
        else:
            print(f"repo: {repo}")

            def read(action, payload):
                rid = gate.propose(action, payload, "smoke")["request_id"]
                code, res = gate.execute(rid, action, payload, "smoke")
                return res.get("result"), res

            r, _ = read("code.get_repo", {"repo": repo})
            print("phase1 get_repo:", json.dumps(r, default=str)[:800])
            default_branch = (r or {}).get("data", {}).get("default_branch", "main") if isinstance(r, dict) else "main"
            r, _ = read("code.list_prs", {"repo": repo, "state": "all"})
            print("phase1 list_prs:", json.dumps(r, default=str)[:800])
            prs = (r or {}).get("data") or []
            if isinstance(prs, list) and prs:
                n = prs[0].get("number")
                r, _ = read("code.get_pr_diff", {"repo": repo, "pr_number": n})
                print(f"phase1 get_pr_diff #{n}:", json.dumps(r, default=str)[:800])
            else:
                print("phase1 get_pr_diff: skipped (no PRs)")
            payload = {"repo": repo, "title": "smoke dry-run (never sent)", "head": "smoke/dry-run",
                       "base": default_branch, "body": "dry run only", "draft": True}
            res = adapter.execute("code.open_pr", payload, {"request_id": "smoke-dry", "approved": False})
            print("phase2 open_pr dry_run:", json.dumps(res, sort_keys=True))
            if res.get("dry_run") is not True:
                print("ERROR: open_pr was not a dry run"); rc = 1
    text = out.getvalue()
    audit_text = open(os.environ["PATIENCE_AUDIT_PATH"]).read() if os.path.exists(os.environ["PATIENCE_AUDIT_PATH"]) else ""
    leaked = [name for name, t in (("output", text), ("audit", audit_text)) if tok in t or tok[-16:] in t or tok[20:40] in t]
    print(text)
    print(f"audit events: {len(audit_text.splitlines())} ({os.environ['PATIENCE_AUDIT_PATH']})")
    print("LEAK CHECK:", "FAIL in " + ",".join(leaked) if leaked else "PASS (token absent from output and audit)")
    os.environ.pop("PATIENCE_GITHUB_TOKEN", None)
    return 1 if leaked else rc


if __name__ == "__main__":
    sys.exit(main())

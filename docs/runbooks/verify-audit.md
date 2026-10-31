# Verify the audit log
1. `python audit.py verify`: exit 0 = chain intact; exit 1 prints the first bad line.
2. Compare `patience_audit.jsonl.head` with a copy you keep elsewhere (until off-host replication exists, keep a periodic copy of `.head` off the box).
3. `python audit.py tail 50` to inspect recent events.
If verification fails, follow `incident-suspected-tamper.md`. Note a crash between append and head write could once cause a false truncation alarm (fixed on `fix/approval-integrity` with an atomic head write).

# Approver accounts
- Add: `python approvers.py add <user> --role approver|admin` (password >= 10 chars; optional PIN >= 6 digits).
- Disable: `python approvers.py disable <user>`. Rotate a PIN: `python approvers.py set-pin <user>`.
- Lockout: 5 failures lock that username for 5 minutes in the running process (anyone can trigger this; see audit A2). Restarting the API clears it.
- Keep approver usernames distinct from agent identities; on `fix/approval-integrity`, approving a request whose identity equals your username is refused.

# PATIENCE coordinator UI

Vite + React UI for `/v1/coordinator/*` (merged from PATIENCE Experimental).

```bash
npm install
npm run dev      # http://127.0.0.1:5173/coordinator/ ; /v1 is proxied to the API on 127.0.0.1:8765
npm run build    # writes dist/ (git-ignored); api.py then serves it at /coordinator/
```

Log in with an `approvers.yaml` account. The session is an HttpOnly, SameSite=Strict cookie;
mutations send the CSRF token returned at login. The UI can only *submit previews* to the approval
gate; nothing is executed from here.

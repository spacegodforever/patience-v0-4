# Stuck executions
1. `GET /v1/admin/needs_review` (admin Basic auth) lists executions interrupted mid-run.
2. Check the provider (Stripe dashboard, mail logs) for whether it actually happened.
3. Resolve: `POST /v1/admin/requests/{id}/resolve` with the outcome and a reason. Never re-run blindly; execution is at-most-once.
4. `POST /v1/admin/reconcile` runs the startup reconciliation on demand.

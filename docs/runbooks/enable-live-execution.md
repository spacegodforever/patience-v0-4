# Enable live execution
1. Confirm agents hold no tool credentials and egress to tool hosts is blocked (README, Gateway mode).
2. Configure only the executors needed; run in dry-run and review results.
3. Set `PATIENCE_EXECUTE_LIVE=1`. For Stripe, live keys also need `PATIENCE_STRIPE_ALLOW_LIVE`.
4. Verify the audit chain before and after the first live run.

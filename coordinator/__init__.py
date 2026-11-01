"""PATIENCE coordinator (merged from PATIENCE Experimental).

Prioritises projects and prepares action *previews*. It never executes anything:
every proposed action is submitted to the v0.6 approval gate (api._check_impl) and
can only run later via /v1/execute after the normal approval flow.
"""

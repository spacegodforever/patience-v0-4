# PATIENCE v0.3 — Command Dashboard

This version adds a live local control interface to the PATIENCE decision engine.

## What changed

PATIENCE now exposes:

- mission
- end state
- current objective
- priority
- observation count
- current confidence
- model-council votes
- Red Team findings
- blocked actions
- human authorization controls
- active tasks
- decision history
- assumptions and unknowns
- raw persistent state

The interface makes the decision path visible:

Observe → Assess → Challenge → Council → Decide → Authorize → Verify → Remember

## Start it on Windows

Open PowerShell in this folder and run:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\run_dashboard.ps1
```

Or manually:

```powershell
python -m pip install -r requirements.txt
python -m streamlit run dashboard.py
```

Streamlit will open the dashboard in your browser.

## Important architecture rule

Models do not directly receive unrestricted tool authority.

External models such as Grok, Claude, or another LLM should be implemented as advisory adapters that return:

- recommendation
- confidence
- reasoning summary
- dissent

The Governance Gate decides whether an action is allowed.

## v0.4 target

The next version should add:

1. Real LLM adapters.
2. Real tool registry.
3. Event ingestion.
4. Outcome scoring.
5. Model disagreement visualization.
6. Decision replay.
7. Optional notifications and scheduled checks.


# v0.4 — Trigger Agent

v0.4 adds a persistent local agent that continuously inspects PATIENCE state.

It can trigger on:

- due tasks
- blocked actions
- high uncertainty
- checkpoints
- idle reassessment

The agent writes structured trigger events to:

`trigger_queue.jsonl`

Each trigger also contains a ready-to-send PATIENCE prompt.

To inspect the latest trigger manually:

```powershell
python .\trigger_bridge.py
```

To launch the dashboard and trigger agent together:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\run_patience.ps1
```

## Important boundary

This local agent can continuously generate triggers, but it cannot directly wake a ChatGPT conversation by itself unless it is connected to an external API, webhook, automation system, or another supported messaging channel.

That separation is intentional:
the Trigger Agent decides WHEN the system needs attention;
the Governance Gate decides WHAT is allowed;
the model decides HOW to reason about the trigger.

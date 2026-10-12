import json
from datetime import datetime, timezone
import streamlit as st
from engine import Patience

st.set_page_config(
    page_title="PATIENCE Command",
    page_icon="*)",
    layout="wide"
)

st.markdown("""
<style>
html, body, [data-testid="stAppViewContainer"] {
    background: #0b0d10;
    color: #e8eaed;
}
.block-container { padding-top: 1.3rem; max-width: 1500px; }
.p-card {
    border: 1px solid #2a2f36;
    background: rgba(19,22,27,.82);
    border-radius: 14px;
    padding: 14px 16px;
    margin-bottom: 10px;
}
.p-kicker {
    font-size: 0.72rem;
    letter-spacing: .16em;
    color: #9aa0a6;
    text-transform: uppercase;
}
.p-value { font-size: 1.05rem; font-weight: 600; }
.flow {
    display:flex; gap:8px; flex-wrap:wrap; margin: 10px 0 16px 0;
}
.node {
    border:1px solid #31363d;
    border-radius:999px;
    padding:7px 11px;
    font-size:.78rem;
    background:#15181d;
}
.logo { font-size: 2.2rem; font-weight:700; letter-spacing:-.08em; }
.small { color:#9aa0a6; font-size:.78rem; }
</style>
""", unsafe_allow_html=True)

p = Patience("patience_state.json")

if not p.state.mission:
    p.set_mission(
        "Build PATIENCE into a governed proactive decision system.",
        "A persistent, time-aware system that observes, challenges, decides, verifies, and remembers.",
        "Validate the PATIENCE v0.3 control architecture.",
        "Decision integrity before autonomous reach."
    )

top1, top2 = st.columns([1,4])
with top1:
    st.markdown('<div class="logo">*)</div>', unsafe_allow_html=True)
with top2:
    st.title("PATIENCE Command")
    st.caption("Governed decision intelligence / v0.3")

st.markdown("""
<div class="flow">
<span class="node">OBSERVE</span>
<span class="node">ASSESS</span>
<span class="node">CHALLENGE</span>
<span class="node">COUNCIL</span>
<span class="node">DECIDE</span>
<span class="node">AUTHORIZE</span>
<span class="node">VERIFY</span>
<span class="node">REMEMBER</span>
</div>
""", unsafe_allow_html=True)

c1, c2, c3, c4 = st.columns(4)
with c1:
    st.metric("Observations", len(p.state.observations))
with c2:
    latest_conf = p.state.assessments[-1]["confidence"] if p.state.assessments else 0
    st.metric("Confidence", f"{latest_conf:.0%}")
with c3:
    st.metric("Blocked actions", len(p.state.blocked_actions))
with c4:
    st.metric("Active tasks", len([t for t in p.state.tasks if t.get("status")=="active"]))

st.subheader("Command State")
a,b = st.columns(2)
with a:
    st.markdown(f'<div class="p-card"><div class="p-kicker">Mission</div><div class="p-value">{p.state.mission}</div></div>', unsafe_allow_html=True)
    st.markdown(f'<div class="p-card"><div class="p-kicker">Current Objective</div><div class="p-value">{p.state.current_objective}</div></div>', unsafe_allow_html=True)
with b:
    st.markdown(f'<div class="p-card"><div class="p-kicker">End State</div><div class="p-value">{p.state.end_state}</div></div>', unsafe_allow_html=True)
    st.markdown(f'<div class="p-card"><div class="p-kicker">Priority</div><div class="p-value">{p.state.priority}</div></div>', unsafe_allow_html=True)

st.subheader("Inject Observation")
with st.form("observation_form"):
    content = st.text_area("Observation / event / request", height=100, placeholder="Enter a new event for PATIENCE to evaluate...")
    colx, coly = st.columns([3,1])
    with colx:
        source = st.text_input("Source", value="user")
    with coly:
        reliability = st.slider("Reliability", 0.0, 1.0, 0.9, 0.05)
    submitted = st.form_submit_button("Run Decision Cycle", use_container_width=True)

if submitted and content.strip():
    result = p.cycle(content.strip(), source=source.strip() or "user", reliability=reliability)
    st.session_state["latest_result"] = result
    st.rerun()

result = st.session_state.get("latest_result")
if result:
    st.subheader("Live Decision Trace")
    cols = st.columns(4)
    trace = [
        ("Assessment", result["assessment"]),
        ("Red Team", result["red_team"]),
        ("Consensus", {"recommendation": result["consensus"]}),
        ("Decision", result["decision"]),
    ]
    for col, (title, data) in zip(cols, trace):
        with col:
            st.markdown(f"**{title}**")
            st.json(data)

    st.markdown("**Verification**")
    st.json(result["verification"])

st.subheader("Model Council")
votes = p.state.model_votes[-6:]
if votes:
    for v in reversed(votes):
        with st.expander(f'{v["model"]} → {v["recommendation"]} ({v["confidence"]:.0%})'):
            st.write(v["reasoning_summary"])
            if v.get("dissent"):
                st.caption("Dissent: " + v["dissent"])
else:
    st.caption("No model votes yet.")

left, right = st.columns(2)

with left:
    st.subheader("Oversight")
    if p.state.blocked_actions:
        for action in sorted(set(p.state.blocked_actions)):
            st.warning(f"Blocked: {action}")
            if st.button(f"Authorize {action}", key=f"auth-{action}"):
                p.authorize(action)
                st.rerun()
    else:
        st.success("No blocked actions.")

    st.markdown("**Assumptions**")
    if p.state.assumptions:
        for item in p.state.assumptions:
            st.write("•", item)
    else:
        st.caption("No active assumptions.")

    st.markdown("**Unknowns**")
    if p.state.unknowns:
        for item in p.state.unknowns:
            st.write("•", item)
    else:
        st.caption("No material unknowns.")

with right:
    st.subheader("Temporal Layer")
    with st.form("task_form"):
        task_title = st.text_input("Task title")
        due_at = st.text_input("Due timestamp (ISO, optional)", placeholder="2026-10-05T12:00:00+00:00")
        priority = st.selectbox("Priority", [1,2,3,4,5], index=2)
        add_task = st.form_submit_button("Add Task")
    if add_task and task_title.strip():
        p.add_task(task_title.strip(), due_at.strip() or None, priority)
        st.rerun()

    if p.state.tasks:
        for t in sorted(p.state.tasks, key=lambda x: x.get("priority", 3)):
            st.markdown(f"**P{t.get('priority',3)} — {t['title']}**")
            st.caption(f"status={t.get('status')} · due={t.get('due_at') or 'unscheduled'}")
    else:
        st.caption("No tasks registered.")

st.subheader("Decision Log")
if p.state.decisions:
    for i, d in enumerate(reversed(p.state.decisions[-10:]), start=1):
        st.markdown(f"**{d['action']}** · confidence {d['confidence']:.0%}")
        st.caption(d["reason"])
else:
    st.caption("No decisions recorded.")

with st.expander("Raw PATIENCE state"):
    st.json(p.state.__dict__)

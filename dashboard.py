import json
from html import escape
from datetime import datetime, timezone
import streamlit as st
from engine import Patience

st.set_page_config(
    page_title="PATIENCE Command",
    page_icon="P",
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
.logo { font-size: 2.2rem; font-weight:700; letter-spacing:-.08em; animation: notice 7s ease-in-out infinite; }
.small { color:#9aa0a6; font-size:.78rem; }
.flow .node { animation: nodewake 8.8s linear infinite; }
.flow .node:nth-child(1) { animation-delay: 0s; }
.flow .node:nth-child(2) { animation-delay: 1.1s; }
.flow .node:nth-child(3) { animation-delay: 2.2s; }
.flow .node:nth-child(4) { animation-delay: 3.3s; }
.flow .node:nth-child(5) { animation-delay: 4.4s; }
.flow .node:nth-child(6) { animation-delay: 5.5s; }
.flow .node:nth-child(7) { animation-delay: 6.6s; }
.flow .node:nth-child(8) { animation-delay: 7.7s; }
.motion.cycle-live .flow .node { animation-iteration-count: 1; animation-duration: 6.4s; }
.tool-stage { margin: 4px 0 18px 0; }
.tool-row { display:grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap:10px; }
@media (max-width: 900px) { .tool-row { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
.tool {
    border: 1px solid #2a2f36;
    background: rgba(19,22,27,.82);
    border-radius: 14px;
    padding: 10px 12px 12px;
    min-height: 108px;
}
.play { position: relative; height: 36px; margin: 8px 0 6px; overflow: hidden; }
.play-oracle .beam {
    position:absolute; left:0; top:14px; height:3px; width:34%;
    background: linear-gradient(90deg, transparent, #d6b25e, transparent);
    animation: scan 2.8s ease-in-out infinite;
}
.play-skeptic .chip {
    position:absolute; top:13px; width:22px; height:8px; border-radius:4px; background:#3c434c;
}
.play-skeptic .a { left:4px; }
.play-skeptic .b { left:34px; animation: dissent 3.2s ease-in-out infinite; }
.play-opportunity .rise {
    position:absolute; left:8px; bottom:4px; width:12px; height:8px;
    background:#7d9a6a; border-radius:3px; transform-origin: bottom;
    animation: rise 2.8s ease-in-out infinite;
}
.play-council .dot {
    position:absolute; top:13px; width:8px; height:8px; border-radius:50%; background:#d6b25e;
}
.play-council .d1 { left:6px; animation: meet-right 3.6s ease-in-out infinite; }
.play-council .d2 { left:28px; }
.play-council .d3 { left:50px; animation: meet-left 3.6s ease-in-out infinite; }
.play-governance .post {
    position:absolute; right:18px; top:6px; width:3px; height:24px; background:#c47b6a; border-radius:2px;
}
.play-governance .walker {
    position:absolute; left:6px; top:13px; width:8px; height:8px; border-radius:50%; background:#e8eaed;
    animation: hold-gate 3.4s ease-in-out infinite;
}
.play-temporal .tick {
    position:absolute; bottom:6px; width:3px; height:10px; background:#9aa0a6; border-radius:2px;
    transform-origin: bottom;
}
.play-temporal .t1 { left:8px; animation: tick 1.8s ease-in-out infinite; }
.play-temporal .t2 { left:16px; animation: tick 1.8s ease-in-out infinite .2s; }
.play-temporal .t3 { left:24px; animation: tick 1.8s ease-in-out infinite .4s; }
.play-memory .line {
    position:absolute; left:4px; height:3px; width:12px; background:#9aa0a6; border-radius:2px;
}
.play-memory .l1 { top:8px; animation: record 3s ease-in-out infinite; }
.play-memory .l2 { top:16px; animation: record 3s ease-in-out infinite .25s; }
.play-memory .l3 { top:24px; animation: record 3s ease-in-out infinite .5s; }
.play-trigger .queue {
    position:absolute; right:8px; top:8px; width:28px; height:18px;
    border:1px solid #31363d; border-radius:4px;
}
.play-trigger .packet {
    position:absolute; left:4px; top:13px; width:8px; height:8px; border-radius:2px; background:#d6b25e;
    animation: enqueue 3.2s ease-in-out infinite;
}
.motion.cycle-live .play * { animation-iteration-count: 1 !important; }
@keyframes notice { 0%,100% { opacity:.72; } 50% { opacity:1; } }
@keyframes nodewake {
    0%, 7% { border-color:#d6b25e; color:#f3e6c4; background:#241e14; }
    16%, 100% { border-color:#31363d; color:inherit; background:#15181d; }
}
@keyframes scan {
    0% { transform: translateX(-30%); opacity:.25; }
    45% { opacity:1; }
    100% { transform: translateX(280%); opacity:.2; }
}
@keyframes dissent {
    0%, 35% { background:#3c434c; transform:none; }
    50%, 75% { background:#c47b6a; transform: translateY(3px) rotate(-8deg); }
    100% { background:#3c434c; transform:none; }
}
@keyframes rise {
    0%, 20% { height:6px; opacity:.45; }
    60% { height:24px; opacity:1; }
    100% { height:6px; opacity:.45; }
}
@keyframes meet-right { 0%,100% { transform:translateX(0); } 50% { transform:translateX(16px); } }
@keyframes meet-left { 0%,100% { transform:translateX(0); } 50% { transform:translateX(-16px); } }
@keyframes hold-gate {
    0% { transform:translateX(0); opacity:.45; }
    55% { transform:translateX(42px); opacity:1; }
    80% { transform:translateX(42px); opacity:1; }
    100% { transform:translateX(0); opacity:.45; }
}
@keyframes tick {
    0%, 100% { transform:scaleY(.45); opacity:.4; }
    40% { transform:scaleY(1.7); opacity:1; }
}
@keyframes record {
    0%, 20% { width:10px; opacity:.35; }
    55% { width:78px; opacity:1; }
    100% { width:10px; opacity:.35; }
}
@keyframes enqueue {
    0% { transform:translateX(0); opacity:.3; }
    55% { transform:translateX(62px); opacity:1; }
    75% { transform:translateX(62px); opacity:1; }
    100% { transform:translateX(0); opacity:.3; }
}
@media (prefers-reduced-motion: reduce) {
    .logo, .flow .node, .play * { animation: none !important; }
}
</style>
""", unsafe_allow_html=True)

p = Patience("patience_state.json")

if not p.state.mission:
    p.set_mission(
        "Build PATIENCE into a governed proactive decision system.",
        "A persistent, time-aware system that observes, challenges, decides, verifies, and remembers.",
        "Validate the PATIENCE v0.4 control architecture.",
        "Decision integrity before autonomous reach."
    )

top1, top2 = st.columns([1,4])
with top1:
    st.markdown('<div class="logo">*)</div>', unsafe_allow_html=True)
with top2:
    st.title("PATIENCE Command")
    st.caption("Governed decision intelligence / v0.4")

motion = "cycle-live" if st.session_state.get("latest_result") else "cycle-idle"
st.markdown(f"""
<div class="motion {motion}">
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
<div class="tool-stage">
<div class="p-kicker">Local tool sequences</div>
<div class="tool-row">
<div class="tool"><div class="p-kicker">Oracle</div><div class="play play-oracle"><span class="beam"></span></div><div class="small">Scan</div></div>
<div class="tool"><div class="p-kicker">Skeptic</div><div class="play play-skeptic"><span class="chip a"></span><span class="chip b"></span></div><div class="small">Dissent</div></div>
<div class="tool"><div class="p-kicker">Opportunity</div><div class="play play-opportunity"><span class="rise"></span></div><div class="small">Rise</div></div>
<div class="tool"><div class="p-kicker">Council</div><div class="play play-council"><span class="dot d1"></span><span class="dot d2"></span><span class="dot d3"></span></div><div class="small">Converge</div></div>
<div class="tool"><div class="p-kicker">Governance</div><div class="play play-governance"><span class="walker"></span><span class="post"></span></div><div class="small">Hold</div></div>
<div class="tool"><div class="p-kicker">Temporal</div><div class="play play-temporal"><span class="tick t1"></span><span class="tick t2"></span><span class="tick t3"></span></div><div class="small">Tick</div></div>
<div class="tool"><div class="p-kicker">Memory</div><div class="play play-memory"><span class="line l1"></span><span class="line l2"></span><span class="line l3"></span></div><div class="small">Record</div></div>
<div class="tool"><div class="p-kicker">Trigger</div><div class="play play-trigger"><span class="packet"></span><span class="queue"></span></div><div class="small">Queue</div></div>
</div>
<div class="small">Motion only. These sequences do not call out or execute an action. A decision cycle plays each one once.</div>
</div>
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
    st.markdown(f'<div class="p-card"><div class="p-kicker">Mission</div><div class="p-value">{escape(p.state.mission)}</div></div>', unsafe_allow_html=True)
    st.markdown(f'<div class="p-card"><div class="p-kicker">Current Objective</div><div class="p-value">{escape(p.state.current_objective)}</div></div>', unsafe_allow_html=True)
with b:
    st.markdown(f'<div class="p-card"><div class="p-kicker">End State</div><div class="p-value">{escape(p.state.end_state)}</div></div>', unsafe_allow_html=True)
    st.markdown(f'<div class="p-card"><div class="p-kicker">Priority</div><div class="p-value">{escape(str(p.state.priority))}</div></div>', unsafe_allow_html=True)

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

st.caption("Local rule-based advisors only. No external models or tools are connected. Authorization does not execute an action.")
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

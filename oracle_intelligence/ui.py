"""Minimal Oracle Intelligence page (Streamlit). Display and analysis only: no approve/execute controls.
Uses dashboard_auth: with no approver accounts the page is read-only (counters and past reports only)."""
from __future__ import annotations
import time

from . import inquiry, sources
from .common import IntelError
from .report import to_markdown
from .store import default_store

STEPS = ["1 Question", "2 Collections", "3 Retrieve", "4 Evidence", "5 Statistics", "6 Hypotheses & report"]


def render(st, auth, store=None, clock=time.time):
    st.markdown("<div style='font-size:.75rem;letter-spacing:.2em;color:#9aa0a6'>ORACLE / INTELLIGENCE</div>", unsafe_allow_html=True)
    st.title("Oracle Intelligence")
    st.caption("Analysis only: it retrieves, interprets and recommends. It cannot approve, execute or change policy. "
               "Retrieved text is untrusted data.")
    if auth.password_configured():
        if not auth.is_authed(st.session_state):
            st.info("Sign in on the main PATIENCE page first.")
            st.stop()
        who = auth.current(st.session_state)["user"]
        can_run = True
    else:
        who, can_run = None, False
        st.warning("READ-ONLY: no approver accounts exist, so questions and ingestion are disabled.")
    store = store or default_store()
    if who:
        c = store.counts([x["source_id"] for x in sources.list_sources(store, who)])
        c["queries"] = store.query("SELECT COUNT(*) FROM analytical_queries WHERE asked_by=?", (who,))[0][0]
        c["reports"] = store.query("SELECT COUNT(*) FROM intelligence_reports WHERE created_by=?", (who,))[0][0]
    else:
        c = {"sources": "-", "records": "-", "quarantined": "-", "queries": "-", "reports": "-"}   # read-only: nothing is disclosed
    cols = st.columns(5)
    for col, (label, key) in zip(cols, (("Sources", "sources"), ("Records", "records"), ("Quarantined", "quarantined"),
                                        ("Queries", "queries"), ("Reports", "reports"))):
        col.metric(label, c[key])
    st.markdown(" → ".join(f"`{s}`" for s in STEPS))
    visible = sources.list_sources(store, who) if who else []
    if can_run:
        q = st.text_area("Analytical question", key="intel_q", max_chars=1000,
                         placeholder="Identify emerging trends across semiconductor companies and supply chains")
        names = {f"{s['name']} ({s['category']})": s["source_id"] for s in visible}
        pick = st.multiselect("Sources (default: all you can access)", sorted(names), key="intel_src")
        d1, d2 = st.columns(2)
        since = d1.text_input("From (YYYY-MM-DD, optional)", key="intel_since")
        until = d2.text_input("To (YYYY-MM-DD, optional)", key="intel_until")
        if st.button("Run inquiry", key="intel_run"):
            try:
                st.session_state["intel_report"] = inquiry.run_inquiry(
                    store, caller=who, question=q, clock=clock, source_ids=[names[p] for p in pick] or None,
                    since=since or None, until=until or None)
            except IntelError as e:
                st.error(f"{e.status}: {e.message}")
    rep = st.session_state.get("intel_report")
    if not rep:
        st.caption("No report yet.")
        return
    st.subheader(f"Report {rep['report_id']}  ·  status {rep['status']}")
    t_ev, t_st, t_hy, t_mi, t_md = st.tabs(["Evidence", "Statistics", "Hypotheses", "Missing evidence", "Report"])
    with t_ev:
        for e in rep["evidence"]:
            with st.container(border=True):
                st.markdown(f"`{e['evidence_id']}`  ·  {e['source_name']}  ·  published {e['published_at'] or 'unknown'}  ·  "
                            f"retrieved {e['retrieved_at']}")
                st.text(e["excerpt"])  # untrusted text: plain text only, never rendered as markdown/HTML
                st.caption(f"provenance digest {e['provenance_hashes_digest'][:16]}...")
    with t_st:
        for s in rep["statistics"]:
            st.markdown(f"**{s['subject']}** (`{s['stat_id']}`, {s['method_version']})")
            st.json(s["result"], expanded=False)
    with t_hy:
        for h in rep["hypotheses"]:
            with st.container(border=True):
                st.markdown(f"**{h['hypothesis_id']}** ({h['kind']}): {h['statement']}")
                st.caption(f"supporting: {[x['evidence_id'] for x in h['supporting']]}  ·  contradicting: "
                           f"{[x['evidence_id'] for x in h['contradicting']]}  ·  probability: {h['probability']} "
                           f"({h['probability_reason']})  ·  review by {h['review_date']}")
    with t_mi:
        for m in rep["missing_evidence"] or []:
            st.write(f"- **{m['kind']}**: {m['item']}")
        if not rep["missing_evidence"]:
            st.caption("None recorded.")
    with t_md:
        md = to_markdown(rep)
        st.download_button("Download report (Markdown)", md, file_name=f"{rep['report_id']}.md", key="intel_dl")
        st.code(md, language="markdown")

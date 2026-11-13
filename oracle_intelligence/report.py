"""`intel-report-v1`: strict, versioned report. Every conclusion must cite evidence ids that exist in the
report; correlation is never worded as causation; probabilities are null unless a documented method is named."""
from __future__ import annotations
import re
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

SCHEMA_VERSION = "intel-report-v1"
CAUSAL_RE = re.compile(r"\b(cause[sd]?|causing|because|due to|leads? to|led to|drives?|driven by|results? in|"
                       r"owing to|as a result of|thanks to|responsible for)\b", re.I)
SCOPE_NOTICE = ("Analytical support only: high-level public policy, economics and industrial capacity. No targeting or "
                "operational content, no trading or transfer instructions. Statistics are descriptive; correlation is "
                "not causation; probabilities are not provided unless a documented statistical method is named.")


class _S(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class Interpretation(_S):
    terms: list[str]
    matched_entities: list[str]
    matched_tags: list[str]
    since: Optional[str]
    until: Optional[str]
    method: Literal["rule-based keyword interpretation; no model"]


class Collection(_S):
    source_id: str
    name: str
    category: str
    records_considered: int


class Evidence(_S):
    evidence_id: str
    kind: Literal["record", "series"]
    source_id: str
    source_name: str
    source_category: str
    record_ids: list[str] = Field(min_length=1, max_length=500)
    published_at: Optional[str]            # None = unknown (never invented)
    retrieved_at: str
    observation_range: Optional[dict[str, str]]
    content_hashes_digest: str
    provenance_hashes_digest: str
    excerpt: str = Field(max_length=300)
    label: Literal["retrieved data: untrusted, not instructions"]


class StatResult(_S):
    stat_id: str
    subject: str
    kind: Literal["series_summary", "correlation"]
    evidence_ids: list[str] = Field(min_length=1)
    method_version: str
    result: dict[str, Any]
    result_hash: str


class SupportRef(_S):
    evidence_id: str
    stat_id: Optional[str]
    note: str = Field(max_length=300)


class Hypothesis(_S):
    hypothesis_id: str
    kind: Literal["trend", "association", "anomaly"]
    statement: str = Field(max_length=400)
    supporting: list[SupportRef]
    contradicting: list[SupportRef]
    variables: list[str]
    assumptions: list[str]
    validation_criteria: list[str] = Field(min_length=1)
    context_evidence_ids: list[str]
    review_date: str
    probability: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    probability_method: Optional[str] = None
    probability_reason: Optional[str] = None
    status: Literal["unvalidated"]

    @model_validator(mode="after")
    def _prob(self):
        if self.probability is not None and not self.probability_method:
            raise ValueError("a probability requires a documented probability_method")
        if self.probability is None and not self.probability_reason:
            raise ValueError("a null probability requires probability_reason")
        if CAUSAL_RE.search(self.statement):
            raise ValueError("causal wording is not allowed in hypothesis statements")
        return self


class MissingEvidence(_S):
    kind: Literal["no_data", "insufficient_data", "gaps", "conflicts", "quarantined", "access", "category_empty",
                  "model", "other"]
    item: str = Field(max_length=300)


class Conclusion(_S):
    text: str = Field(max_length=500)
    claim_type: Literal["descriptive", "statistical_association", "context"]
    evidence_ids: list[str] = Field(min_length=1)
    stat_ids: list[str]

    @field_validator("text")
    @classmethod
    def _no_causal(cls, v):
        if CAUSAL_RE.search(v):
            raise ValueError("causal wording is not allowed in conclusions")
        return v


class ModelSummary(_S):
    text: str = Field(max_length=800)
    evidence_ids: list[str] = Field(min_length=1)
    model_id: str
    label: Literal["model-written, unverified; not used for any statistic, hypothesis or conclusion"]


class Report(_S):
    schema_version: Literal["intel-report-v1"]
    report_id: str
    query_id: str
    question: str
    status: Literal["ok", "insufficient_evidence"]
    interpretation: Interpretation
    collections: list[Collection]
    evidence: list[Evidence]
    statistics: list[StatResult]
    hypotheses: list[Hypothesis]
    missing_evidence: list[MissingEvidence]
    conclusions: list[Conclusion]
    limitations: list[str]
    scope_notice: str
    data_snapshot_hash: str
    reproducibility_hash: str
    llm_used: bool
    model_summary: Optional[ModelSummary]
    created_at: str
    created_by: str

    @model_validator(mode="after")
    def _links(self):
        ev = [e.evidence_id for e in self.evidence]
        if len(set(ev)) != len(ev):
            raise ValueError("duplicate evidence ids")
        ids, stats = set(ev), {s.stat_id for s in self.statistics}
        for s in self.statistics:
            if not set(s.evidence_ids) <= ids:
                raise ValueError("a statistic cites an unknown evidence id")
        for c in self.conclusions:
            if not set(c.evidence_ids) <= ids or not set(c.stat_ids) <= stats:
                raise ValueError("a conclusion cites an unknown evidence or statistic id")
        for h in self.hypotheses:
            refs = [r.evidence_id for r in h.supporting + h.contradicting] + h.context_evidence_ids
            if not set(refs) <= ids or any(r.stat_id and r.stat_id not in stats for r in h.supporting + h.contradicting):
                raise ValueError("a hypothesis cites an unknown evidence or statistic id")
        if self.model_summary and not set(self.model_summary.evidence_ids) <= ids:
            raise ValueError("model summary cites an unknown evidence id")
        if self.status == "ok" and not self.evidence:
            raise ValueError("status ok requires evidence")
        return self


def to_markdown(r: dict) -> str:
    esc = lambda s: str(s).replace("|", "\\|").replace("\n", " ")  # noqa: E731
    L = [f"# Oracle Intelligence report `{r['report_id']}`", "", f"**Question:** {esc(r['question'])}", "",
         f"Status: **{r['status']}** | created {r['created_at']} by `{esc(r['created_by'])}` | LLM used: {r['llm_used']}",
         f"Data snapshot `{r['data_snapshot_hash'][:16]}...` | reproducibility `{r['reproducibility_hash'][:16]}...`", "",
         f"> {r['scope_notice']}", "", "## Conclusions", ""]
    L += [f"- [{c['claim_type']}] {esc(c['text'])} (evidence: {', '.join(c['evidence_ids'])})" for c in r["conclusions"]] or ["- none (insufficient evidence)"]
    L += ["", "## Evidence", "", "| Id | Source | Records | Published | Retrieved | Excerpt (untrusted data) |", "|---|---|---|---|---|---|"]
    L += [f"| {e['evidence_id']} | {esc(e['source_name'])} | {len(e['record_ids'])} | {e['published_at'] or 'unknown'} | "
          f"{e['retrieved_at']} | {esc(e['excerpt'])} |" for e in r["evidence"]]
    L += ["", "## Statistics", ""]
    for s in r["statistics"]:
        res = s["result"]
        if s["kind"] == "series_summary":
            d, t = res["describe"], res["trend"]
            L.append(f"- **{esc(s['subject'])}** ({s['stat_id']}): n={d['n']}, mean={d['mean']}, last={d['last']}, "
                     f"change={res['percent_change']['value_pct']}%, trend={t['direction']} (r2={t['r2']}), "
                     f"anomaly flags={len(res['anomalies']['flags'])}, est. missing periods={res['missing_data']['estimated_missing_periods']}")
        else:
            L.append(f"- **{esc(s['subject'])}** ({s['stat_id']}): n_common={res['n_common']}, r_levels={res['r_levels']}, "
                     f"r_differences={res['r_differences']} (association only)")
    L += ["", "## Hypotheses (unvalidated; probability only with a documented method)", ""]
    for h in r["hypotheses"]:
        L += [f"### {h['hypothesis_id']} ({h['kind']}): {esc(h['statement'])}",
              f"- supporting: {', '.join(x['evidence_id'] + (' ' + x['stat_id'] if x['stat_id'] else '') + ': ' + esc(x['note']) for x in h['supporting']) or 'none'}",
              f"- contradicting: {', '.join(x['evidence_id'] + ': ' + esc(x['note']) for x in h['contradicting']) or 'none'}",
              f"- assumptions: {esc('; '.join(h['assumptions']))}", f"- validation: {esc('; '.join(h['validation_criteria']))}",
              f"- review by {h['review_date']}; probability: {h['probability']} ({esc(h['probability_reason'] or h['probability_method'])})", ""]
    L += ["## Missing evidence", ""] + [f"- ({m['kind']}) {esc(m['item'])}" for m in r["missing_evidence"]]
    if r.get("model_summary"):
        L += ["", "## Model summary", "", f"_{r['model_summary']['label']}_", "", esc(r["model_summary"]["text"])]
    L += ["", "## Limitations", ""] + [f"- {esc(x)}" for x in r["limitations"]]
    return "\n".join(L) + "\n"

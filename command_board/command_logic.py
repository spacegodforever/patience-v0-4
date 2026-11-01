from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List


PRIORITY_RANK = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
}

LANE_RANK = {
    "contain": 0,
    "act_now": 1,
    "proceed": 1,
    "escalate": 1,
    "prepare": 2,
    "watch": 3,
    "observe": 3,
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_get(payload: dict, path: Iterable[str], default: Any = None) -> Any:
    current: Any = payload
    for key in path:
        if not isinstance(current, dict) or key not in current:
            return default
        current = current[key]
    return current


def normalize_priority(value: str | None, fallback: str = "medium") -> str:
    if not value:
        return fallback
    value = str(value).lower().strip()
    return value if value in PRIORITY_RANK else fallback


def mode_to_lane(mode: str | None, score: float | None = None) -> str:
    mode = (mode or "").lower().strip()
    if mode == "contain":
        return "contain"
    if mode in {"proceed", "escalate"}:
        return "act_now"
    if mode == "prepare":
        return "prepare"
    if score is not None and score < 45:
        return "act_now"
    return "watch"


def command_card(
    *,
    lane: str,
    priority: str,
    domain: str,
    title: str,
    owner: str,
    action: str,
    reason: str,
    evidence_required: list[str] | None = None,
    guardrails: list[str] | None = None,
    metric: str | None = None,
    source: str | None = None,
    cadence_days: int | None = None,
    deadline_days: int | None = None,
) -> dict:
    return {
        "lane": lane,
        "priority": normalize_priority(priority),
        "domain": domain,
        "title": title,
        "owner": owner or "Unassigned",
        "action": action,
        "reason": reason,
        "evidence_required": evidence_required or [],
        "guardrails": guardrails or [],
        "metric": metric or "",
        "source": source or domain,
        "review_cadence_days": cadence_days,
        "deadline_days": deadline_days,
    }


def build_command_board(db: Any, experience_db: Any | None = None, risk_db: Any | None = None) -> dict:
    governance = db.governance_status()
    trajectory = db.economic_trajectory()
    recovery_actions = db.generate_recovery_actions()
    projects = db.project_follow_through()
    employment = db.employment_path()
    investors = db.qualified_investor_pools(threshold=0)

    cards: list[dict] = []

    for policy in governance.get("hard_stops", []):
        cards.append(command_card(
            lane="contain",
            priority="critical",
            domain="governance",
            title=f"Hard stop: {policy.get('domain', 'Governance')}",
            owner=policy.get("owner", "Matthew"),
            action=f"Satisfy policy before expansion: {policy.get('rule', '')}",
            reason="Active hard-stop governance rule blocks unsafe scaling.",
            evidence_required=policy.get("evidence_required", []),
            guardrails=["No investor, employment, or public outreach using sensitive claims until evidence is recorded."],
            metric="hard_stop_active",
            source="/governance/status",
            cadence_days=policy.get("review_cadence_days"),
            deadline_days=1,
        ))

    for action in recovery_actions:
        item = action if isinstance(action, dict) else action.__dict__
        # RecoveryAction stores enum objects in direct __dict__, so make them readable.
        priority = getattr(item.get("priority"), "value", item.get("priority", "medium")) if isinstance(item, dict) else "medium"
        patience_mode = getattr(item.get("patience_mode"), "value", item.get("patience_mode", "prepare")) if isinstance(item, dict) else "prepare"
        score = float(item.get("score", 0))
        cards.append(command_card(
            lane=mode_to_lane(patience_mode, score),
            priority=priority,
            domain="operations",
            title=f"{item.get('workstream', '')} × {item.get('capability', '')}",
            owner=item.get("owner", "Unassigned"),
            action=item.get("recommended_action", "Resolve the highest-impact operational blocker."),
            reason=item.get("reason", "Operational score is below threshold."),
            evidence_required=["decision log", "owner", "completion proof"],
            guardrails=["Do not broaden scope until the named blocker is resolved."],
            metric=f"score={score}",
            source="/recovery-actions",
            cadence_days=item.get("review_cadence_days"),
            deadline_days=item.get("escalation_deadline_days"),
        ))

    for project in projects:
        assessment = project.get("patience_assessment", {})
        mode = assessment.get("mode", "prepare")
        score = float(project.get("follow_through_score", 0))
        priority = assessment.get("priority", "medium")
        lane = mode_to_lane(mode, score)
        if project.get("status") == "blocked":
            lane = "contain"
            priority = "critical"
        cards.append(command_card(
            lane=lane,
            priority=priority,
            domain="projects",
            title=project.get("name", "Project"),
            owner=project.get("owner", "Unassigned"),
            action=project.get("recommended_follow_through") or project.get("next_action") or "Define the next concrete action.",
            reason=f"Follow-through score {score}; stage={project.get('stage')}; status={project.get('status')}.",
            evidence_required=[project.get("north_star_metric", "north-star metric"), "next action", "owner note"],
            guardrails=assessment.get("guardrails", []),
            metric=f"follow_through_score={score}",
            source="/projects/follow-through",
            cadence_days=assessment.get("review_cadence_days"),
            deadline_days=assessment.get("escalation_deadline_days"),
        ))

    for item in employment:
        assessment = item.get("patience_assessment", {})
        readiness = float(item.get("readiness_score", 0))
        lane = "act_now" if readiness >= 75 and not item.get("gaps") else "prepare"
        if assessment.get("mode") in {"proceed", "escalate"} and readiness >= 65:
            lane = "act_now"
        cards.append(command_card(
            lane=lane,
            priority=assessment.get("priority", "medium"),
            domain="employment",
            title=f"{item.get('title', 'Role')} — {item.get('organization', '')}",
            owner="Matthew",
            action=item.get("recommended_next_step") or item.get("next_action") or "Prepare application proof packet.",
            reason=f"Fit score {item.get('fit_score')}; readiness score {readiness}; gaps={len(item.get('gaps', []))}.",
            evidence_required=["tailored resume", "proof artifact", "role-specific outreach"],
            guardrails=assessment.get("guardrails", []),
            metric=f"readiness_score={readiness}",
            source="/employment/path",
            cadence_days=assessment.get("review_cadence_days"),
            deadline_days=assessment.get("escalation_deadline_days"),
        ))

    hard_stop_count = int(governance.get("hard_stop_count", 0))
    for pool in investors:
        assessment = pool.get("patience_assessment", {})
        readiness = float(pool.get("capital_readiness_score", 0))
        lane = "prepare"
        priority = assessment.get("priority", "medium")
        if hard_stop_count > 0:
            lane = "contain"
            priority = "high"
        elif readiness >= 70 and pool.get("status") in {"ready_to_contact", "warming"}:
            lane = "act_now"
        cards.append(command_card(
            lane=lane,
            priority=priority,
            domain="investors",
            title=pool.get("name", "Investor Pool"),
            owner=pool.get("relationship_owner", "Matthew"),
            action=pool.get("recommended_next_step") or pool.get("next_action") or "Qualify investor and assemble proof packet.",
            reason=f"Qualification score {pool.get('qualification_score')}; capital readiness {readiness}; hard stops={hard_stop_count}.",
            evidence_required=pool.get("evidence_required", []),
            guardrails=assessment.get("guardrails", []),
            metric=f"capital_readiness_score={readiness}",
            source="/investor-pools/qualified",
            cadence_days=assessment.get("review_cadence_days"),
            deadline_days=assessment.get("escalation_deadline_days"),
        ))

    if experience_db is not None:
        customer_control = experience_db.customer_control_snapshot()
        cx = customer_control.get("customer_experience", {})
        control_status = customer_control.get("enterprise_controls", {})
        innovation = customer_control.get("innovation_risk", {})

        for control in control_status.get("failed_controls", []) + control_status.get("critical_attention", []) + control_status.get("overdue_controls", []):
            cards.append(command_card(
                lane="contain",
                priority="critical" if control.get("risk_level") in {"critical", "high"} else "high",
                domain="enterprise_control",
                title=f"Control: {control.get('domain', '')} / {control.get('control_name', '')}",
                owner=control.get("owner", "Matthew"),
                action=control.get("recommended_action", "Review and remediate control."),
                reason=f"Control score {control.get('control_score')}; status={control.get('status')}; overdue={control.get('is_overdue')}.",
                evidence_required=control.get("evidence_required", []),
                guardrails=["Do not scale the related customer, investor, or product claim until control evidence is current."],
                metric=f"control_score={control.get('control_score')}",
                source="/enterprise-controls/status",
                cadence_days=control.get("review_cadence_days"),
                deadline_days=1 if control.get("status") == "failed" else 3,
            ))

        for influence in cx.get("top_positive_influences", [])[:5]:
            score = float(influence.get("influence_score", 0))
            lane = "act_now" if score >= 75 else "prepare"
            cards.append(command_card(
                lane=lane,
                priority="high" if score >= 75 else "medium",
                domain="customer_experience",
                title=f"CX impact: {influence.get('touchpoint', '')} / {influence.get('metric_name', '')}",
                owner=influence.get("owner", "Unassigned"),
                action=influence.get("recommended_next_step") or influence.get("follow_up_action") or "Capture stronger customer evidence.",
                reason=f"Positive outcome: {influence.get('positive_outcome', '')} Score={score}.",
                evidence_required=["metric", "evidence source", "owner", "follow-up action"],
                guardrails=["Do not claim traction externally unless metric movement and source are present."],
                metric=f"influence_score={score}",
                source="/customer-experience/positive-impact",
                cadence_days=7,
                deadline_days=3 if score >= 75 else 7,
            ))

        lanes_payload = innovation.get("lanes", {})
        for lane_name, items in lanes_payload.items():
            for item in items[:4]:
                risk_level = item.get("risk_level", "moderate")
                priority = "critical" if lane_name == "contain" and risk_level == "critical" else ("high" if lane_name in {"contain", "act_now"} else "medium")
                cards.append(command_card(
                    lane=lane_name,
                    priority=priority,
                    domain="innovation_risk",
                    title=item.get("name", "Innovation Risk"),
                    owner=item.get("owner", "Unassigned"),
                    action=item.get("recommended_action", "Manage innovation risk."),
                    reason=f"Risk-adjusted score {item.get('risk_adjusted_score')}; posture={item.get('posture')}; risk={risk_level}.",
                    evidence_required=["control link", "next experiment", "kill criteria"],
                    guardrails=["Use small experiments; record kill criteria before adding capital, hiring, or public claims."],
                    metric=f"risk_adjusted_score={item.get('risk_adjusted_score')}",
                    source="/innovation-risks/portfolio",
                    cadence_days=7,
                    deadline_days=3 if lane_name in {"contain", "act_now"} else 14,
                ))



    if risk_db is not None:
        risk_snapshot = risk_db.risk_control_snapshot()
        for item in risk_snapshot.get("top_problematic_concerns", [])[:10]:
            lane = item.get("lane", "prepare")
            priority = "critical" if lane == "contain" else ("high" if lane == "act_now" else "medium")
            title = item.get("failure_name") or item.get("system_component") or item.get("dependency_name") or item.get("market_vector") or "Risk item"
            owner = item.get("control_owner") or item.get("owner") or "Unassigned"
            metric_value = item.get("risk_score", item.get("failure_score", item.get("exposure_score", 0)))
            cards.append(command_card(
                lane=lane,
                priority=priority,
                domain=f"risk_intelligence/{item.get('category', 'risk')}",
                title=title,
                owner=owner,
                action=item.get("recommended_action") or item.get("avoid_by") or item.get("strategic_response") or "Control the risk before scale.",
                reason=item.get("failure_mode") or item.get("consequence") or item.get("current_position") or item.get("concern_type", "Risk requires review."),
                evidence_required=["owner", "fallback/control", "evidence trail"],
                guardrails=["No scale, investor claim, hiring commitment, or customer-impact action until this risk has owner, evidence, and fallback."],
                metric=f"risk_metric={metric_value}",
                source="/command/risk-ground-truth",
                cadence_days=3 if lane in {"contain", "act_now"} else 7,
                deadline_days=1 if lane == "contain" else 3,
            ))

    trajectory_summary = trajectory.get("trajectory_summary", "No economic signals available.")
    cards.append(command_card(
        lane="watch",
        priority="medium",
        domain="economic_trajectory",
        title="Economic trajectory watch",
        owner="Strategy Lead",
        action="Maintain capital discipline: prioritize proof, revenue, employment stability, and non-dilutive funding before broad expansion.",
        reason=trajectory_summary,
        evidence_required=["updated macro signal", "job-market signal", "capital-cost signal"],
        guardrails=["Do not assume cheap capital; prove near-term value before large capital asks."],
        metric=f"signal_count={trajectory.get('signal_count', 0)}",
        source="/trajectory",
        cadence_days=7,
        deadline_days=7,
    ))

    sorted_cards = sorted(
        cards,
        key=lambda c: (LANE_RANK.get(c["lane"], 9), PRIORITY_RANK.get(c["priority"], 9), c.get("deadline_days") or 999, c["domain"]),
    )

    lanes = {"contain": [], "act_now": [], "prepare": [], "watch": []}
    for card in sorted_cards:
        lanes.setdefault(card["lane"], []).append(card)

    seventy_two_hour = []
    for card in sorted_cards:
        if card["lane"] in {"contain", "act_now"}:
            seventy_two_hour.append({
                "title": card["title"],
                "owner": card["owner"],
                "action": card["action"],
                "deadline_days": min(card.get("deadline_days") or 3, 3),
                "evidence_required": card["evidence_required"][:3],
            })
        if len(seventy_two_hour) >= 7:
            break

    if not seventy_two_hour:
        seventy_two_hour.append({
            "title": "Create proof packet",
            "owner": "Matthew",
            "action": "Assemble one-page narrative, prototype screenshot, governance note, and next ask.",
            "deadline_days": 3,
            "evidence_required": ["narrative", "prototype proof", "governance note"],
        })

    return {
        "generated_at": utc_now(),
        "doctrine": "Oracle interprets. PATIENCE governs timing, consent, audit, and grounded action. Act only when evidence, owner, and next proof are defined.",
        "operating_posture": determine_operating_posture(lanes, governance),
        "seventy_two_hour_mandate": seventy_two_hour,
        "lanes": lanes,
        "counts": {lane: len(items) for lane, items in lanes.items()},
        "governance_summary": {
            "hard_stop_count": governance.get("hard_stop_count", 0),
            "required_policy_count": governance.get("required_policy_count", 0),
            "active_policy_count": governance.get("active_policy_count", 0),
        },
        "economic_trajectory": trajectory,
    }


def determine_operating_posture(lanes: dict, governance: dict) -> str:
    if governance.get("hard_stop_count", 0) > 0:
        return "CONTAIN_AND_PREPARE: resolve hard-stop governance while building proof assets."
    if len(lanes.get("act_now", [])) >= 3:
        return "ACT_NOW: execute top actions with daily review."
    if len(lanes.get("prepare", [])) >= 3:
        return "PREPARE_TO_SCALE: proof, policies, and relationships need tightening before outreach."
    return "WATCH_AND_COMPOUND: maintain cadence and protect optionality."


def build_evolution_readiness(db: Any, experience_db: Any | None = None) -> dict:
    cells = db.list_cells()
    projects = db.list_projects(include_complete=False)
    employment = db.list_employment(active_only=True)
    investors = db.list_investor_pools()
    governance = db.governance_status()

    cell_score = avg([cell.score() for cell in cells])
    project_score = avg([project.follow_through_score() for project in projects])
    employment_score = avg([item.readiness_score() for item in employment])
    investor_score = avg([pool.qualification_score() for pool in investors])

    cx_score = 0.0
    control_score = 0.0
    innovation_score = 0.0
    if experience_db is not None:
        customer_control = experience_db.customer_control_snapshot()
        cx_score = float(customer_control.get("customer_experience", {}).get("average_influence_score", 0.0))
        control_score = float(customer_control.get("enterprise_controls", {}).get("average_control_score", 0.0))
        innovation_score = float(customer_control.get("innovation_risk", {}).get("average_risk_adjusted_score", 0.0))

    base = avg([cell_score, project_score, employment_score, investor_score, cx_score, control_score, innovation_score])
    penalty = governance.get("hard_stop_count", 0) * 12 + governance.get("required_policy_count", 0) * 4
    readiness_score = round(max(0, min(100, base - penalty)), 2)

    if readiness_score >= 80:
        phase = "scale"
    elif readiness_score >= 65:
        phase = "outreach_ready"
    elif readiness_score >= 45:
        phase = "proof_building"
    else:
        phase = "stabilization"

    gaps = []
    if governance.get("hard_stop_count", 0) > 0:
        gaps.append("Resolve active hard-stop governance rules before investor or public expansion.")
    if cell_score < 60:
        gaps.append("Raise operations matrix average above 60 by clearing blockers and dependency owners.")
    if project_score < 60:
        gaps.append("Convert projects into named next actions with evidence and due dates.")
    if employment_score < 70:
        gaps.append("Build employment proof packet: role families, resume bullets, portfolio artifact, outreach script.")
    if investor_score < 65:
        gaps.append("Improve investor readiness with prototype evidence, narrative, risk note, and capital use plan.")
    if cx_score < 55:
        gaps.append("Add evidence-backed customer experience influence records before making broad customer-impact claims.")
    if control_score < 70:
        gaps.append("Raise enterprise control score by clearing failed, overdue, and critical controls.")
    if innovation_score < 60:
        gaps.append("Convert innovation risks into small experiments with control links and kill criteria.")

    next_gate = {
        "stabilization": "Governance and operational blockers controlled.",
        "proof_building": "Proof packet complete and two strong use cases documented.",
        "outreach_ready": "Investor/employer outreach allowed with source trail and risk note.",
        "scale": "Repeatable system ready for partnerships, capital, and hiring expansion.",
    }[phase]

    return {
        "generated_at": utc_now(),
        "readiness_score": readiness_score,
        "phase": phase,
        "next_gate": next_gate,
        "component_scores": {
            "operations_matrix": cell_score,
            "project_follow_through": project_score,
            "employment_path": employment_score,
            "investor_pool": investor_score,
            "customer_experience_influence": cx_score,
            "enterprise_control": control_score,
            "innovation_risk": innovation_score,
            "governance_penalty": penalty,
        },
        "gaps": gaps,
        "act_now": build_command_board(db, experience_db)["seventy_two_hour_mandate"],
    }


def avg(values: list[float]) -> float:
    values = [float(v) for v in values if v is not None]
    if not values:
        return 0.0
    return round(sum(values) / len(values), 2)

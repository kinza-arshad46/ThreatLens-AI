"""
ai_analyst.py
-------------
The AI Security Analyst (blueprint Section 11): retrieves real evidence
from the database before answering, rather than being a free-floating
chatbot. The blueprint's own example workflow is:

    Analyst Question -> Intent/Query Understanding -> Retrieve Evidence
    -> Compute/Filter Analytics -> Generate Answer -> Show Evidence
    -> Link to Investigation View

This module implements exactly that pipeline, in code, without calling out
to an external LLM API: intent is matched against a small set of known
question patterns (the same three example questions the blueprint itself
gives), each pattern runs a real SQL query for evidence, and the answer is
built from a template filled in with the retrieved numbers. This keeps the
"evidence-based, not black-box" promise literally true — every number in
every answer traces back to a query result printed alongside it, and the
whole thing runs with no external API key or network call required.

Extending this later with a real LLM (e.g. via the Anthropic API) would
slot in at the `generate_answer()` step only — intent understanding could
stay rule-based or be upgraded, but evidence retrieval should always
precede generation, exactly as designed here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

from sqlalchemy import func
from sqlalchemy.orm import Session

from src.database.models import Alert, Attack, SecurityEvent


@dataclass
class AnalystAnswer:
    question: str
    intent: str
    answer: str
    evidence: dict = field(default_factory=dict)


def _intent_increase_in_activity(q: str) -> bool:
    keywords = ["increase", "why", "caused", "spike", "suspicious activity"]
    return any(k in q for k in keywords)


def _intent_users_to_investigate(q: str) -> bool:
    keywords = ["which users", "who should", "investigate", "priority", "risky users"]
    return any(k in q for k in keywords)


def _intent_attack_trend(q: str) -> bool:
    keywords = ["attack increased", "most this week", "trend", "which attack"]
    return any(k in q for k in keywords)


def answer_question(db: Session, question: str) -> AnalystAnswer:
    """
    Main entry point. Matches the question against known intents (mirroring
    the blueprint's three example questions), retrieves real evidence for
    whichever intent matched, and returns a templated answer plus the raw
    evidence dict — the evidence is what the dashboard's chat bubble would
    show as supporting detail, and what a `/analyst/query` endpoint returns
    as structured JSON alongside the natural-language string.
    """
    q = question.lower().strip()

    if _intent_increase_in_activity(q):
        return _answer_increase_in_activity(db, question)
    if _intent_users_to_investigate(q):
        return _answer_users_to_investigate(db, question)
    if _intent_attack_trend(q):
        return _answer_attack_trend(db, question)

    return _answer_fallback(db, question)


def _answer_increase_in_activity(db: Session, question: str) -> AnalystAnswer:
    """Blueprint example 1: 'What caused the increase in suspicious activity today?'"""
    since = datetime.utcnow() - timedelta(hours=24)

    total_events = db.query(func.count(SecurityEvent.id)).filter(SecurityEvent.timestamp >= since).scalar() or 0
    attack_events = db.query(func.count(Attack.id)).join(SecurityEvent).filter(SecurityEvent.timestamp >= since).scalar() or 0
    top_attack = (
        db.query(Attack.attack_category, func.count(Attack.id).label("n"))
        .join(SecurityEvent).filter(SecurityEvent.timestamp >= since)
        .group_by(Attack.attack_category).order_by(func.count(Attack.id).desc()).first()
    )
    new_ip_count = (
        db.query(func.count(func.distinct(SecurityEvent.source_ip)))
        .filter(SecurityEvent.timestamp >= since).scalar() or 0
    )

    ratio = (attack_events / total_events * 100) if total_events else 0
    top_type = top_attack[0] if top_attack else "no dominant type"
    top_count = top_attack[1] if top_attack else 0

    answer = (
        f"In the last 24 hours, {attack_events} of {total_events} events "
        f"({ratio:.1f}%) were classified as attacks. The largest contributor was "
        f"'{top_type}' with {top_count} events, across {new_ip_count} distinct source IPs."
    )
    evidence = {
        "window_hours": 24, "total_events": total_events, "attack_events": attack_events,
        "attack_ratio_pct": round(ratio, 1), "top_attack_type": top_type,
        "top_attack_count": top_count, "distinct_source_ips": new_ip_count,
    }
    return AnalystAnswer(question, "increase_in_activity", answer, evidence)


def _answer_users_to_investigate(db: Session, question: str) -> AnalystAnswer:
    """Blueprint example 2: 'Which users require immediate investigation?'"""
    rows = (
        db.query(Alert.source_ip, func.avg(Alert.threat_score).label("avg_score"), func.count(Alert.id).label("n"))
        .filter(Alert.severity.in_(["High", "Critical"]))
        .group_by(Alert.source_ip)
        .order_by(func.avg(Alert.threat_score).desc())
        .limit(3)
        .all()
    )

    if not rows:
        answer = "No users currently exceed the high/critical risk threshold."
        return AnalystAnswer(question, "users_to_investigate", answer, {"flagged_users": []})

    names = ", ".join(f"{r[0]} ({r[1]:.0f}%)" for r in rows)
    answer = (
        f"{len(rows)} user(s)/sources exceed the high-risk threshold: {names}. "
        f"Recommend starting with {rows[0][0]}, the highest average threat score."
    )
    evidence = {"flagged_users": [{"source_ip": r[0], "avg_threat_score": round(r[1], 1), "alert_count": r[2]} for r in rows]}
    return AnalystAnswer(question, "users_to_investigate", answer, evidence)


def _answer_attack_trend(db: Session, question: str) -> AnalystAnswer:
    """Blueprint example 3: 'What attack increased most this week?'"""
    since = datetime.utcnow() - timedelta(days=7)
    rows = (
        db.query(Attack.attack_category, func.count(Attack.id).label("n"))
        .join(SecurityEvent).filter(SecurityEvent.timestamp >= since)
        .group_by(Attack.attack_category).order_by(func.count(Attack.id).desc())
        .all()
    )

    if not rows:
        answer = "No attack data available for the past 7 days yet."
        return AnalystAnswer(question, "attack_trend", answer, {"by_category": []})

    top = rows[0]
    answer = (
        f"Over the past 7 days, '{top[0]}' was the most frequent attack type with "
        f"{top[1]} events, ahead of {', '.join(f'{r[0]} ({r[1]})' for r in rows[1:4])}."
    )
    evidence = {"window_days": 7, "by_category": [{"category": r[0], "count": r[1]} for r in rows]}
    return AnalystAnswer(question, "attack_trend", answer, evidence)


def _answer_fallback(db: Session, question: str) -> AnalystAnswer:
    """
    No known intent matched. Rather than guessing, the analyst is honest
    about its current scope — this keeps the "evidence-based, not black-box"
    promise intact instead of fabricating a plausible-sounding but ungrounded
    answer, which matters more for a security tool than for a general chatbot.
    """
    answer = (
        "I can currently answer questions about: recent activity spikes and their "
        "cause, which users/sources need investigation, and which attack type is "
        "trending. Try rephrasing your question closer to one of those, or extend "
        "`src/analyst/ai_analyst.py` with a new intent pattern and evidence query."
    )
    return AnalystAnswer(question, "fallback", answer, {})

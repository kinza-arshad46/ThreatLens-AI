"""POST /analyst/query — the AI Security Analyst endpoint (blueprint Section 11)."""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from src.analyst.ai_analyst import answer_question
from src.database.session import get_db
from api.schemas.schemas import AnalystQueryIn, AnalystQueryOut

router = APIRouter(tags=["analyst"])


@router.post("/analyst/query", response_model=AnalystQueryOut)
def query_analyst(payload: AnalystQueryIn, db: Session = Depends(get_db)):
    result = answer_question(db, payload.question)
    return AnalystQueryOut(
        question=result.question, intent=result.intent,
        answer=result.answer, evidence=result.evidence,
    )

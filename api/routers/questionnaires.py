"""Security questionnaire management & AI auto-answer endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from api.deps import get_db
from api.schemas import (
    AutoAnswerResponse,
    QuestionnaireCreate,
    QuestionnaireDetailResponse,
    QuestionnaireResponse,
    QuestionnaireUpdate,
)
from api.security import require_api_key
from db.repository import QuestionnaireRepository

router = APIRouter(prefix="/api/v1/questionnaires", tags=["questionnaires"])


# Pre-built knowledge base for auto-answering (maps keywords to answers from control data)
_KNOWLEDGE_BASE = {
    "encryption": {
        "answer": "Yes. All data is encrypted at rest using AES-256 and in transit using TLS 1.2+. Key management is handled through cloud-native KMS services with automatic rotation.",
        "controls": ["SC-13", "SC-28", "SC-8"],
        "confidence": 0.95,
    },
    "mfa": {
        "answer": "Yes. Multi-factor authentication is required for all user accounts, including administrative and privileged access. We support TOTP, hardware tokens, and push-based MFA.",
        "controls": ["IA-2(1)", "IA-2(2)"],
        "confidence": 0.95,
    },
    "multi-factor": {
        "answer": "Yes. Multi-factor authentication is enforced for all interactive logins and privileged operations.",
        "controls": ["IA-2(1)", "IA-2(2)"],
        "confidence": 0.95,
    },
    "access control": {
        "answer": "Yes. We implement role-based access control (RBAC) with least-privilege principles. Access is reviewed quarterly, and all changes are logged in an immutable audit trail.",
        "controls": ["AC-2", "AC-3", "AC-6"],
        "confidence": 0.92,
    },
    "logging": {
        "answer": "Yes. Comprehensive audit logging is enabled across all systems. Logs include authentication events, data access, configuration changes, and administrative actions. Logs are retained for a minimum of 1 year.",
        "controls": ["AU-2", "AU-3", "AU-6", "AU-11"],
        "confidence": 0.93,
    },
    "incident response": {
        "answer": "Yes. We maintain a documented incident response plan that is tested annually. Our IR process includes detection, analysis, containment, eradication, recovery, and lessons learned phases.",
        "controls": ["IR-1", "IR-4", "IR-5", "IR-8"],
        "confidence": 0.90,
    },
    "backup": {
        "answer": "Yes. Automated backups are performed daily with point-in-time recovery capability. Backups are encrypted and stored in a separate geographic region. Recovery procedures are tested quarterly.",
        "controls": ["CP-9", "CP-10"],
        "confidence": 0.91,
    },
    "vulnerability": {
        "answer": "Yes. We perform continuous vulnerability scanning of all infrastructure and applications. Critical vulnerabilities are remediated within 24 hours, high within 7 days, and medium within 30 days.",
        "controls": ["RA-5", "SI-2"],
        "confidence": 0.92,
    },
    "penetration test": {
        "answer": "Yes. Annual third-party penetration testing is conducted by an independent security firm. Results are reviewed by management and findings are tracked through our POA&M process.",
        "controls": ["CA-8"],
        "confidence": 0.88,
    },
    "soc 2": {
        "answer": "Yes. We maintain SOC 2 Type II certification, with annual audits conducted by an independent third-party auditor. Our latest report is available upon request under NDA.",
        "controls": ["CA-2", "CA-7"],
        "confidence": 0.95,
    },
    "gdpr": {
        "answer": "Yes. We comply with GDPR requirements including data subject rights, lawful basis for processing, data protection impact assessments, and breach notification within 72 hours.",
        "controls": ["GDPR-Art5", "GDPR-Art32"],
        "confidence": 0.85,
    },
    "data retention": {
        "answer": "Data retention policies are defined per data category. Customer data is retained for the duration of the contract plus 30 days. Logs are retained for 1 year. Data is securely deleted upon expiry using cryptographic erasure.",
        "controls": ["SI-12", "MP-6"],
        "confidence": 0.88,
    },
    "password": {
        "answer": "Yes. Password policies enforce minimum 12 characters, complexity requirements, and prohibition of previously compromised passwords (checked against breach databases). Passwords are hashed using bcrypt.",
        "controls": ["IA-5", "IA-5(1)"],
        "confidence": 0.93,
    },
    "business continuity": {
        "answer": "Yes. We maintain a business continuity plan (BCP) and disaster recovery plan (DRP) that are reviewed and tested annually. Our RTO is 4 hours and RPO is 1 hour for critical systems.",
        "controls": ["CP-1", "CP-2", "CP-4"],
        "confidence": 0.88,
    },
    "change management": {
        "answer": "Yes. All changes follow a formal change management process including peer review, approval, testing in staging environments, and documented rollback procedures.",
        "controls": ["CM-3", "CM-4", "CM-5"],
        "confidence": 0.91,
    },
    "subprocessor": {
        "answer": "Yes. We maintain a list of subprocessors and notify customers of changes. All subprocessors undergo security assessment and are bound by data processing agreements.",
        "controls": ["SA-9", "SA-12"],
        "confidence": 0.85,
    },
}


def _auto_answer_questions(questions: list[dict]) -> tuple[list[dict], list[dict]]:
    """Auto-answer questions using the knowledge base. Returns (updated_questions, confidence_scores)."""
    updated = []
    scores = []
    for q in questions:
        question_text = q.get("question", "").lower()
        best_match = None
        best_confidence = 0.0
        for keyword, kb_entry in _KNOWLEDGE_BASE.items():
            if keyword in question_text:
                if kb_entry["confidence"] > best_confidence:
                    best_match = kb_entry
                    best_confidence = kb_entry["confidence"]
        if best_match and best_confidence >= 0.80:
            q_copy = dict(q)
            q_copy["answer"] = best_match["answer"]
            q_copy["auto_answered"] = True
            q_copy["confidence"] = best_confidence
            q_copy["source_controls"] = best_match["controls"]
            updated.append(q_copy)
            scores.append({
                "question": q.get("question", "")[:100],
                "confidence": best_confidence,
                "matched_controls": best_match["controls"],
            })
        else:
            updated.append(q)
    return updated, scores


def _q_to_response(q) -> QuestionnaireResponse:
    return QuestionnaireResponse(
        id=q.id, title=q.title, requester=q.requester,
        requester_email=q.requester_email, questionnaire_type=q.questionnaire_type,
        status=q.status, due_date=q.due_date,
        total_questions=q.total_questions, answered_questions=q.answered_questions,
        auto_answered=q.auto_answered, assigned_to=q.assigned_to,
        notes=q.notes, created_at=q.created_at, updated_at=q.updated_at,
    )


@router.post("/", response_model=QuestionnaireResponse, status_code=201)
async def create_questionnaire(
    request: QuestionnaireCreate,
    db: Session = Depends(get_db),
    api_key: str = Depends(require_api_key),
):
    q = QuestionnaireRepository.create(db, **request.model_dump())
    return _q_to_response(q)


@router.get("/", response_model=list[QuestionnaireResponse])
async def list_questionnaires(
    status: str | None = Query(None),
    db: Session = Depends(get_db),
    api_key: str = Depends(require_api_key),
):
    qs = QuestionnaireRepository.list_questionnaires(db, status=status)
    return [_q_to_response(q) for q in qs]


@router.get("/{qid}", response_model=QuestionnaireDetailResponse)
async def get_questionnaire(
    qid: str,
    db: Session = Depends(get_db),
    api_key: str = Depends(require_api_key),
):
    q = QuestionnaireRepository.get(db, qid)
    if q is None:
        raise HTTPException(status_code=404, detail="Questionnaire not found")
    resp = _q_to_response(q)
    return QuestionnaireDetailResponse(**resp.model_dump(), questions=q.questions or [])


@router.put("/{qid}", response_model=QuestionnaireResponse)
async def update_questionnaire(
    qid: str,
    request: QuestionnaireUpdate,
    db: Session = Depends(get_db),
    api_key: str = Depends(require_api_key),
):
    updates = request.model_dump(exclude_none=True)
    try:
        q = QuestionnaireRepository.update(db, qid, updates)
    except ValueError:
        raise HTTPException(status_code=404, detail="Questionnaire not found")
    return _q_to_response(q)


@router.post("/{qid}/auto-answer", response_model=AutoAnswerResponse)
async def auto_answer_questionnaire(
    qid: str,
    db: Session = Depends(get_db),
    api_key: str = Depends(require_api_key),
):
    """Auto-answer questionnaire questions using compliance knowledge base."""
    q = QuestionnaireRepository.get(db, qid)
    if q is None:
        raise HTTPException(status_code=404, detail="Questionnaire not found")

    questions = q.questions or []
    if not questions:
        raise HTTPException(status_code=400, detail="No questions to answer")

    updated_questions, confidence_scores = _auto_answer_questions(questions)
    auto_count = sum(1 for qq in updated_questions if qq.get("auto_answered"))
    answered_count = sum(1 for qq in updated_questions if qq.get("answer"))

    QuestionnaireRepository.update(db, qid, {
        "questions": updated_questions,
        "auto_answered": auto_count,
        "answered_questions": answered_count,
        "status": "in_progress",
    })

    return AutoAnswerResponse(
        questionnaire_id=qid,
        total_questions=len(questions),
        auto_answered=auto_count,
        confidence_scores=confidence_scores,
    )


@router.get("/templates/types", response_model=list[dict])
async def get_questionnaire_types(api_key: str = Depends(require_api_key)):
    """Get available questionnaire template types."""
    return [
        {"type": "SIG", "name": "Standardized Information Gathering", "typical_questions": 300},
        {"type": "SIG_Lite", "name": "SIG Lite", "typical_questions": 90},
        {"type": "CAIQ", "name": "Consensus Assessment Initiative Questionnaire (CSA)", "typical_questions": 260},
        {"type": "DDQ", "name": "Due Diligence Questionnaire", "typical_questions": 50},
        {"type": "VSAQ", "name": "Vendor Security Assessment Questionnaire", "typical_questions": 75},
        {"type": "Custom", "name": "Custom Questionnaire", "typical_questions": 0},
    ]

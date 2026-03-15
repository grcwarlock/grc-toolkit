"""Audit collaboration portal endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from api.deps import get_db
from api.schemas import (
    AuditCommentCreate,
    AuditCommentResponse,
    AuditEngagementResponse,
)
from api.security import require_api_key
from db.repository import AuditCommentRepository

router = APIRouter(prefix="/api/v1/audit", tags=["audit-collaboration"])


def _to_response(c) -> AuditCommentResponse:
    return AuditCommentResponse(
        id=c.id, audit_id=c.audit_id, resource_type=c.resource_type,
        resource_id=c.resource_id, author=c.author, author_role=c.author_role,
        comment_type=c.comment_type, content=c.content,
        is_resolved=c.is_resolved, resolved_by=c.resolved_by,
        resolved_at=c.resolved_at, created_at=c.created_at,
    )


@router.post("/comments", response_model=AuditCommentResponse, status_code=201)
async def create_comment(
    request: AuditCommentCreate,
    db: Session = Depends(get_db),
    api_key: str = Depends(require_api_key),
):
    comment = AuditCommentRepository.create(db, **request.model_dump())
    return _to_response(comment)


@router.get("/comments", response_model=list[AuditCommentResponse])
async def list_comments(
    audit_id: str | None = Query(None),
    resource_type: str | None = Query(None),
    resource_id: str | None = Query(None),
    db: Session = Depends(get_db),
    api_key: str = Depends(require_api_key),
):
    if audit_id:
        comments = AuditCommentRepository.list_by_audit(db, audit_id)
    elif resource_type and resource_id:
        comments = AuditCommentRepository.list_by_resource(db, resource_type, resource_id)
    else:
        comments = AuditCommentRepository.list_by_audit(db, "default")
    return [_to_response(c) for c in comments]


@router.post("/comments/{comment_id}/resolve", response_model=AuditCommentResponse)
async def resolve_comment(
    comment_id: str,
    resolved_by: str = Query("analyst"),
    db: Session = Depends(get_db),
    api_key: str = Depends(require_api_key),
):
    try:
        comment = AuditCommentRepository.resolve(db, comment_id, resolved_by)
    except ValueError:
        raise HTTPException(status_code=404, detail="Comment not found")
    return _to_response(comment)


@router.get("/engagements/{audit_id}", response_model=AuditEngagementResponse)
async def get_engagement(
    audit_id: str,
    db: Session = Depends(get_db),
    api_key: str = Depends(require_api_key),
):
    summary = AuditCommentRepository.get_engagement_summary(db, audit_id)
    return AuditEngagementResponse(**summary)

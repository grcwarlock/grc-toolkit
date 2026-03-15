"""Workflow task assignment & management endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from api.deps import get_db
from api.schemas import TaskCommentCreate, TaskCreate, TaskResponse, TaskUpdate
from api.security import require_api_key
from db.repository import TaskRepository

router = APIRouter(prefix="/api/v1/tasks", tags=["tasks"])


def _to_response(t) -> TaskResponse:
    return TaskResponse(
        id=t.id, title=t.title, description=t.description,
        task_type=t.task_type, reference_type=t.reference_type,
        reference_id=t.reference_id, assigned_to=t.assigned_to,
        assigned_by=t.assigned_by, priority=t.priority, status=t.status,
        due_date=t.due_date, completed_at=t.completed_at,
        comments=t.comments or [], created_at=t.created_at,
    )


@router.post("/", response_model=TaskResponse, status_code=201)
async def create_task(
    request: TaskCreate,
    db: Session = Depends(get_db),
    api_key: str = Depends(require_api_key),
):
    task = TaskRepository.create(db, **request.model_dump())
    return _to_response(task)


@router.get("/", response_model=list[TaskResponse])
async def list_tasks(
    assigned_to: str | None = Query(None),
    status: str | None = Query(None),
    task_type: str | None = Query(None),
    db: Session = Depends(get_db),
    api_key: str = Depends(require_api_key),
):
    tasks = TaskRepository.list_tasks(db, assigned_to=assigned_to, status=status, task_type=task_type)
    return [_to_response(t) for t in tasks]


@router.get("/dashboard")
async def task_dashboard(
    db: Session = Depends(get_db),
    api_key: str = Depends(require_api_key),
):
    return TaskRepository.get_dashboard(db)


@router.get("/{task_id}", response_model=TaskResponse)
async def get_task(
    task_id: str,
    db: Session = Depends(get_db),
    api_key: str = Depends(require_api_key),
):
    task = TaskRepository.get(db, task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")
    return _to_response(task)


@router.put("/{task_id}", response_model=TaskResponse)
async def update_task(
    task_id: str,
    request: TaskUpdate,
    db: Session = Depends(get_db),
    api_key: str = Depends(require_api_key),
):
    updates = request.model_dump(exclude_none=True)
    try:
        task = TaskRepository.update(db, task_id, updates)
    except ValueError:
        raise HTTPException(status_code=404, detail="Task not found")
    return _to_response(task)


@router.post("/{task_id}/comments", response_model=TaskResponse)
async def add_comment(
    task_id: str,
    request: TaskCommentCreate,
    db: Session = Depends(get_db),
    api_key: str = Depends(require_api_key),
):
    task = TaskRepository.get(db, task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")
    comments = list(task.comments or [])
    from datetime import UTC, datetime
    comments.append({
        "author": request.author,
        "content": request.content,
        "timestamp": datetime.now(UTC).isoformat(),
    })
    TaskRepository.update(db, task_id, {"comments": comments})
    task = TaskRepository.get(db, task_id)
    return _to_response(task)

"""Saved searches for the SIEM-style Log Explorer."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from ...database import get_db
from ...models import SavedSearch
from ...schemas import SavedSearchIn
from ...security import client_ip, require_analyst, require_viewer
from ...services.audit import log_action

router = APIRouter(tags=["Saved Searches"])


def _out(row: SavedSearch) -> dict:
    return {
        "id": row.id,
        "name": row.name,
        "owner": row.owner,
        "query_text": row.query_text,
        "filters": row.filters or {},
        "is_shared": row.is_shared,
        "created_at": row.created_at.isoformat() + "Z",
        "updated_at": row.updated_at.isoformat() + "Z",
    }


@router.get("/searches")
def list_searches(db: Session = Depends(get_db), user=Depends(require_viewer)) -> dict:
    rows = db.scalars(
        select(SavedSearch).where(
            (SavedSearch.owner == user.username) | (SavedSearch.is_shared.is_(True))
        ).order_by(SavedSearch.name)
    ).all()
    return {"total": len(rows), "items": [_out(row) for row in rows]}


@router.post("/searches", status_code=201)
def create_search(
    payload: SavedSearchIn,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(require_analyst),
) -> dict:
    if db.scalar(
        select(SavedSearch).where(SavedSearch.owner == user.username, SavedSearch.name == payload.name)
    ):
        raise HTTPException(status_code=409, detail="A saved search with this name already exists")
    row = SavedSearch(
        name=payload.name,
        owner=user.username,
        query_text=payload.query_text,
        filters=payload.filters,
        is_shared=payload.is_shared,
    )
    db.add(row)
    log_action(
        db, user.username, "saved_search_created", actor_role=user.role,
        target_type="saved_search", target_id=payload.name, ip_address=client_ip(request),
    )
    db.commit()
    db.refresh(row)
    return _out(row)


@router.delete("/searches/{search_id}")
def delete_search(
    search_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(require_analyst),
) -> dict:
    row = db.get(SavedSearch, search_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Saved search not found")
    if row.owner != user.username and user.role != "admin":
        raise HTTPException(status_code=403, detail="Only the owner or an admin can delete this search")
    log_action(
        db, user.username, "saved_search_deleted", actor_role=user.role,
        target_type="saved_search", target_id=row.name, ip_address=client_ip(request),
    )
    db.delete(row)
    db.commit()
    return {"deleted": search_id}

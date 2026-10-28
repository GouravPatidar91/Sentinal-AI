from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from backend.app.models.database import get_db
from backend.app.models.models import DetectionRule
from backend.app.schemas.schemas import RuleResponse, RuleUpdate
from backend.app.api.auth import get_current_user, get_current_admin

router = APIRouter(prefix="/rules", tags=["Rules"])

@router.get("/", response_model=List[RuleResponse])
def list_rules(
    db: Session = Depends(get_db)
):
    """Lists all detection rules in the system."""
    return db.query(DetectionRule).all()

@router.get("/{rule_id}", response_model=RuleResponse)
def get_rule(
    rule_id: int,
    db: Session = Depends(get_db)
):
    """Retrieves details of a specific detection rule."""
    rule = db.query(DetectionRule).filter(DetectionRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return rule

@router.put("/{rule_id}", response_model=RuleResponse)
def update_rule(
    rule_id: int,
    rule_in: RuleUpdate,
    db: Session = Depends(get_db),
    current_admin = Depends(get_current_admin)
):
    """
    Updates a detection rule (e.g. toggles is_enabled, adjusts severity).
    Restricted to Admin users only.
    """
    rule = db.query(DetectionRule).filter(DetectionRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
        
    update_data = rule_in.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(rule, field, value)
        
    db.commit()
    db.refresh(rule)
    return rule

import datetime
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List, Optional
from backend.app.models.database import get_db
from backend.app.models.models import SOARAction, Incident, User
from backend.app.schemas.schemas import SOARActionCreate, SOARActionResponse
from backend.app.api.auth import get_current_user
from backend.app.services.websocket import manager

router = APIRouter(prefix="/soar", tags=["SOAR Remediation"])

@router.post("/actions", response_model=SOARActionResponse)
async def create_soar_action(
    action_in: SOARActionCreate,
    auto_approve: bool = False,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Creates a new pending or auto-approved SOAR containment action."""
    # Determine initial status
    is_immediate = auto_approve or any(k in (action_in.description or "").lower() for k in ["quick", "one-click", "prevent", "stop attack"])
    initial_status = "APPROVED" if is_immediate else "PENDING"

    action = SOARAction(
        incident_id=action_in.incident_id,
        action_type=action_in.action_type.upper(),
        target_host=action_in.target_host or "web-server-prod",
        payload=action_in.payload,
        description=action_in.description,
        status=initial_status,
        executed_by_id=current_user.id if current_user else None,
        executed_at=datetime.datetime.utcnow() if is_immediate else None
    )
    db.add(action)
    db.commit()
    db.refresh(action)

    print(f"\n[SOAR DISPATCH] Action #{action.id}: {action.action_type} on host '{action.target_host}' (Status: {action.status}) -> Payload: {action.payload}")

    if is_immediate:
        # Broadcast command dispatch to live WebSocket subscribers / agents immediately
        await manager.broadcast({
            "type": "SOAR_COMMAND",
            "action": {
                "id": action.id,
                "incident_id": action.incident_id,
                "action_type": action.action_type,
                "target_host": action.target_host,
                "payload": action.payload,
                "description": action.description,
                "status": action.status
            }
        })

    return action

@router.get("/actions", response_model=List[SOARActionResponse])
def list_soar_actions(
    incident_id: Optional[int] = None,
    target_host: Optional[str] = None,
    status_filter: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Lists SOAR containment actions with optional filtering."""
    query = db.query(SOARAction)
    if incident_id:
        query = query.filter(SOARAction.incident_id == incident_id)
    if target_host:
        query = query.filter(SOARAction.target_host == target_host)
    if status_filter:
        query = query.filter(SOARAction.status == status_filter.upper())
    return query.order_by(SOARAction.created_at.desc()).all()

@router.post("/approve/{action_id}", response_model=SOARActionResponse)
async def approve_soar_action(
    action_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Approves a SOAR containment action and dispatches command payload
    to the target endpoint agent via WebSocket / polling stream.
    """
    action = db.query(SOARAction).filter(SOARAction.id == action_id).first()
    if not action:
        raise HTTPException(status_code=404, detail="SOAR Action not found")
        
    action.status = "APPROVED"
    action.executed_by_id = current_user.id
    action.executed_at = datetime.datetime.utcnow()
    db.commit()
    db.refresh(action)

    # Broadcast command dispatch to live WebSocket subscribers / agents
    await manager.broadcast({
        "type": "SOAR_COMMAND",
        "action": {
            "id": action.id,
            "incident_id": action.incident_id,
            "action_type": action.action_type,
            "target_host": action.target_host,
            "payload": action.payload,
            "description": action.description,
            "status": action.status
        }
    })

    return action

@router.post("/report_execution/{action_id}", response_model=SOARActionResponse)
async def report_execution_result(
    action_id: int,
    status_result: str,
    output: str = "",
    db: Session = Depends(get_db)
):
    """
    Called by the SOC agent after executing the command locally.
    Updates the action status to EXECUTED or FAILED.
    """
    action = db.query(SOARAction).filter(SOARAction.id == action_id).first()
    if not action:
        raise HTTPException(status_code=404, detail="SOAR Action not found")
        
    action.status = status_result.upper()  # EXECUTED or FAILED
    action.output = output
    if not action.executed_at:
        action.executed_at = datetime.datetime.utcnow()
    db.commit()
    db.refresh(action)

    # Update incident status if contained
    if action.incident_id and action.status == "EXECUTED":
        inc = db.query(Incident).filter(Incident.id == action.incident_id).first()
        if inc and inc.status in ["New", "Investigating"]:
            inc.status = "Contained"
            db.commit()

    # Broadcast update
    await manager.broadcast({
        "type": "SOAR_UPDATE",
        "action_id": action.id,
        "status": action.status,
        "output": action.output
    })

    return action

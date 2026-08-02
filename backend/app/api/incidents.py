from fastapi import APIRouter, Depends, HTTPException, status, Response
from sqlalchemy.orm import Session
from typing import List, Optional
from backend.app.models.database import get_db
from backend.app.models.models import Incident, User
from backend.app.schemas.schemas import IncidentResponse, IncidentDetailResponse, IncidentUpdate
from backend.app.api.auth import get_current_user
from backend.app.services.ai import ai_investigator
from backend.app.services.pdf import generate_incident_pdf
from backend.app.services.websocket import manager

router = APIRouter(prefix="/incidents", tags=["Incidents"])

@router.get("/", response_model=List[IncidentResponse])
def list_incidents(
    status_filter: Optional[str] = None,
    severity_filter: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Lists security incidents, optional filtering by status and severity."""
    query = db.query(Incident)
    if status_filter:
        query = query.filter(Incident.status == status_filter)
    if severity_filter:
        query = query.filter(Incident.severity == severity_filter.upper())
        
    return query.order_by(Incident.created_at.desc()).all()

@router.get("/{incident_id}", response_model=IncidentDetailResponse)
def get_incident(
    incident_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Retrieves full details of a specific incident, including timeline events."""
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident

@router.put("/{incident_id}", response_model=IncidentResponse)
async def update_incident(
    incident_id: int,
    incident_in: IncidentUpdate,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Updates an incident's status or assigned analyst."""
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
        
    update_data = incident_in.model_dump(exclude_unset=True)
    
    # Verify assignee if updating analyst
    if "assigned_to_id" in update_data and update_data["assigned_to_id"] is not None:
        user_exists = db.query(User).filter(User.id == update_data["assigned_to_id"]).first()
        if not user_exists:
            raise HTTPException(status_code=400, detail="Assigned user does not exist")
            
    for field, value in update_data.items():
        setattr(incident, field, value)
        
    db.commit()
    db.refresh(incident)
    
    # Broadcast status update to live dashboard
    await manager.broadcast({
        "type": "INCIDENT_UPDATE",
        "incident": {
            "id": incident.id,
            "title": incident.title,
            "severity": incident.severity,
            "status": incident.status,
            "risk_score": incident.risk_score,
            "anomaly_score": incident.anomaly_score,
            "created_at": incident.created_at.isoformat()
        }
    })
    
    return incident

@router.post("/{incident_id}/investigate", response_model=IncidentDetailResponse)
async def run_ai_investigation(
    incident_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Triggers the AI Incident Investigation and returns the report."""
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
        
    # Trigger AI Investigation (Gemini / OpenAI / Ollama / Fallback)
    report_json_str = await ai_investigator.investigate(incident)
    
    # Save the generated report
    incident.ai_report = report_json_str
    
    # Escalate status to Investigating if it was New
    if incident.status == "New":
        incident.status = "Investigating"
        
    db.commit()
    db.refresh(incident)
    
    # Broadcast update
    await manager.broadcast({
        "type": "INCIDENT_INVESTIGATED",
        "incident_id": incident.id,
        "status": incident.status
    })
    
    return incident

@router.get("/{incident_id}/pdf")
def export_incident_pdf(
    incident_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Generates a downloadable PDF report for this incident."""
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
        
    pdf_content = generate_incident_pdf(incident)
    
    headers = {
        "Content-Disposition": f"attachment; filename=incident_INC_{incident_id}_report.pdf"
    }
    return Response(content=pdf_content, media_type="application/pdf", headers=headers)

import datetime
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from backend.app.models.database import get_db
from backend.app.models.models import LogEntry, DetectionRule, Incident, IncidentEvent
from backend.app.schemas.schemas import LogCreate, LogResponse
from backend.app.services.normalization import normalize_log
from backend.app.services.detection import evaluate_log_rules
from backend.app.services.anomaly import anomaly_detector
from backend.app.services.correlation import correlate_event
from backend.app.services.websocket import manager

router = APIRouter(prefix="/logs", tags=["Logs"])

@router.post("/ingest")
async def ingest_log(payload: LogCreate, db: Session = Depends(get_db)):
    """
    Ingests a log entry, normalizes it, detects threats, runs anomaly scoring,
    performs event correlation, and broadcasts live updates via WebSockets.
    """
    try:
        # 1. Normalize Log
        # Use provided values, applying default parser rules where fields are missing
        normalized = normalize_log(payload.raw_log, payload.source)
        
        # Override with any explicit fields sent by the agent if present
        if payload.host and payload.host != "unknown-host":
            normalized.host = payload.host
        if payload.username:
            normalized.username = payload.username
        if payload.src_ip:
            normalized.src_ip = payload.src_ip
        if payload.dst_ip:
            normalized.dst_ip = payload.dst_ip
        if payload.process:
            normalized.process = payload.process
        if payload.severity and payload.severity != "INFO":
            normalized.severity = payload.severity
            
        # 2. Save LogEntry to Database
        log_entry = LogEntry(
            timestamp=normalized.timestamp or datetime.datetime.utcnow(),
            host=normalized.host,
            source=normalized.source,
            log_type=normalized.log_type,
            severity=normalized.severity,
            username=normalized.username,
            src_ip=normalized.src_ip,
            dst_ip=normalized.dst_ip,
            process=normalized.process,
            message=normalized.message,
            raw_log=normalized.raw_log
        )
        db.add(log_entry)
        db.flush()  # Populates log_entry.id
        
        # 3. ML Anomaly Detection Scoring
        anomaly_score = anomaly_detector.predict_anomaly(db, log_entry)
        
        # 4. Evaluate Detection Rules
        matched_rules = evaluate_log_rules(db, log_entry)
        
        # 5. Core Correlation & Incident Handling
        incident = None
        if matched_rules:
            # Correlate this log and rules to an incident
            incident = correlate_event(db, log_entry, matched_rules)
            
            # If an incident was created/updated, associate its anomaly score
            if incident:
                # Update incident anomaly score (max of current incident score and new log score)
                incident.anomaly_score = max(incident.anomaly_score, anomaly_score)
                db.commit()
                
        # Commit database transaction
        db.commit()
        db.refresh(log_entry)
        
        # 6. Real-Time Broadcast via WebSockets
        broadcast_msg = {
            "type": "NEW_LOG",
            "log": {
                "id": log_entry.id,
                "timestamp": log_entry.timestamp.isoformat(),
                "host": log_entry.host,
                "source": log_entry.source,
                "log_type": log_entry.log_type,
                "severity": log_entry.severity,
                "username": log_entry.username,
                "src_ip": log_entry.src_ip,
                "dst_ip": log_entry.dst_ip,
                "process": log_entry.process,
                "message": log_entry.message,
                "anomaly_score": anomaly_score
            }
        }
        
        if matched_rules:
            broadcast_msg["alert"] = {
                "rule_name": matched_rules[0].name,
                "description": matched_rules[0].description,
                "severity": matched_rules[0].severity,
                "tactic": matched_rules[0].tactic,
                "technique": matched_rules[0].technique
            }
            
        if incident:
            broadcast_msg["incident"] = {
                "id": incident.id,
                "title": incident.title,
                "severity": incident.severity,
                "status": incident.status,
                "risk_score": incident.risk_score,
                "anomaly_score": incident.anomaly_score,
                "created_at": incident.created_at.isoformat()
            }
            
        await manager.broadcast(broadcast_msg)
        
        return {
            "status": "success",
            "log_id": log_entry.id,
            "rules_matched": [r.name for r in matched_rules],
            "incident_id": incident.id if incident else None,
            "anomaly_score": anomaly_score
        }
        
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Log ingestion failed: {str(e)}")

@router.get("/search", response_model=List[LogResponse])
def search_logs(
    username: Optional[str] = None,
    host: Optional[str] = None,
    ip: Optional[str] = None,
    severity: Optional[str] = None,
    source: Optional[str] = None,
    log_type: Optional[str] = None,
    limit: int = Query(100, ge=1, le=1000),
    db: Session = Depends(get_db)
):
    """
    Search and filter normalized log entries.
    """
    query = db.query(LogEntry)
    
    if username:
        query = query.filter(LogEntry.username.like(f"%{username}%"))
    if host:
        query = query.filter(LogEntry.host.like(f"%{host}%"))
    if ip:
        query = query.filter((LogEntry.src_ip == ip) | (LogEntry.dst_ip == ip))
    if severity:
        query = query.filter(LogEntry.severity == severity.upper())
    if source:
        query = query.filter(LogEntry.source == source)
    if log_type:
        query = query.filter(LogEntry.log_type == log_type)
        
    return query.order_by(LogEntry.timestamp.desc()).limit(limit).all()

@router.get("/stats")
def get_log_stats(db: Session = Depends(get_db)):
    """
    Returns quick stats for logs (count by severity, count by source).
    """
    total_logs = db.query(LogEntry).count()
    
    # Severity counts
    severities = ["INFO", "WARNING", "ERROR", "CRITICAL"]
    severity_counts = {sev: db.query(LogEntry).filter(LogEntry.severity == sev).count() for sev in severities}
    
    # Source counts
    sources = ["Windows", "Linux", "Apache", "Firewall", "Simulator"]
    source_counts = {src: db.query(LogEntry).filter(LogEntry.source == src).count() for src in sources}
    
    return {
        "total_logs": total_logs,
        "by_severity": severity_counts,
        "by_source": source_counts
    }

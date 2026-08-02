import datetime
from typing import List, Optional
from sqlalchemy.orm import Session
from backend.app.models.models import Incident, IncidentEvent, LogEntry, DetectionRule
from backend.app.services.risk import calculate_risk_score

CORRELATION_WINDOW_MINUTES = 15

def correlate_event(db: Session, log: LogEntry, matched_rules: List[DetectionRule]) -> Optional[Incident]:
    """
    Correlates a newly logged event with existing active incidents or creates a new incident.
    """
    if not matched_rules:
        return None
        
    # We will pick the most severe matched rule to start with
    primary_rule = max(matched_rules, key=lambda r: {"CRITICAL": 4, "HIGH": 3, "WARNING": 2, "INFO": 1}.get(r.severity, 0))
    
    # Calculate time window for correlation
    time_limit = datetime.datetime.utcnow() - datetime.timedelta(minutes=CORRELATION_WINDOW_MINUTES)
    
    # Search for an existing "active" incident associated with this Host, IP, or Username in the last 15 mins
    from sqlalchemy import or_
    
    # Build list of potential correlation hooks
    correlation_filters = [Incident.title.contains(log.host)]
    if log.src_ip:
        correlation_filters.append(Incident.description.contains(log.src_ip))
    if log.username:
        correlation_filters.append(Incident.description.contains(log.username))

    existing_incident = db.query(Incident).filter(
        Incident.status.in_(["New", "Investigating"]),
        Incident.created_at >= time_limit
    ).filter(
        or_(*correlation_filters)
    ).order_by(Incident.created_at.desc()).first()
    
    if existing_incident:
        # Append to existing incident
        # Calculate new order index
        current_event_count = db.query(IncidentEvent).filter(IncidentEvent.incident_id == existing_incident.id).count()
        
        # Create IncidentEvent relation
        new_event = IncidentEvent(
            incident_id=existing_incident.id,
            log_entry_id=log.id,
            rule_id=primary_rule.id,
            timestamp=log.timestamp,
            description=f"Triggered rule '{primary_rule.name}': {primary_rule.description}",
            order_index=current_event_count + 1
        )
        db.add(new_event)
        db.flush() # get ID
        
        # Update incident metadata
        existing_incident.updated_at = datetime.datetime.utcnow()
        
        # Escalate title/severity if necessary
        # Check all rules associated with this incident
        all_events = db.query(IncidentEvent).filter(IncidentEvent.incident_id == existing_incident.id).all()
        rules_triggered = [e.rule for e in all_events if e.rule]
        
        # If we have multiple stages, escalate
        unique_tactics = {r.tactic for r in rules_triggered}
        unique_types = {r.rule_type for r in rules_triggered}
        
        # Update Title to show multi-stage correlation
        if len(unique_tactics) >= 2:
            existing_incident.title = f"Multi-Stage Cyber Attack Chain Detected on {log.host.upper()}"
            existing_incident.severity = "CRITICAL"
        elif len(all_events) >= 5:
            existing_incident.title = f"Persistent Alert Sequence on {log.host.upper()}"
            existing_incident.severity = "HIGH"
            
        # Recalculate Risk Score
        existing_incident.risk_score = calculate_risk_score(
            rules_triggered=rules_triggered,
            anomaly_score=existing_incident.anomaly_score,
            host_importance=1.5 if "server" in log.host.lower() or "dc" in log.host.lower() else 1.0,
            event_count=len(all_events)
        )
        
        db.commit()
        return existing_incident
        
    else:
        # Create a NEW incident
        # Check severity threshold - We create incidents for WARNING, HIGH, CRITICAL rules
        rule_severity = primary_rule.severity.upper()
        if rule_severity not in ["WARNING", "HIGH", "CRITICAL"]:
            # Check if there are multiple failed logins recently that haven't been correlated yet
            # e.g., if there were 3+ failed logins in the last 5 mins, escalate to brute force incident
            recent_fails = db.query(LogEntry).filter(
                LogEntry.timestamp >= (datetime.datetime.utcnow() - datetime.timedelta(minutes=5)),
                LogEntry.host == log.host,
                LogEntry.process.in_(["WinEventLog:4625", "sshd"]),
                LogEntry.severity == "WARNING"
            ).count()
            
            if recent_fails < 3:
                # Do not escalate a single low-severity log to an Incident
                return None
                
            # If we have 3+ fails, escalate and create brute force incident
            incident_title = f"Brute Force Authentication Attempt Detected on {log.host.upper()}"
            incident_desc = f"Detected {recent_fails} failed login attempts on host '{log.host}' from IP '{log.src_ip or 'unknown'}'. This matches brute-force credential guessing."
            severity = "HIGH"
        else:
            incident_title = f"Threat Detected: {primary_rule.name} on {log.host.upper()}"
            incident_desc = f"Security rule '{primary_rule.name}' triggered on host '{log.host}'. Message: {log.message}."
            if log.src_ip:
                incident_desc += f" Attacking IP: {log.src_ip}."
            if log.username:
                incident_desc += f" Target User: {log.username}."
            severity = primary_rule.severity
            
        new_incident = Incident(
            title=incident_title,
            description=incident_desc,
            severity=severity,
            status="New",
            risk_score=0, # Will calculate next
            anomaly_score=0.0,
            created_at=log.timestamp,
            updated_at=log.timestamp
        )
        db.add(new_incident)
        db.flush() # get ID
        
        # Link log to incident
        new_event = IncidentEvent(
            incident_id=new_incident.id,
            log_entry_id=log.id,
            rule_id=primary_rule.id,
            timestamp=log.timestamp,
            description=f"Incident Trigger Alert: {primary_rule.description}",
            order_index=1
        )
        db.add(new_event)
        
        # Calculate Risk Score
        new_incident.risk_score = calculate_risk_score(
            rules_triggered=[primary_rule],
            anomaly_score=0.0,
            host_importance=1.5 if "server" in log.host.lower() or "dc" in log.host.lower() else 1.0,
            event_count=1
        )
        
        db.commit()
        return new_incident

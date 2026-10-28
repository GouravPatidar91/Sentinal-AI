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
    
    # Check if this rule is an authentication/credential failure rule
    is_credential_failure = (
        primary_rule.technique in ["T1110", "T1078"] or
        primary_rule.tactic == "Credential Access" or
        "bruteforce" in primary_rule.name.lower() or
        "failure" in primary_rule.name.lower() or
        (log.process and any(p in log.process for p in ["4625", "sshd"]))
    )

    # Build list of correlation hooks
    # For credential failures, correlate strictly by target host and username to avoid private LAN NAT bleeding
    if is_credential_failure:
        correlation_filters = [Incident.title.contains(log.host)]
    else:
        correlation_filters = [Incident.title.contains(log.host)]
        # Only correlate by IP for public/external attacker IPs (not private LAN subnets)
        if log.src_ip and not log.src_ip.startswith(("127.", "192.168.", "10.")):
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
        # Distinguish between high-certainty single events (SQLi, command injection)
        # and authentication failure events that require multi-factor thresholding.
        rule_severity = primary_rule.severity.upper()
        
        # Check if rule is an authentication/credential failure rule
        is_credential_failure = (
            primary_rule.technique in ["T1110", "T1078"] or
            primary_rule.tactic == "Credential Access" or
            "bruteforce" in primary_rule.name.lower() or
            "failure" in primary_rule.name.lower() or
            (log.process and any(p in log.process for p in ["4625", "sshd"]))
        )
        
        if is_credential_failure:
            # Multi-factor authentication defense:
            # Distinguish benign human error (e.g. forgot password, 1-2 typos) from brute-force attack.
            # Factor 1: Sliding Time Window (5 minutes)
            # Factor 2: Frequency Threshold (>= 3 attempts)
            # Factor 3: Host & User correlation
            fail_query = db.query(LogEntry).filter(
                LogEntry.timestamp >= (datetime.datetime.utcnow() - datetime.timedelta(minutes=5)),
                LogEntry.host == log.host,
                LogEntry.severity.in_(["WARNING", "HIGH", "ERROR"])
            )
            if log.username:
                fail_query = fail_query.filter(LogEntry.username == log.username)
            recent_fails = fail_query.count()
            
            if recent_fails < 3:
                # Do not escalate 1 or 2 isolated failed attempts to an Incident.
                # The log remains stored in DB for auditing, but avoids false-positive dashboard alarms.
                return None
                
            # If 3+ failed logins occur within the 5-minute window, escalate to Brute Force incident
            incident_title = f"Brute Force Authentication Attempt Detected on {log.host.upper()}"
            incident_desc = f"Detected {recent_fails} failed login attempts on host '{log.host}' within 5 minutes from IP '{log.src_ip or 'unknown'}'. Exceeds threshold (>=3), indicating automated credential guessing."
            severity = "HIGH"
        elif rule_severity in ["WARNING", "HIGH", "CRITICAL"]:
            incident_title = f"Threat Detected: {primary_rule.name} on {log.host.upper()}"
            incident_desc = f"Security rule '{primary_rule.name}' triggered on host '{log.host}'. Message: {log.message}."
            if log.src_ip:
                incident_desc += f" Attacking IP: {log.src_ip}."
            if log.username:
                incident_desc += f" Target User: {log.username}."
            severity = primary_rule.severity
        else:
            # Low or Info level rules do not spawn new incidents
            return None
            
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

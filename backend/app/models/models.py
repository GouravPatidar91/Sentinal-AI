import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Float, ForeignKey, Text
from sqlalchemy.orm import relationship
from backend.app.models.database import Base

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(String, default="analyst")  # admin, analyst
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    # Relationships
    assigned_incidents = relationship("Incident", back_populates="assigned_analyst")

class LogEntry(Base):
    __tablename__ = "log_entries"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, index=True, nullable=False)
    host = Column(String, index=True, nullable=False)
    source = Column(String, index=True, nullable=False)  # Windows, Linux, Apache, Firewall, Simulator
    log_type = Column(String, index=True, nullable=False)  # Security, Auth, System, Web, Traffic
    severity = Column(String, index=True, nullable=False)  # DEBUG, INFO, WARNING, ERROR, CRITICAL
    username = Column(String, index=True, nullable=True)
    src_ip = Column(String, index=True, nullable=True)
    dst_ip = Column(String, index=True, nullable=True)
    process = Column(String, index=True, nullable=True)
    message = Column(Text, nullable=False)
    raw_log = Column(Text, nullable=False)
    normalized_at = Column(DateTime, default=datetime.datetime.utcnow)

    # Relationships
    incident_events = relationship("IncidentEvent", back_populates="log_entry", cascade="all, delete-orphan")

class DetectionRule(Base):
    __tablename__ = "detection_rules"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True, nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String, nullable=False)  # Low, Medium, High, Critical
    tactic = Column(String, nullable=False)  # MITRE ATT&CK Tactic
    technique = Column(String, nullable=False)  # MITRE ATT&CK Technique ID
    rule_type = Column(String, nullable=False)  # Windows, Linux, Apache, Firewall, Correlation, Anomaly
    condition_pattern = Column(Text, nullable=False)  # JSON or simple pattern for matching
    is_enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    # Relationships
    incident_events = relationship("IncidentEvent", back_populates="rule")

class Incident(Base):
    __tablename__ = "incidents"
    
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, index=True, nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String, index=True, nullable=False)  # Low, Medium, High, Critical
    status = Column(String, index=True, default="New")  # New, Investigating, Contained, Resolved, Closed
    risk_score = Column(Integer, default=0, index=True)  # 0 - 100
    anomaly_score = Column(Float, default=0.0)
    assigned_to_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
    ai_report = Column(Text, nullable=True)  # Markdown text containing AI Investigation

    # Relationships
    assigned_analyst = relationship("User", back_populates="assigned_incidents")
    events = relationship("IncidentEvent", back_populates="incident", cascade="all, delete-orphan", order_by="IncidentEvent.order_index")
    soar_actions = relationship("SOARAction", back_populates="incident", cascade="all, delete-orphan")

class IncidentEvent(Base):
    __tablename__ = "incident_events"
    
    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=False)
    log_entry_id = Column(Integer, ForeignKey("log_entries.id"), nullable=False)
    rule_id = Column(Integer, ForeignKey("detection_rules.id"), nullable=True)
    timestamp = Column(DateTime, nullable=False)
    description = Column(Text, nullable=False)
    order_index = Column(Integer, nullable=False)

    # Relationships
    incident = relationship("Incident", back_populates="events")
    log_entry = relationship("LogEntry", back_populates="incident_events")
    rule = relationship("DetectionRule", back_populates="incident_events")

class SOARAction(Base):
    __tablename__ = "soar_actions"
    
    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=True)
    action_type = Column(String, index=True, nullable=False)  # KILL_PROCESS, BLOCK_IP, QUARANTINE_INTERFACE, DISABLE_USER
    target_host = Column(String, index=True, nullable=False)
    payload = Column(String, nullable=False)  # PID, IP address, Interface name, Username
    description = Column(Text, nullable=False)
    status = Column(String, index=True, default="PENDING")  # PENDING, APPROVED, EXECUTED, FAILED, REJECTED
    executed_by_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    output = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, index=True)
    executed_at = Column(DateTime, nullable=True)

    # Relationships
    incident = relationship("Incident", back_populates="soar_actions")
    executed_by = relationship("User")


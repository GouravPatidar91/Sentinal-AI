from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime

# ==========================================
# AUTH / USER SCHEMAS
# ==========================================
class UserBase(BaseModel):
    username: str

class UserCreate(UserBase):
    password: str
    role: Optional[str] = "analyst"  # admin or analyst

class UserResponse(UserBase):
    id: int
    role: str
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str
    role: str
    username: str

class TokenData(BaseModel):
    username: Optional[str] = None
    role: Optional[str] = None

# ==========================================
# LOG SCHEMAS
# ==========================================
class LogCreate(BaseModel):
    timestamp: Optional[datetime] = None  # Agent can supply it, otherwise server generates it
    host: str
    source: str  # Windows, Linux, Apache, Firewall, Simulator
    log_type: str  # Security, Auth, System, Web, Traffic
    severity: str  # DEBUG, INFO, WARNING, ERROR, CRITICAL
    username: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    process: Optional[str] = None
    message: str
    raw_log: str

class LogResponse(BaseModel):
    id: int
    timestamp: datetime
    host: str
    source: str
    log_type: str
    severity: str
    username: Optional[str]
    src_ip: Optional[str]
    dst_ip: Optional[str]
    process: Optional[str]
    message: str
    raw_log: str
    normalized_at: datetime

    class Config:
        from_attributes = True

# ==========================================
# RULE SCHEMAS
# ==========================================
class RuleBase(BaseModel):
    name: str
    description: str
    severity: str  # Low, Medium, High, Critical
    tactic: str  # MITRE ATT&CK Tactic
    technique: str  # MITRE ATT&CK Technique ID
    rule_type: str  # Windows, Linux, Apache, Firewall, Correlation, Anomaly
    condition_pattern: str  # JSON or simple pattern for matching

class RuleCreate(RuleBase):
    pass

class RuleUpdate(BaseModel):
    description: Optional[str] = None
    severity: Optional[str] = None
    tactic: Optional[str] = None
    technique: Optional[str] = None
    condition_pattern: Optional[str] = None
    is_enabled: Optional[bool] = None

class RuleResponse(RuleBase):
    id: int
    is_enabled: bool
    created_at: datetime

    class Config:
        from_attributes = True

# ==========================================
# INCIDENT SCHEMAS
# ==========================================
class IncidentEventResponse(BaseModel):
    id: int
    incident_id: int
    log_entry_id: int
    timestamp: datetime
    description: str
    order_index: int
    rule: Optional[RuleResponse] = None

    class Config:
        from_attributes = True

class IncidentResponse(BaseModel):
    id: int
    title: str
    description: str
    severity: str
    status: str
    risk_score: int
    anomaly_score: float
    assigned_to_id: Optional[int]
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

class IncidentUpdate(BaseModel):
    status: Optional[str] = None
    assigned_to_id: Optional[int] = None
    severity: Optional[str] = None
    risk_score: Optional[int] = None

class IncidentDetailResponse(IncidentResponse):
    events: List[IncidentEventResponse] = []
    ai_report: Optional[str] = None

    class Config:
        from_attributes = True

# ==========================================
# SIMULATION & SEARCH
# ==========================================
class SimulationRequest(BaseModel):
    attack_type: str  # brute_force, sql_injection, xss, port_scan, ransomware, privilege_escalation, insider_threat, malware
    host: Optional[str] = "host-corp-win10"
    target_ip: Optional[str] = "192.168.10.15"
    attacker_ip: Optional[str] = "185.220.101.44"

class SearchQuery(BaseModel):
    username: Optional[str] = None
    host: Optional[str] = None
    ip: Optional[str] = None
    date_from: Optional[datetime] = None
    date_to: Optional[datetime] = None
    mitre_technique: Optional[str] = None
    threat_type: Optional[str] = None
    severity: Optional[str] = None

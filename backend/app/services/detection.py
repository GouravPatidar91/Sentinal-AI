import json
import re
from typing import List, Tuple
from sqlalchemy.orm import Session
from backend.app.models.models import DetectionRule, LogEntry

def matches_rule(log: LogEntry, rule: DetectionRule) -> bool:
    """
    Evaluates if a LogEntry matches a DetectionRule based on its condition_pattern.
    condition_pattern is a JSON string describing the matching logic.
    Examples:
      {"type": "exact", "field": "process", "value": "WinEventLog:4625"}
      {"type": "regex", "field": "message", "pattern": "Failed password for"}
      {"type": "regex", "field": "message", "pattern": "(UNION SELECT|SELECT.*FROM)"}
    """
    if not rule.is_enabled:
        return False
        
    try:
        cond = json.loads(rule.condition_pattern)
        match_type = cond.get("type")
        field = cond.get("field")
        
        # Get the field value from log entry
        field_value = getattr(log, field, None)
        if field_value is None:
            return False
            
        field_value_str = str(field_value)
        
        if match_type == "exact":
            target_value = str(cond.get("value"))
            return field_value_str == target_value
            
        elif match_type == "contains":
            target_value = str(cond.get("value")).lower()
            return target_value in field_value_str.lower()
            
        elif match_type == "regex":
            pattern = cond.get("pattern")
            return bool(re.search(pattern, field_value_str, re.IGNORECASE))
            
    except Exception as e:
        # Avoid crashing the pipeline on malformed rules
        print(f"Error parsing/matching rule '{rule.name}' (ID: {rule.id}): {e}")
        
    return False

def evaluate_log_rules(db: Session, log: LogEntry) -> List[DetectionRule]:
    """
    Evaluates a single LogEntry against all enabled DetectionRules in the database.
    Returns a list of matched DetectionRules.
    """
    enabled_rules = db.query(DetectionRule).filter(DetectionRule.is_enabled == True).all()
    matched = []
    
    for rule in enabled_rules:
        if matches_rule(log, rule):
            matched.append(rule)
            
    return matched

def seed_default_rules(db: Session):
    """
    Seeds default SOC rules into the database if they don't already exist.
    """
    default_rules = [
        # ================= Windows Rules =================
        {
            "name": "Win-BruteForce",
            "description": "Detects Windows logon failure (Event 4625), potential credential brute-forcing.",
            "severity": "WARNING",
            "tactic": "Credential Access",
            "technique": "T1110",
            "rule_type": "Windows",
            "condition_pattern": json.dumps({"type": "exact", "field": "process", "value": "WinEventLog:4625"})
        },
        {
            "name": "Win-PrivilegeEscalation",
            "description": "Detects logon using administrative privileges (Event 4672), potential privilege escalation.",
            "severity": "HIGH",
            "tactic": "Privilege Escalation",
            "technique": "T1078",
            "rule_type": "Windows",
            "condition_pattern": json.dumps({"type": "exact", "field": "process", "value": "WinEventLog:4672"})
        },
        {
            "name": "Win-AuditPolicyChanged",
            "description": "Detects modification of audit policy settings (Event 4719), potential defense evasion.",
            "severity": "HIGH",
            "tactic": "Defense Evasion",
            "technique": "T1562.001",
            "rule_type": "Windows",
            "condition_pattern": json.dumps({"type": "exact", "field": "process", "value": "WinEventLog:4719"})
        },
        # ================= Linux Rules =================
        {
            "name": "Linux-SSH-Failure",
            "description": "Detects repeated SSH daemon connection failures.",
            "severity": "WARNING",
            "tactic": "Credential Access",
            "technique": "T1110",
            "rule_type": "Linux",
            "condition_pattern": json.dumps({"type": "regex", "field": "message", "pattern": "SSH login failed for user"})
        },
        {
            "name": "Linux-New-Sudoer",
            "description": "Detects use of sudo commands on Linux server.",
            "severity": "HIGH",
            "tactic": "Privilege Escalation",
            "technique": "T1078",
            "rule_type": "Linux",
            "condition_pattern": json.dumps({"type": "regex", "field": "message", "pattern": "Sudo executed: command="})
        },
        {
            "name": "Linux-Root-Login",
            "description": "Detects successful SSH root login.",
            "severity": "HIGH",
            "tactic": "Privilege Escalation",
            "technique": "T1078",
            "rule_type": "Linux",
            "condition_pattern": json.dumps({"type": "regex", "field": "message", "pattern": "login successful for user root"})
        },
        {
            "name": "Linux-New-Account",
            "description": "Detects creation of a new local user account on Linux.",
            "severity": "HIGH",
            "tactic": "Persistence",
            "technique": "T1136.001",
            "rule_type": "Linux",
            "condition_pattern": json.dumps({"type": "regex", "field": "message", "pattern": "New user account created:"})
        },
        # ================= Apache Rules =================
        {
            "name": "Apache-SQL-Injection",
            "description": "Detects web SQL injection attempts in Apache HTTP parameters.",
            "severity": "HIGH",
            "tactic": "Initial Access",
            "technique": "T1190",
            "rule_type": "Apache",
            "condition_pattern": json.dumps({"type": "regex", "field": "message", "pattern": "(UNION\\s+SELECT|SELECT.*FROM|UNION\\s+ALL\\s+SELECT|HAVING\\s+\\d|OR\\s+\\d+=\\d+|UNION\\s+char)"})
        },
        {
            "name": "Apache-Directory-Traversal",
            "description": "Detects directory traversal attempts in HTTP requests.",
            "severity": "HIGH",
            "tactic": "Discovery",
            "technique": "T1083",
            "rule_type": "Apache",
            "condition_pattern": json.dumps({"type": "regex", "field": "message", "pattern": "(\\.\\./|\\.\\.\\\\|/etc/passwd|win\\.ini|boot\\.ini)"})
        },
        {
            "name": "Apache-XSS",
            "description": "Detects Cross-Site Scripting (XSS) attack payloads.",
            "severity": "HIGH",
            "tactic": "Initial Access",
            "technique": "T1190",
            "rule_type": "Apache",
            "condition_pattern": json.dumps({"type": "regex", "field": "message", "pattern": "(<script>|javascript:|onerror\\s*=|onload\\s*=|alert\\()"})
        },
        {
            "name": "Apache-File-Inclusion",
            "description": "Detects Local/Remote File Inclusion (LFI/RFI) parameter checks.",
            "severity": "HIGH",
            "tactic": "Initial Access",
            "technique": "T1190",
            "rule_type": "Apache",
            "condition_pattern": json.dumps({"type": "regex", "field": "message", "pattern": "(\\?file=|\\?page=|\\?path=|\\?include=|php://filter|expect://)"})
        },
        {
            "name": "Apache-Command-Injection",
            "description": "Detects OS command injection attempts in URI parameters.",
            "severity": "CRITICAL",
            "tactic": "Execution",
            "technique": "T1203",
            "rule_type": "Apache",
            "condition_pattern": json.dumps({"type": "regex", "field": "message", "pattern": "(;\\s*whoami|;\\s*id|;\\s*uname|;\\s*cat\\s+/etc|&&\\s*whoami|\\|\\|\\s*whoami|;\\s*wget|;\\s*curl)"})
        },
        # ================= Firewall Rules =================
        {
            "name": "Firewall-Denied-Connection",
            "description": "Detects blocked packet connections.",
            "severity": "WARNING",
            "tactic": "Discovery",
            "technique": "T1046",
            "rule_type": "Firewall",
            "condition_pattern": json.dumps({"type": "regex", "field": "message", "pattern": "Firewall blocked packet"})
        },
        {
            "name": "Firewall-Large-Traffic",
            "description": "Detects bulk outbound traffic transfer indicating potential data exfiltration.",
            "severity": "HIGH",
            "tactic": "Exfiltration",
            "technique": "T1048",
            "rule_type": "Firewall",
            "condition_pattern": json.dumps({"type": "regex", "field": "message", "pattern": "LEN=(1[3-9]\\d{2}|[2-9]\\d{3})"}) # Len >= 1300
        },
        {
            "name": "Firewall-Suspicious-Country",
            "description": "Detects firewall traffic connections routing through known malicious IPs.",
            "severity": "HIGH",
            "tactic": "Command and Control",
            "technique": "T1090",
            "rule_type": "Firewall",
            "condition_pattern": json.dumps({"type": "regex", "field": "raw_log", "pattern": "(185\\.220\\.101\\.\\d+|203\\.0\\.113\\.\\d+)"})
        }
    ]
    
    for r in default_rules:
        # Check if already exists
        exists = db.query(DetectionRule).filter(DetectionRule.name == r["name"]).first()
        if not exists:
            new_rule = DetectionRule(**r)
            db.add(new_rule)
    
    db.commit()

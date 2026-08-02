import datetime
from typing import Dict, Any
from backend.app.services.parser import parse_log
from backend.app.schemas.schemas import LogCreate

def normalize_log(raw_log: str, source: str) -> LogCreate:
    """
    Parses a raw log, maps it to a common schema, sanitizes inputs, and returns a LogCreate schema.
    """
    parsed_data = parse_log(raw_log, source)
    
    # Extract parsed fields
    timestamp = parsed_data.get("timestamp") or datetime.datetime.utcnow()
    host = parsed_data.get("host") or "unknown-host"
    severity = parsed_data.get("severity") or "INFO"
    username = parsed_data.get("username")
    src_ip = parsed_data.get("src_ip")
    dst_ip = parsed_data.get("dst_ip")
    process = parsed_data.get("process")
    message = parsed_data.get("message") or raw_log
    
    # Host Sanitization
    host = host.strip("[],()").lower()
    if not host or host == "unknown-host":
        # Fallback host detection in raw string if parser missed it
        if "host-" in raw_log:
            host_extracted = raw_log.split("host-")[1].split()[0].strip("[],()\"':")
            host = f"host-{host_extracted}"
        else:
            host = "host-generic"
            
    # Message Sanitization (remove trailing carriage returns/newlines)
    message = message.strip()
    
    # Severity Sanitization
    severity = severity.upper()
    valid_severities = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
    if severity not in valid_severities:
        severity = "INFO"
        
    # Map sources and determine specific log_type
    src_lower = source.lower()
    if "windows" in src_lower:
        log_type = "Security"
    elif "linux" in src_lower:
        log_type = "Auth" if "auth" in raw_log or "sshd" in raw_log or "sudo" in raw_log else "System"
    elif "apache" in src_lower:
        log_type = "Web"
    elif "firewall" in src_lower:
        log_type = "Traffic"
    else:
        log_type = "Generic"

    # Construct the LogCreate schema
    return LogCreate(
        timestamp=timestamp,
        host=host,
        source=source,
        log_type=log_type,
        severity=severity,
        username=username,
        src_ip=src_ip,
        dst_ip=dst_ip,
        process=process,
        message=message,
        raw_log=raw_log
    )

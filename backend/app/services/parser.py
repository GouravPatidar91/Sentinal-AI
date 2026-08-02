import re
import datetime
from typing import Dict, Any, Optional

# Regular Expression Patterns
LINUX_SSH_FAIL = re.compile(r"Failed password for (invalid user )?(\S+) from (\S+) port \d+ ssh2")
LINUX_SSH_SUCCESS = re.compile(r"Accepted password for (\S+) from (\S+) port \d+ ssh2")
LINUX_SUDO = re.compile(r"sudo:\s+(\S+)\s+:\s+TTY=\S+\s+;\s+PWD=\S+\s+;\s+USER=(\S+)\s+;\s+COMMAND=(.+)")
LINUX_NEW_USER = re.compile(r"new user: name=(\S+)")

APACHE_ACCESS = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<time>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<path>[^\s?]+)(?:\?(?P<query>[^"]*))?\s+HTTP/[^"]+"\s+(?P<status>\d+)\s+(?P<size>\S+)'
)

FIREWALL_DENY = re.compile(
    r"FW_DENY:.*SRC=(?P<src>\S+).*DST=(?P<dst>\S+).*PROTO=(?P<proto>\S+).*DPT=(?P<dpt>\d+)"
)
FIREWALL_ALLOW = re.compile(
    r"FW_ALLOW:.*SRC=(?P<src>\S+).*DST=(?P<dst>\S+).*PROTO=(?P<proto>\S+).*DPT=(?P<dpt>\d+)"
)

def parse_log(raw_log: str, source: str) -> Dict[str, Any]:
    """
    Parses a raw log string based on its source type and returns extracted fields.
    """
    data = {
        "timestamp": datetime.datetime.utcnow(),
        "host": "unknown-host",
        "username": None,
        "src_ip": None,
        "dst_ip": None,
        "process": None,
        "message": raw_log,
        "severity": "INFO"
    }

    # Normalize source name (case-insensitive)
    src = source.lower()

    # ----------------------------------------------------
    # WINDOWS LOG PARSER
    # ----------------------------------------------------
    if "windows" in src:
        data["process"] = "Security"
        # Parse host if present
        host_match = re.search(r"TargetDomainName:\s*(\S+)", raw_log) or re.search(r"ComputerName:\s*(\S+)", raw_log)
        if host_match:
            data["host"] = host_match.group(1).strip(" ,;[]()")
        
        # Determine Event ID
        event_id_match = re.search(r"Event\s*ID:\s*(\d+)", raw_log, re.IGNORECASE) or re.search(r"EventID:\s*(\d+)", raw_log, re.IGNORECASE) or re.search(r"Event\s*(\d+)", raw_log, re.IGNORECASE)
        event_id = event_id_match.group(1) if event_id_match else None
        
        if event_id:
            data["process"] = f"WinEventLog:{event_id}"
            if event_id == "4625":
                data["severity"] = "WARNING"
                data["message"] = "Windows Failed Login Attempt"
            elif event_id == "4624":
                data["severity"] = "INFO"
                data["message"] = "Windows Successful Login"
            elif event_id == "4672":
                data["severity"] = "HIGH"
                data["message"] = "Windows Administrative Privilege Logon"
            elif event_id == "4719":
                data["severity"] = "HIGH"
                data["message"] = "Windows System Audit Policy Changed"
        
        # Extract username
        user_match = re.search(r"TargetUserName:\s*(\S+)", raw_log)
        if user_match and user_match.group(1) != "-":
            data["username"] = user_match.group(1).strip(" ,;[]()")
        
        # Extract Source IP
        ip_match = re.search(r"IpAddress:\s*(\S+)", raw_log)
        if ip_match and ip_match.group(1) != "-":
            data["src_ip"] = ip_match.group(1).strip(" ,;[]()")

    # ----------------------------------------------------
    # LINUX LOG PARSER
    # ----------------------------------------------------
    elif "linux" in src:
        # Standard syslog format: Jul 25 21:05:01 host process[pid]: message
        syslog_match = re.match(r"(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<process>[\w\-]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)", raw_log)
        if syslog_match:
            data["host"] = syslog_match.group("host")
            data["process"] = syslog_match.group("process")
            data["message"] = syslog_match.group("msg")
            
            msg = data["message"]
            
            # Sub-parsing: SSH Failed login
            ssh_fail = LINUX_SSH_FAIL.search(msg)
            if ssh_fail:
                data["username"] = ssh_fail.group(2)
                data["src_ip"] = ssh_fail.group(3)
                data["severity"] = "WARNING"
                data["message"] = f"SSH login failed for user {data['username']}"
            
            # Sub-parsing: SSH Success
            ssh_success = LINUX_SSH_SUCCESS.search(msg)
            if ssh_success:
                data["username"] = ssh_success.group(1)
                data["src_ip"] = ssh_success.group(2)
                data["severity"] = "INFO"
                data["message"] = f"SSH login successful for user {data['username']}"
            
            # Sub-parsing: sudo Command Execution
            sudo_match = LINUX_SUDO.search(msg) or LINUX_SUDO.search(raw_log)
            if sudo_match:
                data["username"] = sudo_match.group(1)  # the executor
                data["severity"] = "HIGH"
                data["message"] = f"Sudo executed: command={sudo_match.group(3)} as user={sudo_match.group(2)}"
            
            # Sub-parsing: new user creation
            new_user = LINUX_NEW_USER.search(msg)
            if new_user:
                data["username"] = new_user.group(1)
                data["severity"] = "HIGH"
                data["message"] = f"New user account created: {data['username']}"

    # ----------------------------------------------------
    # APACHE WEB LOG PARSER
    # ----------------------------------------------------
    elif "apache" in src:
        data["process"] = "apache2"
        access_match = APACHE_ACCESS.search(raw_log)
        if access_match:
            data["src_ip"] = access_match.group("ip")
            user = access_match.group("user")
            if user != "-":
                data["username"] = user
            
            method = access_match.group("method")
            path = access_match.group("path")
            query = access_match.group("query") or ""
            status = int(access_match.group("status"))
            
            data["message"] = f"HTTP {method} {path} - Status {status}"
            data["severity"] = "INFO" if status < 400 else "WARNING" if status < 500 else "ERROR"
            
            import urllib.parse
            # Store full request details in message, URL decoding for regex inspection
            full_path = f"{path}?{query}" if query else path
            decoded_path = urllib.parse.unquote(full_path)
            data["message"] = f"HTTP {method} {decoded_path} - Response {status}"
        else:
            # Apache Error Log format
            error_match = re.search(r"\[client\s+(?P<ip>\S+)(:\d+)?\]\s+(?P<msg>.*)", raw_log)
            if error_match:
                data["src_ip"] = error_match.group("ip")
                data["message"] = error_match.group("msg")
                data["severity"] = "ERROR"

    # ----------------------------------------------------
    # FIREWALL LOG PARSER
    # ----------------------------------------------------
    elif "firewall" in src:
        data["process"] = "ufw"  # Default firewall process
        deny_match = FIREWALL_DENY.search(raw_log)
        allow_match = FIREWALL_ALLOW.search(raw_log)
        
        if deny_match:
            data["src_ip"] = deny_match.group("src")
            data["dst_ip"] = deny_match.group("dst")
            proto = deny_match.group("proto")
            port = deny_match.group("dpt")
            data["severity"] = "WARNING"
            data["message"] = f"Firewall blocked packet: {proto} from {data['src_ip']} to {data['dst_ip']}:{port}"
        elif allow_match:
            data["src_ip"] = allow_match.group("src")
            data["dst_ip"] = allow_match.group("dst")
            proto = allow_match.group("proto")
            port = allow_match.group("dpt")
            data["severity"] = "INFO"
            data["message"] = f"Firewall allowed packet: {proto} from {data['src_ip']} to {data['dst_ip']}:{port}"
        
        # Check if syslog header contains host
        syslog_hdr = re.match(r"\w{3}\s+\d+\s+\S+\s+(?P<host>\S+)", raw_log)
        if syslog_hdr:
            data["host"] = syslog_hdr.group("host")

    # ----------------------------------------------------
    # SIMULATOR / GENERIC LOG PARSER
    # ----------------------------------------------------
    else:
        # Fallback host parser
        host_match = re.search(r"host[:\s]+(\S+)", raw_log, re.IGNORECASE)
        if host_match:
            data["host"] = host_match.group(1)
        
        # Fallback IP parser
        ips = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", raw_log)
        if len(ips) >= 1:
            data["src_ip"] = ips[0]
        if len(ips) >= 2:
            data["dst_ip"] = ips[1]
            
        # Fallback Username
        user_match = re.search(r"user[:\s]+(\S+)", raw_log, re.IGNORECASE) or re.search(r"username[:\s]+(\S+)", raw_log, re.IGNORECASE)
        if user_match:
            data["username"] = user_match.group(1).strip("',.[]()")

    return data

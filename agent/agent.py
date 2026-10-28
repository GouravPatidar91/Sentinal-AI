import os
import sys
import time
import socket
import threading
import platform
import requests
import json
from datetime import datetime
from dotenv import load_dotenv

# Load agent environment variables
load_dotenv()

BACKEND_URL = os.getenv("BACKEND_URL", "http://127.0.0.1:8000/api/logs/ingest")
HOST_NAME = os.getenv("HOST_NAME", socket.gethostname().lower())
SYSLOG_PORT = int(os.getenv("SYSLOG_PORT", "5140"))  # Default 5140 (non-root port) for firewall syslog receipt

# Global flag to control execution
running = True

def send_log_to_backend(raw_log: str, source: str, severity: str = "INFO", process: str = None, username: str = None, src_ip: str = None):
    """
    HTTP client helper to stream parsed logs to the backend ingestion API.
    """
    payload = {
        "host": HOST_NAME,
        "source": source,
        "log_type": "Generic", # Backend will resolve based on source
        "severity": severity,
        "username": username,
        "src_ip": src_ip,
        "process": process,
        "message": raw_log.strip(),
        "raw_log": raw_log
    }
    
    try:
        resp = requests.post(BACKEND_URL, json=payload, timeout=3)
        if resp.status_code == 200:
            data = resp.json()
            log_id = data.get("log_id", "?")
            rules = data.get("rules_matched", [])
            inc_id = data.get("incident_id")
            
            # Formatted transmission feedback for live demonstration
            msg_snippet = (payload["message"][:50] + "...") if len(payload["message"]) > 50 else payload["message"]
            alert_tag = f" -> Matched: {rules}" if rules else ""
            inc_tag = f" [ALERT: INCIDENT #{inc_id}]" if inc_id else ""
            
            print(f"[STREAM SUCCESS] Log #{log_id} | Host: {HOST_NAME} | Source: {source} | User: {username or '-'} | Sev: {severity}{inc_tag}")
            print(f"  └─ Payload: \"{msg_snippet}\"{alert_tag}")
        else:
            print(f"[STREAM WARNING] Backend returned code {resp.status_code}: {resp.text}")
    except Exception as e:
        print(f"[STREAM ERROR] Failed to connect to backend: {e}")

# ----------------------------------------------------
# Syslog UDP Firewall Receiver
# ----------------------------------------------------
def start_syslog_server():
    """
    Runs a UDP socket server to receive Syslog packets (e.g. from firewalls/routers)
    and forwards them to the backend.
    """
    print(f"[*] Starting UDP Syslog Server on 0.0.0.0:{SYSLOG_PORT}...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(("0.0.0.0", SYSLOG_PORT))
    except Exception as e:
        print(f"[!] Syslog Server failed to bind to port {SYSLOG_PORT}: {e}")
        return
        
    while running:
        try:
            sock.settimeout(2.0)
            data, addr = sock.recvfrom(4096)
            message = data.decode("utf-8", errors="ignore")
            print(f"[+] Received Syslog packet from {addr[0]}")
            
            # Forward firewall syslog to backend
            send_log_to_backend(
                raw_log=message,
                source="Firewall",
                severity="WARNING" if "DENY" in message or "BLOCK" in message else "INFO",
                process="syslog_receiver"
            )
        except socket.timeout:
            continue
        except Exception as e:
            print(f"[!] Syslog Server socket error: {e}")
            break
            
    sock.close()
    print("[*] Syslog Server stopped.")

# ----------------------------------------------------
# File Tailer (Linux auth.log/syslog, Apache logs)
# ----------------------------------------------------
def tail_file(file_path: str, source: str):
    """
    Tails a text file, sending new lines to the backend.
    """
    if not os.path.exists(file_path):
        print(f"[-] Target file {file_path} not found. Skipping tailer.")
        return
        
    print(f"[*] Starting tailer on: {file_path} for source: {source}")
    with open(file_path, "r", errors="ignore") as f:
        # Seek to the end of the file
        f.seek(0, os.SEEK_END)
        while running:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            
            clean_line = line.strip()
            if clean_line:
                # Determine default severity based on common keywords
                severity = "INFO"
                if any(x in clean_line.upper() for x in ["FAIL", "ERR", "DENY", "WARN", "CRIT"]):
                    severity = "WARNING"
                
                send_log_to_backend(
                    raw_log=clean_line,
                    source=source,
                    severity=severity
                )

# ----------------------------------------------------
# OS-Specific Event Collection (Windows vs. Linux)
# ----------------------------------------------------
def start_linux_log_collector():
    """Starts tailing standard Linux logs if available."""
    # Standard paths
    auth_log = "/var/log/auth.log"
    syslog = "/var/log/syslog"
    
    # Start thread for auth.log
    t1 = threading.Thread(target=tail_file, args=(auth_log, "Linux"), daemon=True)
    t1.start()
    
    # Start thread for syslog
    t2 = threading.Thread(target=tail_file, args=(syslog, "Linux"), daemon=True)
    t2.start()

def start_windows_log_collector():
    """
    Hooks into Windows Security event logs.
    Falls back to a simulated Windows security event tailer if pywin32 is not installed or lacks privileges.
    """
    def simulate_windows_events():
        print("[*] Starting Simulated Windows Security Event Generator for testing...")
        while running:
            time.sleep(30)
            send_log_to_backend(
                raw_log=f"Event ID: 4624, ComputerName: {HOST_NAME}, TargetUserName: system_agent, IpAddress: 127.0.0.1",
                source="Windows",
                severity="INFO",
                process="WinEventLog:4624"
            )

    has_pywin32 = False
    try:
        import win32evtlog
        has_pywin32 = True
    except ImportError:
        print("[-] pywin32 not found. Cannot read Windows Event Logs directly.")
        t = threading.Thread(target=simulate_windows_events, daemon=True)
        t.start()
        return
        
    if has_pywin32:
        def read_event_logs():
            print("[*] Starting direct Windows Security Event Log Listener...")
            server = 'localhost'
            logtype = 'Security'
            
            try:
                # Open Windows Event log
                hand = win32evtlog.OpenEventLog(server, logtype)
                
                # Seek to current events by moving cursor to the end
                total = win32evtlog.GetNumberOfEventLogRecords(hand)
                oldest = win32evtlog.GetOldestEventLogRecord(hand)
                if total > 0:
                    last_rec = oldest + total - 1
                    seek_flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEEK_READ
                    try:
                        # Read the last event to position the cursor
                        win32evtlog.ReadEventLog(hand, seek_flags, last_rec)
                        print(f"[*] Positioned event log reader at end record: {last_rec}")
                    except Exception as seek_err:
                        print(f"[-] Warning: Failed to seek to end of event log: {seek_err}")
                
                # Read forwards sequentially from the cursor position
                flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                
                while running:
                    events = win32evtlog.ReadEventLog(hand, flags, 0)
                    if not events:
                        time.sleep(1.0)
                        continue
                        
                    for event in events:
                        event_id = event.EventID & 0xFFFF
                        if event_id in [4624, 4625, 4672, 4719]:
                            time_str = event.TimeGenerated.Format()
                            message = event.StringInserts
                            raw = f"Event ID: {event_id}, Time: {time_str}, ComputerName: {HOST_NAME}, Inserts: {str(message)}"
                            
                            send_log_to_backend(
                                raw_log=raw,
                                source="Windows",
                                severity="WARNING" if event_id == 4625 else "HIGH" if event_id in [4672, 4719] else "INFO",
                                process=f"WinEventLog:{event_id}"
                            )
            except Exception as e:
                print(f"[!] Error reading Windows Event Logs: {e}")
                print("[*] Insufficient privileges. Please run PowerShell/CMD as Administrator to capture active Security logs.")
                print("[*] Falling back to Simulated Event Generator...")
                simulate_windows_events()
                
        t = threading.Thread(target=read_event_logs, daemon=True)
        t.start()

# ----------------------------------------------------
# SOAR Command Execution Listener & Remediation Engine
# ----------------------------------------------------
import subprocess

def execute_soar_command(action: dict):
    """
    Executes OS-level SOAR containment actions dispatched by the backend.
    Supported Actions:
      - KILL_PROCESS (PID)
      - BLOCK_IP (Attacker IP)
      - QUARANTINE_INTERFACE (Interface Name)
      - DISABLE_USER (Username)
    """
    action_id = action.get("id")
    action_type = action.get("action_type", "").upper()
    payload = action.get("payload", "").strip()
    target_host = action.get("target_host", "").lower()
    
    # Verify command is intended for this host
    if target_host and target_host not in [HOST_NAME, "localhost", "127.0.0.1", "web-server-prod", "desktop-hg34g7h"]:
        return

    print(f"\n[SOAR EXECUTOR] Received approved action #{action_id}: {action_type} -> Payload: '{payload}'")

    os_type = platform.system().lower()
    cmd = []
    output_log = ""
    status_result = "EXECUTED"

    try:
        if action_type == "KILL_PROCESS":
            if "windows" in os_type:
                cmd = ["powershell", "-Command", f"Stop-Process -Id {payload} -Force"]
            else:
                cmd = ["kill", "-9", payload]

        elif action_type == "BLOCK_IP":
            if "windows" in os_type:
                cmd = ["netsh", "advfirewall", "firewall", "add", "rule", f"name=SentinelBlock_{payload}", "dir=in", "action=block", f"remoteip={payload}"]
            else:
                cmd = ["iptables", "-A", "INPUT", "-s", payload, "-j", "DROP"]

        elif action_type == "QUARANTINE_INTERFACE":
            if "windows" in os_type:
                cmd = ["netsh", "interface", "set", "interface", f"name={payload}", "admin=disable"]
            else:
                cmd = ["ip", "link", "set", payload, "down"]

        elif action_type == "DISABLE_USER":
            if "windows" in os_type:
                cmd = ["powershell", "-Command", f"Disable-LocalUser -Name '{payload}'"]
            else:
                cmd = ["usermod", "-L", payload]

        else:
            output_log = f"Unsupported SOAR Action type: {action_type}"
            status_result = "FAILED"

        if cmd:
            print(f"[SOAR EXECUTOR] Running command: {' '.join(cmd)}")
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            output_log = res.stdout or res.stderr or f"Command executed cleanly with returncode {res.returncode}"
            if res.returncode != 0:
                status_result = "FAILED"

    except Exception as e:
        status_result = "FAILED"
        output_log = f"Execution exception: {e}"

    print(f"[SOAR EXECUTOR] Result for Action #{action_id}: {status_result} | Log: {output_log}")

    # Report execution result back to backend
    base_api = BACKEND_URL.rsplit("/api/", 1)[0]
    report_url = f"{base_api}/api/soar/report_execution/{action_id}"
    try:
        requests.post(report_url, params={"status_result": status_result, "output": output_log[:500]}, timeout=5)
    except Exception as err:
        print(f"[SOAR EXECUTOR] Failed to report execution result to backend: {err}")


def poll_soar_commands():
    """
    Periodically polls the backend for APPROVED SOAR actions waiting for target execution.
    """
    print("[*] Starting SOAR Command Listener thread...")
    base_api = BACKEND_URL.rsplit("/api/", 1)[0]
    soar_url = f"{base_api}/api/soar/actions"
    
    while running:
        try:
            resp = requests.get(soar_url, params={"status_filter": "APPROVED"}, timeout=4)
            if resp.status_code == 200:
                actions = resp.json()
                for action in actions:
                    execute_soar_command(action)
        except Exception:
            pass
        time.sleep(5)


# ----------------------------------------------------
# Main Agent Loop
# ----------------------------------------------------
def main():
    global running
    print("====================================================")
    print("  SentinelAI Lightweight Endpoint Agent  ")
    print("====================================================")
    print(f"[*] OS Detected: {platform.system()} ({platform.release()})")
    print(f"[*] Endpoint Hostname: {HOST_NAME}")
    print(f"[*] Streaming Endpoint: {BACKEND_URL}")
    print("====================================================")

    # 1. Start Firewall Syslog server (UDP)
    syslog_thread = threading.Thread(target=start_syslog_server, daemon=True)
    syslog_thread.start()

    # 2. Start SOAR Command Listener
    soar_thread = threading.Thread(target=poll_soar_commands, daemon=True)
    soar_thread.start()
    
    # 3. Start OS-specific log collectors
    os_type = platform.system().lower()
    if "windows" in os_type:
        start_windows_log_collector()
    elif "linux" in os_type:
        start_linux_log_collector()
    else:
        print("[!] Unsupported operating system for direct OS log collection. Generic mode activated.")

    # 4. Apache Web Logs Tailing (if file exists locally)
    apache_paths = [
        "C:\\xampp\\apache\\logs\\access.log",
        "/var/log/apache2/access.log",
        "/var/log/httpd/access_log",
        "./access.log" # local folder test path
    ]
    for path in apache_paths:
        if os.path.exists(path):
            t_apache = threading.Thread(target=tail_file, args=(path, "Apache"), daemon=True)
            t_apache.start()
            break

    # Main thread sleep loop
    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        print("\n[*] Exiting agent...")
        running = False
        time.sleep(1.0)

if __name__ == "__main__":
    main()


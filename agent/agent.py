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

BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000/api/logs/ingest")
HOST_NAME = os.getenv("HOST_NAME", socket.gethostname().lower())
SYSLOG_PORT = int(os.getenv("SYSLOG_PORT", "5140"))  # Default 5140 (non-root port) for firewall syslog receipt

# Global flag to control execution
running = True

def send_log_to_backend(raw_log: str, source: str, severity: str = "INFO", process: str = None, username: str = None):
    """
    HTTP client helper to stream parsed logs to the backend ingestion API.
    """
    payload = {
        "host": HOST_NAME,
        "source": source,
        "log_type": "Generic", # Backend will resolve based on source
        "severity": severity,
        "username": username,
        "process": process,
        "message": raw_log.strip(),
        "raw_log": raw_log
    }
    
    try:
        resp = requests.post(BACKEND_URL, json=payload, timeout=3)
        if resp.status_code == 200:
            print(f"[Streaming Success] Sent log from {source} - Status: {resp.json().get('status')}")
        else:
            print(f"[Streaming Warning] Backend returned code {resp.status_code}: {resp.text}")
    except Exception as e:
        print(f"[Streaming Error] Failed to connect to backend: {e}")

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
                flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                
                # Seek to current events by reading existing
                _ = win32evtlog.ReadEventLog(hand, flags, 0)
                
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
    
    # 2. Start OS-specific log collectors
    os_type = platform.system().lower()
    if "windows" in os_type:
        start_windows_log_collector()
    elif "linux" in os_type:
        start_linux_log_collector()
    else:
        print("[!] Unsupported operating system for direct OS log collection. Generic mode activated.")

    # 3. Apache Web Logs Tailing (if file exists locally)
    # Check common Apache paths
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

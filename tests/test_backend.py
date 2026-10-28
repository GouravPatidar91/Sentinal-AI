import pytest
import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.app.models.database import Base
from backend.app.models.models import LogEntry, DetectionRule, Incident, IncidentEvent
from backend.app.services.parser import parse_log
from backend.app.services.normalization import normalize_log
from backend.app.services.detection import matches_rule, seed_default_rules
from backend.app.services.correlation import correlate_event
from backend.app.services.anomaly import anomaly_detector

# Setup memory database for unit testing
TEST_DATABASE_URL = "sqlite:///:memory:"

@pytest.fixture(name="db_session")
def fixture_db_session():
    engine = create_engine(TEST_DATABASE_URL, connect_args={"check_same_thread": False})
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)
    
    db = TestingSessionLocal()
    # Seed default rules for test context
    seed_default_rules(db)
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)

def test_log_parser_linux_ssh():
    """Verify that SSH failure syslog parses correctly."""
    raw = "Jul 25 21:05:12 host-linux-server sshd[1243]: Failed password for invalid user admin from 198.51.100.12 port 38222 ssh2"
    parsed = parse_log(raw, "Linux")
    
    assert parsed["host"] == "host-linux-server"
    assert parsed["username"] == "admin"
    assert parsed["src_ip"] == "198.51.100.12"
    assert parsed["process"] == "sshd"
    assert "ssh login failed" in parsed["message"].lower()

def test_log_parser_windows_event():
    """Verify that Windows Event 4625 parses correctly."""
    raw = "Event ID: 4625, ComputerName: host-win10, TargetUserName: test_user, IpAddress: 192.168.10.45"
    parsed = parse_log(raw, "Windows")
    
    assert parsed["host"] == "host-win10"
    assert parsed["username"] == "test_user"
    assert parsed["src_ip"] == "192.168.10.45"
    assert parsed["process"] == "WinEventLog:4625"
    assert parsed["severity"] == "WARNING"

def test_log_parser_apache_sqli():
    """Verify that Apache access logs target SQLi strings."""
    raw = '192.168.1.100 - - [25/Jul/2026:21:07:00 +0000] "GET /index.php?id=1%20UNION%20SELECT%20null,username,password%20FROM%20users HTTP/1.1" 200 4502'
    parsed = parse_log(raw, "Apache")
    
    assert parsed["src_ip"] == "192.168.1.100"
    assert "UNION SELECT" in parsed["message"]
    assert parsed["severity"] == "INFO" # 200 response

def test_log_normalization():
    """Verify normalization returns a valid schema-compliant structure."""
    raw = "Jul 25 21:05:01 host-linux cron[4512]: (root) CMD (run-parts /etc/cron.hourly)"
    normalized = normalize_log(raw, "Linux")
    
    assert normalized.host == "host-linux"
    assert normalized.source == "Linux"
    assert normalized.log_type == "System"
    assert normalized.severity == "INFO"

def test_rules_matching(db_session):
    """Verify SQL injection rule matches SQLi payload."""
    log = LogEntry(
        timestamp=datetime.datetime.utcnow(),
        host="host-apache",
        source="Apache",
        log_type="Web",
        severity="WARNING",
        message="HTTP GET /index.php?id=1 UNION SELECT null,username,password FROM users",
        raw_log="127.0.0.1 - - [25/Jul/2026] \"GET /index.php?id=1 UNION SELECT null,username,password FROM users HTTP/1.1\" 200 4502"
    )
    
    sqli_rule = db_session.query(DetectionRule).filter(DetectionRule.name == "Apache-SQL-Injection").first()
    assert sqli_rule is not None
    assert matches_rule(log, sqli_rule) is True

def test_event_correlation(db_session):
    """Verify failed login triggers correlate into a single brute-force incident."""
    logs = []
    # Create 5 failed logins
    for i in range(5):
        log = LogEntry(
            timestamp=datetime.datetime.utcnow() - datetime.timedelta(seconds=(10 - i)),
            host="host-corp-dc",
            source="Windows",
            log_type="Security",
            severity="WARNING",
            username="administrator",
            src_ip="185.220.101.5",
            process="WinEventLog:4625",
            message="An account failed to log on.",
            raw_log=f"Event ID: 4625, ComputerName: host-corp-dc, TargetUserName: administrator, IpAddress: 185.220.101.5"
        )
        db_session.add(log)
        db_session.flush()
        logs.append(log)
        
    rule = db_session.query(DetectionRule).filter(DetectionRule.name == "Win-BruteForce").first()
    
    # Send events to correlation engine
    incident = None
    for log in logs:
        incident = correlate_event(db_session, log, [rule])
        
    assert incident is not None
    assert "Persistent Alert Sequence" in incident.title
    assert incident.severity == "HIGH"
    
    # Verify events are grouped in timeline
    event_relations = db_session.query(IncidentEvent).filter(IncidentEvent.incident_id == incident.id).all()
    assert len(event_relations) >= 1

def test_anomaly_scoring_heuristics(db_session):
    """Verify anomaly detector scores high for impossible travel IP changes."""
    log1 = LogEntry(
        timestamp=datetime.datetime.utcnow(),
        host="server01",
        source="Linux",
        log_type="Auth",
        severity="INFO",
        username="db_admin",
        src_ip="100.1.1.1",
        message="Accepted password for db_admin from 100.1.1.1",
        raw_log="Accepted password for db_admin from 100.1.1.1"
    )
    db_session.add(log1)
    db_session.commit()
    
    log2 = LogEntry(
        timestamp=datetime.datetime.utcnow() + datetime.timedelta(minutes=2),
        host="server01",
        source="Linux",
        log_type="Auth",
        severity="INFO",
        username="db_admin",
        src_ip="200.2.2.2", # Different IP 2 minutes later
        message="Accepted password for db_admin from 200.2.2.2",
        raw_log="Accepted password for db_admin from 200.2.2.2"
    )
    db_session.add(log2)
    db_session.commit()
    
    # Score the second log
    score = anomaly_detector.predict_anomaly(db_session, log2)
    assert score >= 0.5  # Should flag as anomaly due to impossible travel

def test_multi_agent_workflow(db_session):
    """Verify Multi-Agent SOC Workflow produces Triage, Forensic, and Containment reports."""
    import asyncio
    from backend.app.services.ai_agents import multi_agent_workflow
    
    incident = Incident(
        title="Test Critical Security Threat",
        description="Multiple failed SSH attempts followed by root login.",
        severity="CRITICAL",
        risk_score=90,
        anomaly_score=0.85
    )
    db_session.add(incident)
    db_session.commit()
    
    report = asyncio.run(multi_agent_workflow.run_workflow(incident))
    assert "executive_summary" in report
    assert "technical_analysis" in report
    assert "soar_actions" in report
    assert len(report["soar_actions"]) > 0

def test_soar_action_model(db_session):
    """Verify SOARAction DB model creation and relationship."""
    from backend.app.models.models import SOARAction
    
    incident = Incident(
        title="Ransomware Activity",
        description="Process crypto-locker detected.",
        severity="CRITICAL",
        risk_score=95
    )
    db_session.add(incident)
    db_session.commit()
    
    action = SOARAction(
        incident_id=incident.id,
        action_type="KILL_PROCESS",
        target_host="win-server01",
        payload="4082",
        description="Kill ransomware PID 4082",
        status="PENDING"
    )
    db_session.add(action)
    db_session.commit()
    
    assert action.id is not None
    assert action.status == "PENDING"
    assert action.incident.title == "Ransomware Activity"


"""
SentinelAI Database Inspector CLI
=================================
Allows developers, guides, and professors to view parsed logs, incidents,
detection rules, and SOAR actions directly from `database/sentinel.db`.

Usage:
    python view_db.py                  # Show database overview and recent 10 logs
    python view_db.py --table logs     # Show parsed log records
    python view_db.py --table incidents# Show security incidents
    python view_db.py --table rules    # Show active detection rules
    python view_db.py --limit 25       # Custom row limit
    python view_db.py --search "admin" # Search logs for term
"""

import os
import sys
import argparse
import sqlite3
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "database", "sentinel.db")

def truncate(text, length=32):
    if text is None:
        return "-"
    text = str(text).replace("\r", " ").replace("\n", " ")
    return text if len(text) <= length else text[:length - 3] + "..."

def print_box_header(title):
    width = 90
    print("\n" + "=" * width)
    print(f"  {title.center(width - 4)}")
    print("=" * width)

def get_connection():
    if not os.path.exists(DB_PATH):
        print(f"[!] Error: Database file not found at {DB_PATH}")
        sys.exit(1)
    return sqlite3.connect(DB_PATH)

def show_overview():
    conn = get_connection()
    c = conn.cursor()
    
    file_size_kb = os.path.getsize(DB_PATH) / 1024
    
    print_box_header("SENTINEL-AI SQLITE DATABASE OVERVIEW")
    print(f"[*] Database File : {DB_PATH}")
    print(f"[*] File Size     : {file_size_kb:.1f} KB")
    print(f"[*] Inspected At  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 90)

    # Counts
    tables = [
        ("log_entries", "Log Entries (Parsed System, Web, Windows & Firewall logs)"),
        ("incidents", "Security Incidents (Correlated Multi-stage Attacks)"),
        ("incident_events", "Incident Timeline Events (Linked Evidence)"),
        ("detection_rules", "Detection Rules (MITRE ATT&CK Mapping)"),
        ("soar_actions", "SOAR Automated Containment Actions"),
        ("users", "System Users & Analysts")
    ]

    print(f"{'TABLE NAME':<20} | {'ROW COUNT':<10} | {'DESCRIPTION'}")
    print("-" * 90)
    for tbl, desc in tables:
        try:
            count = c.execute(f"SELECT COUNT(*) FROM {tbl};").fetchone()[0]
            print(f"{tbl:<20} | {count:<10} | {desc}")
        except Exception:
            print(f"{tbl:<20} | {'(not found)':<10} | {desc}")

    print("-" * 90)
    conn.close()

def show_logs(limit=10, search=None):
    conn = get_connection()
    c = conn.cursor()

    query = """
        SELECT id, timestamp, host, source, severity, username, src_ip, process, message 
        FROM log_entries
    """
    params = []
    if search:
        query += " WHERE host LIKE ? OR username LIKE ? OR src_ip LIKE ? OR message LIKE ? OR process LIKE ?"
        term = f"%{search}%"
        params.extend([term, term, term, term, term])

    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    rows = c.execute(query, params).fetchall()
    
    title = f"PARSED LOG ENTRIES (Showing {len(rows)} records" + (f" matching '{search}')" if search else ")")
    print_box_header(title)
    
    if not rows:
        print("  [No log entries found]")
        conn.close()
        return

    # Header
    print(f"{'ID':<6} | {'TIMESTAMP':<19} | {'HOST':<14} | {'SRC':<8} | {'SEV':<8} | {'SRC IP':<15} | {'USER':<10} | {'MESSAGE'}")
    print("-" * 110)
    for r in rows:
        lid, ts, host, src, sev, user, src_ip, proc, msg = r
        ts_str = str(ts)[:19] if ts else "-"
        print(f"#{lid:<5} | {ts_str:<19} | {truncate(host, 14):<14} | {truncate(src, 8):<8} | {truncate(sev, 8):<8} | {truncate(src_ip, 15):<15} | {truncate(user, 10):<10} | {truncate(msg, 32)}")

    print("-" * 110)
    print("  * Tip: In the Web UI, view and filter all logs interactively at: http://localhost:5173/search")
    conn.close()

def show_incidents(limit=10):
    conn = get_connection()
    c = conn.cursor()

    query = """
        SELECT id, title, severity, status, risk_score, anomaly_score, created_at 
        FROM incidents ORDER BY id DESC LIMIT ?
    """
    rows = c.execute(query, (limit,)).fetchall()

    print_box_header(f"CORRELATED SECURITY INCIDENTS (Showing {len(rows)} records)")

    if not rows:
        print("  [No security incidents found]")
        conn.close()
        return

    print(f"{'ID':<5} | {'SEVERITY':<9} | {'STATUS':<12} | {'RISK':<6} | {'ANOMALY':<7} | {'TITLE'}")
    print("-" * 95)
    for r in rows:
        iid, title, sev, status, risk, anom, created = r
        anom_str = f"{anom:.2f}" if anom is not None else "0.00"
        print(f"#{iid:<4} | {truncate(sev, 9):<9} | {truncate(status, 12):<12} | {str(risk):<6} | {anom_str:<7} | {truncate(title, 45)}")

    print("-" * 95)
    print("  * Tip: In the Web UI, view live Incident timelines and AI Reports at: http://localhost:5173/incidents")
    conn.close()

def show_rules():
    conn = get_connection()
    c = conn.cursor()

    query = "SELECT id, name, severity, tactic, technique, rule_type, is_enabled FROM detection_rules ORDER BY id ASC"
    rows = c.execute(query).fetchall()

    print_box_header(f"DETECTION RULES & MITRE ATT&CK MAPPINGS ({len(rows)} rules)")
    print(f"{'ID':<4} | {'NAME':<24} | {'SEVERITY':<9} | {'TACTIC':<18} | {'TECHNIQUE':<10} | {'ENABLED'}")
    print("-" * 85)
    for r in rows:
        rid, name, sev, tactic, tech, rtype, enabled = r
        en_str = "YES" if enabled else "NO"
        print(f"#{rid:<3} | {truncate(name, 24):<24} | {truncate(sev, 9):<9} | {truncate(tactic, 18):<18} | {truncate(tech, 10):<10} | {en_str}")
    print("-" * 85)
    conn.close()

def main():
    parser = argparse.ArgumentParser(description="SentinelAI SQLite Database Inspector")
    parser.add_argument("--table", choices=["all", "logs", "incidents", "rules"], default="all", help="Table to inspect")
    parser.add_argument("--limit", type=int, default=10, help="Number of rows to display (default: 10)")
    parser.add_argument("--search", type=str, default=None, help="Search term across logs")

    args = parser.parse_args()

    show_overview()

    if args.table in ["all", "logs"]:
        show_logs(limit=args.limit, search=args.search)

    if args.table in ["all", "incidents"]:
        show_incidents(limit=args.limit)

    if args.table == "rules":
        show_rules()

if __name__ == "__main__":
    main()

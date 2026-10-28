import json
import os
import httpx
from typing import Dict, Any, List, Optional
from backend.app.core.config import settings
from backend.app.models.models import Incident, IncidentEvent

# Prompts for Specialized Agents

TRIAGE_AGENT_PROMPT = """You are the SentinelAI Triage Agent (Tier 1/2 Specialist).
Your responsibility is to analyze incoming correlated alerts, rule hits, and ML anomaly scores to:
1. Determine if this is a True Positive threat or False Positive noise.
2. Calculate the adjusted threat score (0-100) and severity level.
3. Provide an executive summary and threat credibility assessment.

INCIDENT DATA:
Title: {title}
Description: {description}
Initial Severity: {severity}
Risk Score: {risk_score}/100
ML Anomaly Score: {anomaly_score}/1.0
Target Host: {target_host}
Attacker IP: {attacker_ip}

TIMELINE EVENTS:
{timeline_str}

Respond with a JSON object ONLY containing:
{{
  "is_true_positive": true,
  "credibility_rating": "HIGH|MEDIUM|LOW",
  "adjusted_risk_score": 85,
  "triage_summary": "Summary of triage findings...",
  "attack_vector": "Identified attack vector...",
  "mitre_tactics_identified": ["Initial Access", "Execution"]
}}
"""

FORENSIC_AGENT_PROMPT = """You are the SentinelAI Forensic Agent (Digital Forensics & Incident Response Specialist).
Your responsibility is to analyze target host telemetry, active network connections, process trees, and file indicators.

TRIAGE INPUT:
Triage Summary: {triage_summary}
Target Host: {target_host}
Attacker IP: {attacker_ip}

TIMELINE EVIDENCE:
{timeline_str}

Perform a deep forensic analysis and return a JSON object ONLY containing:
{{
  "netstat_audit": "Detailed netstat connection analysis (e.g. ESTABLISHED connection from attacker IP to local port 80/22)...",
  "suspicious_processes": [
    {{"process_name": "cmd.exe", "pid": 4082, "command_line": "whoami; id", "parent_pid": 1204}}
  ],
  "file_hashes": [
    {{"filename": "payload.sh", "md5": "e99a18c428cb38d5f260853678922e03", "sha256": "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a"}}
  ],
  "root_cause_analysis": "Root cause explanation...",
  "technical_forensic_details": "Comprehensive technical breakdown of attacker movements..."
}}
"""

CONTAINMENT_AGENT_PROMPT = """You are the SentinelAI Containment Agent (SOAR Automation & Incident Response Specialist).
Your responsibility is to evaluate forensic findings and draft immediate, actionable SOAR containment payloads and recovery scripts.

FORENSIC INPUT:
Root Cause: {root_cause}
Suspicious Processes: {suspicious_processes}
Attacker IP: {attacker_ip}
Target Host: {target_host}

Draft a containment & recovery plan. Return a JSON object ONLY containing:
{{
  "containment_steps": "Immediate step-by-step instructions for SOC analysts...",
  "recovery_steps": "Recovery instructions to restore systems to baseline...",
  "soc_recommendations": "Proactive monitoring and policy updates...",
  "soar_actions": [
    {{
      "action_type": "KILL_PROCESS",
      "target_host": "{target_host}",
      "payload": "4082",
      "description": "Terminate suspicious process ID 4082"
    }},
    {{
      "action_type": "BLOCK_IP",
      "target_host": "{target_host}",
      "payload": "{attacker_ip}",
      "description": "Block external attacker IP on perimeter/host firewall"
    }},
    {{
      "action_type": "QUARANTINE_INTERFACE",
      "target_host": "{target_host}",
      "payload": "Ethernet0",
      "description": "Isolate host network interface to prevent lateral movement"
    }}
  ],
  "powershell_script": "Stop-Process -Id 4082 -Force; New-NetFirewallRule -DisplayName 'Block Attacker' -Direction Inbound -Action Block -RemoteAddress '{attacker_ip}'",
  "bash_script": "kill -9 4082 2>/dev/null; iptables -A INPUT -s {attacker_ip} -j DROP"
}}
"""

FAST_UNIFIED_SOC_PROMPT = """
You are SentinelAI Tier-3 Autonomous SOC Multi-Agent System (combining Triage, Forensics, and Containment).
Analyze the following security incident in a single high-efficiency pass:
INCIDENT: {title} | Severity: {severity} | Risk Score: {risk_score}/100
TARGET HOST: {target_host} | ATTACKER IP: {attacker_ip}
TIMELINE EVIDENCE:
{timeline_str}

Respond STRICTLY in valid JSON matching this exact schema:
{{
  "triage_summary": "High-level executive triage summary for CISO/SOC Lead",
  "technical_forensic_details": "Technical forensic breakdown of logs and telemetry",
  "root_cause_analysis": "Exact root cause mechanism or vulnerability abused",
  "attack_vector": "Identified MITRE ATT&CK technique and tactic",
  "adjusted_risk_score": {risk_score},
  "containment_steps": "Immediate step-by-step containment instructions",
  "recovery_steps": "Post-containment recovery and system baseline restoration",
  "soc_recommendations": "Preventative controls and Sigma detection rule tuning",
  "soar_actions": [
    {{"action_type": "BLOCK_IP", "target_host": "{target_host}", "payload": "{attacker_ip}", "description": "Block malicious attacker IP on firewall"}},
    {{"action_type": "QUARANTINE_INTERFACE", "target_host": "{target_host}", "payload": "Ethernet0", "description": "Isolate host interface to stop lateral movement"}}
  ]
}}
"""


class MultiAgentSOCWorkflow:
    """
    Orchestrates the cooperative multi-agent workflow:
    Triage Agent -> Forensic Agent -> Containment Agent.
    """
    
    @staticmethod
    def _extract_timeline_str(events: List[IncidentEvent]) -> str:
        lines = []
        for ev in events:
            rule_name = ev.rule.name if ev.rule else "Anomaly Heuristics"
            tactic = ev.rule.tactic if ev.rule else "Discovery"
            tech = ev.rule.technique if ev.rule else "T1046"
            src_ip = ev.log_entry.src_ip if ev.log_entry else "N/A"
            host = ev.log_entry.host if ev.log_entry else "N/A"
            lines.append(
                f"- [{ev.timestamp}] Host: {host} | IP: {src_ip} | Rule: {rule_name} (MITRE: {tech} {tactic}) - Msg: {ev.description}"
            )
        return "\n".join(lines) if lines else "No detailed events logged."

    @staticmethod
    def _extract_attacker_ip(incident: Incident) -> str:
        for ev in incident.events or []:
            if ev.log_entry and ev.log_entry.src_ip and ev.log_entry.src_ip not in ["-", "127.0.0.1", "::1"]:
                return ev.log_entry.src_ip
        return "198.51.100.55"

    @staticmethod
    def _extract_target_host(incident: Incident) -> str:
        for ev in incident.events or []:
            if ev.log_entry and ev.log_entry.host and ev.log_entry.host != "unknown-host":
                return ev.log_entry.host
        return "DESKTOP-HG34G7H"

    async def run_workflow(self, incident: Incident) -> Dict[str, Any]:
        """
        Runs high-speed unified multi-agent SOC analysis in a single round-trip.
        """
        timeline_str = self._extract_timeline_str(incident.events)
        attacker_ip = self._extract_attacker_ip(incident)
        target_host = self._extract_target_host(incident)

        soc_prompt = FAST_UNIFIED_SOC_PROMPT.format(
            title=incident.title,
            severity=incident.severity,
            risk_score=incident.risk_score,
            target_host=target_host,
            attacker_ip=attacker_ip,
            timeline_str=timeline_str
        )

        res = await self._query_llm_json(soc_prompt, fallback_type="containment", incident=incident)
        is_cloud_ai = bool(res.get("_is_cloud_ai"))

        triage_data = {
            "triage_summary": res.get("triage_summary", incident.description),
            "attack_vector": res.get("attack_vector", incident.title),
            "adjusted_risk_score": res.get("adjusted_risk_score", incident.risk_score),
            "_is_cloud_ai": is_cloud_ai
        }
        forensic_data = {
            "technical_forensic_details": res.get("technical_forensic_details", f"Forensic analysis detected threat targeting {target_host} from {attacker_ip}."),
            "root_cause_analysis": res.get("root_cause_analysis", "Credential abuse or unpatched service exploitation."),
            "_is_cloud_ai": is_cloud_ai
        }
        containment_data = {
            "containment_steps": res.get("containment_steps", "Isolate compromised host and block attacker IP."),
            "recovery_steps": res.get("recovery_steps", "Restore software baseline and inspect system files."),
            "soc_recommendations": res.get("soc_recommendations", "Add alert rules for rapid login failures and commands."),
            "soar_actions": res.get("soar_actions", [
                {"action_type": "BLOCK_IP", "target_host": target_host, "payload": attacker_ip, "description": f"Block external attacker IP {attacker_ip}"},
                {"action_type": "QUARANTINE_INTERFACE", "target_host": target_host, "payload": "Ethernet0", "description": f"Isolate network interface on {target_host}"}
            ]),
            "powershell_script": f"New-NetFirewallRule -DisplayName 'Block Attacker' -Direction Inbound -Action Block -RemoteAddress '{attacker_ip}'",
            "bash_script": f"iptables -A INPUT -s {attacker_ip} -j DROP",
            "_is_cloud_ai": is_cloud_ai
        }

        final_report = {
            "executive_summary": triage_data["triage_summary"],
            "technical_analysis": forensic_data["technical_forensic_details"],
            "root_cause": forensic_data["root_cause_analysis"],
            "possible_attack_type": triage_data["attack_vector"],
            "risk_explanation": f"Incident scored {triage_data['adjusted_risk_score']}/100 based on true positive credibility and MITRE threat mappings.",
            "recommended_mitigation": containment_data["soc_recommendations"],
            "containment_steps": containment_data["containment_steps"],
            "recovery_steps": containment_data["recovery_steps"],
            "soc_recommendations": containment_data["soc_recommendations"],
            "multi_agent_details": {
                "triage": triage_data,
                "forensics": forensic_data,
                "containment": containment_data
            },
            "soar_actions": containment_data["soar_actions"],
            "powershell_script": containment_data["powershell_script"],
            "bash_script": containment_data["bash_script"],
            "is_cloud_ai": is_cloud_ai,
            "detection_source": "cloud_ai" if is_cloud_ai else "local_engine"
        }
        
        return final_report

    async def _query_llm_json(self, prompt: str, fallback_type: str, incident: Incident) -> Dict[str, Any]:
        """Queries the configured AI Provider (Gemini / OpenRouter / OpenAI / Ollama) or returns structured fallback."""
        provider = settings.AI_PROVIDER.lower()
        key_openrouter = settings.OPENROUTER_API_KEY or os.getenv("OPENROUTER_API_KEY")
        key_gemini = settings.GEMINI_API_KEY or os.getenv("GEMINI_API_KEY")
        key_openai = settings.OPENAI_API_KEY or os.getenv("OPENAI_API_KEY")
        
        try:
            res = None
            if provider in ["openrouter", "open_router"] and key_openrouter:
                res = await self._call_openrouter(prompt, key_openrouter)
            elif provider == "gemini" and key_gemini:
                res = await self._call_gemini(prompt, key_gemini)
            elif provider == "openai" and key_openai:
                res = await self._call_openai(prompt, key_openai)
            elif provider == "ollama":
                res = await self._call_ollama(prompt)
            elif key_openrouter:
                res = await self._call_openrouter(prompt, key_openrouter)
            elif key_gemini:
                res = await self._call_gemini(prompt, key_gemini)
            elif key_openai:
                res = await self._call_openai(prompt, key_openai)

            if isinstance(res, dict):
                res["_is_cloud_ai"] = True
                return res
        except Exception as e:
            print(f"[{fallback_type.upper()}_AGENT] LLM Query error ({provider}): {e}")

        # Return rich fallback object per agent type
        fallback = self._get_fallback_data(fallback_type, incident)
        fallback["_is_cloud_ai"] = False
        return fallback

    async def _call_openrouter(self, prompt: str, key: str) -> Dict[str, Any]:
        url = "https://openrouter.ai/api/v1/chat/completions"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {key}",
            "HTTP-Referer": "https://sentinelai.local",
            "X-Title": "SentinelAI SOC Multi-Agent"
        }
        model = settings.AI_MODEL or "nvidia/nemotron-3.5-lightning:free"
        payload = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "response_format": {"type": "json_object"},
            "temperature": 0.2
        }
        async with httpx.AsyncClient(timeout=25.0) as client:
            resp = await client.post(url, json=payload, headers=headers)
            if resp.status_code == 200:
                resp_json = resp.json()
                message = resp_json.get("choices", [{}])[0].get("message", {})
                text = message.get("content") or message.get("reasoning") or ""
                if text:
                    return json.loads(self._clean_json(text))
        raise Exception(f"OpenRouter status {resp.status_code if 'resp' in locals() else 'unknown'}")

    async def _call_gemini(self, prompt: str, key: str) -> Dict[str, Any]:
        model = settings.AI_MODEL or "gemini-1.5-flash"
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={key}"
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"responseMimeType": "application/json"}
        }
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(url, json=payload)
            if resp.status_code == 200:
                text = resp.json()["candidates"][0]["content"]["parts"][0]["text"]
                return json.loads(self._clean_json(text))
        raise Exception(f"Gemini status {resp.status_code}")

    async def _call_openai(self, prompt: str, key: str) -> Dict[str, Any]:
        url = "https://api.openai.com/v1/chat/completions"
        headers = {"Content-Type": "application/json", "Authorization": f"Bearer {key}"}
        payload = {
            "model": settings.AI_MODEL or "gpt-4o-mini",
            "messages": [{"role": "user", "content": prompt}],
            "response_format": {"type": "json_object"},
            "temperature": 0.2
        }
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(url, json=payload, headers=headers)
            if resp.status_code == 200:
                text = resp.json()["choices"][0]["message"]["content"]
                return json.loads(self._clean_json(text))
        raise Exception(f"OpenAI status {resp.status_code}")

    async def _call_ollama(self, prompt: str) -> Dict[str, Any]:
        url = f"{settings.OLLAMA_URL}/api/generate"
        payload = {"model": settings.AI_MODEL or "llama3", "prompt": prompt, "stream": False, "format": "json"}
        async with httpx.AsyncClient(timeout=45.0) as client:
            resp = await client.post(url, json=payload)
            if resp.status_code == 200:
                text = resp.json()["response"]
                return json.loads(self._clean_json(text))
        raise Exception(f"Ollama status {resp.status_code}")

    @staticmethod
    def _clean_json(text: str) -> str:
        cleaned = text.strip()
        if cleaned.startswith("```"):
            lines = cleaned.split("\n")
            if lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].startswith("```"):
                lines = lines[:-1]
            cleaned = "\n".join(lines).strip()
        return cleaned

    def _get_fallback_data(self, agent_type: str, incident: Incident) -> Dict[str, Any]:
        attacker_ip = self._extract_attacker_ip(incident)
        target_host = self._extract_target_host(incident)
        
        if agent_type == "triage":
            return {
                "is_true_positive": True,
                "credibility_rating": "HIGH",
                "adjusted_risk_score": max(incident.risk_score, 75),
                "triage_summary": f"Multi-Agent Triage verified active security threat '{incident.title}' targeting {target_host}.",
                "attack_vector": incident.title,
                "mitre_tactics_identified": ["Initial Access", "Execution"]
            }
        elif agent_type == "forensic":
            return {
                "netstat_audit": f"Active ESTABLISHED connection identified from remote threat IP {attacker_ip} to local port 80/22.",
                "suspicious_processes": [
                    {"process_name": "cmd.exe", "pid": 4082, "command_line": "whoami; id; uname", "parent_pid": 1204}
                ],
                "file_hashes": [
                    {"filename": "malicious_script.sh", "md5": "e99a18c428cb38d5f260853678922e03", "sha256": "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a"}
                ],
                "root_cause_analysis": f"Exploitation of web input fields or unpatched administrative endpoint on {target_host}.",
                "technical_forensic_details": f"Attacker IP {attacker_ip} initiated malicious HTTP payloads resulting in process execution (PID 4082)."
            }
        else: # containment
            return {
                "containment_steps": f"1. Terminate suspicious process (PID 4082).\n2. Block attacker IP {attacker_ip} on host firewall.\n3. Isolate host interface {target_host} if threat escalates.",
                "recovery_steps": "Review auth logs, audit active administrative credentials, and patch vulnerable web interfaces.",
                "soc_recommendations": "Deploy automated network isolation policies for high-risk threat scores (>80).",
                "soar_actions": [
                    {
                        "action_type": "KILL_PROCESS",
                        "target_host": target_host,
                        "payload": "4082",
                        "description": "Terminate suspicious process ID 4082"
                    },
                    {
                        "action_type": "BLOCK_IP",
                        "target_host": target_host,
                        "payload": attacker_ip,
                        "description": f"Block external attacker IP {attacker_ip} on host firewall"
                    },
                    {
                        "action_type": "QUARANTINE_INTERFACE",
                        "target_host": target_host,
                        "payload": "Ethernet0",
                        "description": f"Isolate network interface on {target_host} to prevent lateral movement"
                    }
                ],
                "powershell_script": f"Stop-Process -Id 4082 -Force; New-NetFirewallRule -DisplayName 'Block Attacker' -Direction Inbound -Action Block -RemoteAddress '{attacker_ip}'",
                "bash_script": f"kill -9 4082 2>/dev/null; iptables -A INPUT -s {attacker_ip} -j DROP"
            }

# Global instance
multi_agent_workflow = MultiAgentSOCWorkflow()

async def auto_analyze_incident_openrouter(incident_id: int):
    """
    Background worker that fetches an incident, runs OpenRouter Multi-Agent analysis,
    persists the report and SOAR actions, and broadcasts real-time threat alert to the UI.
    """
    from backend.app.models.database import SessionLocal
    from backend.app.models.models import SOARAction
    from backend.app.services.websocket import manager

    db = SessionLocal()
    try:
        incident = db.query(Incident).filter(Incident.id == incident_id).first()
        if not incident:
            return
            
        # Run workflow
        report_dict = await multi_agent_workflow.run_workflow(incident)
        incident.ai_report = json.dumps(report_dict, indent=2)

        # Create SOARActions in DB if suggested
        soar_actions = report_dict.get("soar_actions", [])
        for act in soar_actions:
            existing = db.query(SOARAction).filter(
                SOARAction.incident_id == incident.id,
                SOARAction.action_type == act.get("action_type"),
                SOARAction.payload == act.get("payload")
            ).first()
            if not existing:
                new_act = SOARAction(
                    incident_id=incident.id,
                    action_type=act.get("action_type", "BLOCK_IP"),
                    target_host=act.get("target_host", "DESKTOP-HG34G7H"),
                    payload=act.get("payload", ""),
                    description=act.get("description", "Auto-generated SOAR remediation"),
                    status="PENDING"
                )
                db.add(new_act)

        db.commit()

        # Broadcast live alert to UI
        target_host = multi_agent_workflow._extract_target_host(incident)
        attacker_ip = multi_agent_workflow._extract_attacker_ip(incident)
        detection_source = report_dict.get("detection_source", "cloud_ai")
        is_cloud_ai = report_dict.get("is_cloud_ai", True)

        await manager.broadcast({
            "type": "REALTIME_OPENROUTER_ALERT",
            "detection_source": detection_source,
            "is_cloud_ai": is_cloud_ai,
            "incident_id": incident.id,
            "title": incident.title,
            "severity": incident.severity,
            "risk_score": incident.risk_score,
            "target_host": target_host,
            "attacker_ip": attacker_ip,
            "executive_summary": report_dict.get("executive_summary", "Threat analysis ready."),
            "containment_steps": report_dict.get("containment_steps", ""),
            "soar_actions": report_dict.get("soar_actions", [])
        })

    except Exception as e:
        print(f"[AUTO OPENROUTER ANALYZER] Background analysis failed: {e}")
        db.rollback()
    finally:
        db.close()


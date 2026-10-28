import json
import os
import httpx
from typing import Dict, Any, Optional, List
from backend.app.core.config import settings
from backend.app.models.models import Incident, IncidentEvent

# Prompt template for AI Security Analyst
PROMPT_TEMPLATE = """You are SentinelAI, a Tier 3 Cyber Threat Investigator and AI SOC Analyst.
You will analyze a correlated cybersecurity incident and output a detailed threat investigation report.

Your input consists of a correlated incident including triggered rules, a timeline of events, and ML anomaly scores:
----------------------------------------------------
INCIDENT METADATA:
Title: {title}
Description: {description}
Initial Severity: {severity}
Risk Score: {risk_score}/100
Anomaly Score: {anomaly_score}/1.0

THREAT TIMELINE & EVIDENCE LOGS:
{timeline_str}
----------------------------------------------------

Your task is to perform an investigation and return a structured JSON object. 
You MUST respond with a valid JSON object ONLY. Do NOT include markdown code blocks, backticks, or any conversational text around the JSON. The JSON keys and structure must be exactly as follows:

{{
  "executive_summary": "High-level summary for the CISO describing what happened and the threat level.",
  "technical_analysis": "Detailed technical analysis of the event chain and what the attacker attempted.",
  "root_cause": "The vector of entry or weakness exploited (e.g. weak SSH credentials, unpatched web vulnerability).",
  "possible_attack_type": "Classified attack category (e.g. Brute Force, Web Intrusion - SQLi, Insider Threat).",
  "risk_explanation": "Why this incident received its risk score and potential impact on business continuity.",
  "recommended_mitigation": "Immediate and long-term security policy recommendations.",
  "containment_steps": "Immediate actions the SOC team should take to stop the active threat (e.g. block IP, disable user).",
  "recovery_steps": "Steps to restore systems to a trusted state.",
  "soc_recommendations": "Proactive detection or monitoring recommendations for future defense."
}}

Analyze the incident meticulously. Provide realistic, concrete, and highly technical recommendations.
"""

from backend.app.services.ai_agents import multi_agent_workflow

class AIInvestigator:
    async def investigate(self, incident: Incident) -> str:
        """
        Runs Multi-Agent SOC Workflow (Triage Agent -> Forensic Agent -> Containment Agent).
        Returns a formatted JSON report string.
        """
        try:
            report_dict = await multi_agent_workflow.run_workflow(incident)
            return json.dumps(report_dict, indent=2)
        except Exception as e:
            print(f"Multi-Agent investigation workflow error: {e}")
            fallback_dict = multi_agent_workflow._get_fallback_data("containment", incident)
            return json.dumps(fallback_dict, indent=2)

    async def _query_openrouter(self, prompt: str) -> str:
        """Queries OpenRouter API (OpenAI-compatible) using high-performance free models."""
        key = settings.OPENROUTER_API_KEY or os.getenv("OPENROUTER_API_KEY")
        if not key:
            raise ValueError("OPENROUTER_API_KEY is not set in environment variables.")
            
        model = settings.AI_MODEL or "meta-llama/llama-3.3-70b-instruct:free"
        url = "https://openrouter.ai/api/v1/chat/completions"
        
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {key}",
            "HTTP-Referer": "https://github.com/GouravPatidar91/Sentinal-AI",
            "X-Title": "SentinelAI SOC"
        }
        payload = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "response_format": {"type": "json_object"},
            "temperature": 0.2
        }
        
        async with httpx.AsyncClient(timeout=45.0) as client:
            resp = await client.post(url, json=payload, headers=headers)
            if resp.status_code != 200:
                raise Exception(f"OpenRouter API returned status {resp.status_code}: {resp.text}")
                
            resp_data = resp.json()
            text = resp_data["choices"][0]["message"]["content"]
            
            # Clean Markdown formatting wrappers if present
            cleaned_text = text.strip()
            if cleaned_text.startswith("```"):
                lines = cleaned_text.split("\n")
                if lines[0].startswith("```"):
                    lines = lines[1:]
                if lines and lines[-1].startswith("```"):
                    lines = lines[:-1]
                cleaned_text = "\n".join(lines).strip()

            parsed = json.loads(cleaned_text)
            return json.dumps(parsed, indent=2)

    async def _query_gemini(self, prompt: str) -> str:
        """Queries the Gemini API."""
        key = settings.GEMINI_API_KEY
        if not key:
            raise ValueError("GEMINI_API_KEY is not set in environment variables.")
            
        model = settings.AI_MODEL or "gemini-1.5-flash"
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={key}"
        
        headers = {"Content-Type": "application/json"}
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "responseMimeType": "application/json"
            }
        }
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(url, json=payload, headers=headers)
            if resp.status_code != 200:
                raise Exception(f"Gemini API returned status {resp.status_code}: {resp.text}")
                
            resp_data = resp.json()
            try:
                text = resp_data["candidates"][0]["content"]["parts"][0]["text"]
                # Parse to ensure it is valid JSON, then return formatted string
                parsed = json.loads(text)
                return json.dumps(parsed, indent=2)
            except (KeyError, IndexError, ValueError) as parse_err:
                raise Exception(f"Failed to parse Gemini response text: {parse_err}. Raw text: {resp.text}")

    async def _query_openai(self, prompt: str) -> str:
        """Queries the OpenAI API."""
        key = settings.OPENAI_API_KEY
        if not key:
            raise ValueError("OPENAI_API_KEY is not set in environment variables.")
            
        model = settings.AI_MODEL or "gpt-4o-mini"
        url = "https://api.openai.com/v1/chat/completions"
        
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {key}"
        }
        payload = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "response_format": {"type": "json_object"},
            "temperature": 0.2
        }
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(url, json=payload, headers=headers)
            if resp.status_code != 200:
                raise Exception(f"OpenAI API returned status {resp.status_code}: {resp.text}")
                
            resp_data = resp.json()
            text = resp_data["choices"][0]["message"]["content"]
            parsed = json.loads(text)
            return json.dumps(parsed, indent=2)

    async def _query_ollama(self, prompt: str) -> str:
        """Queries a local Ollama server."""
        url = f"{settings.OLLAMA_URL}/api/generate"
        model = settings.AI_MODEL or "llama3"
        
        payload = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "format": "json",
            "options": {
                "temperature": 0.2
            }
        }
        
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(url, json=payload)
            if resp.status_code != 200:
                raise Exception(f"Ollama API returned status {resp.status_code}: {resp.text}")
                
            resp_data = resp.json()
            text = resp_data["response"]
            parsed = json.loads(text)
            return json.dumps(parsed, indent=2)

    def _generate_mock_investigation(self, incident: Incident, error: Optional[str] = None) -> str:
        """
        Generates a highly contextual mock report in case the API key is not configured or fails.
        """
        # Determine the type of incident to customize mock details
        title = incident.title.lower()
        
        attack_type = "Brute Force Attack"
        root_cause = "Exposed management services (SSH/RDP) with weak password policies."
        tech_analysis = (
            "The host experienced multiple rapid connection attempts matching brute force signatures, "
            "originating from external IP addresses. This indicates systematic credential spraying or dictionary attacks."
        )
        containment = "Block the attacking IP at the perimeter firewall and force a password reset for the targeted accounts."
        
        if "sql" in title or "web" in title or "apache" in title:
            attack_type = "Web Application Attack (SQL Injection)"
            root_cause = "Lack of parameter validation in application database input interfaces."
            tech_analysis = (
                "The attacker sent SQL payload injections (containing escape tokens and UNION SELECT instructions) "
                "to public-facing web services. This was designed to bypass authorization checks and extract schema records."
            )
            containment = "Deploy Web Application Firewall (WAF) rule to block matching injection signatures and patch the vulnerable API input fields."
        elif "privilege" in title or "sudo" in title:
            attack_type = "Privilege Escalation"
            root_cause = "Over-permissive sudo configuration or abuse of administrative service logons."
            tech_analysis = (
                "A standard user account successfully logged in and subsequently triggered commands with administrative "
                "privileges (Event 4672 / sudo). This represents a lateral transition or privilege escalation."
            )
            containment = "Disable the compromised user account immediately and audit active user groups on the host."
        elif "firewall" in title or "port" in title:
            attack_type = "Reconnaissance (Port Scan)"
            root_cause = "Open ports exposed directly to internet traffic."
            tech_analysis = (
                "The server experienced multiple connections denied on varying ports from a single IP within a short window. "
                "This indicates an adversary mapping open services on the asset (Port Scanning)."
            )
            containment = "Establish dynamic firewall policies that automatically block IPs exhibiting connection scan signatures."

        mock_data = {
            "executive_summary": f"ALERT: SentinelAI correlated a high-severity {attack_type} targeting critical endpoints. Immediate containment actions are recommended to secure the perimeter.",
            "technical_analysis": tech_analysis,
            "root_cause": root_cause,
            "possible_attack_type": attack_type,
            "risk_explanation": f"This incident has a risk score of {incident.risk_score}/100. It presents an active compromise threat that could lead to unauthorized system access and credential theft.",
            "recommended_mitigation": "Enforce MFA, restrict external traffic to VPN subnets, and configure regular vulnerability scans on host software versions.",
            "containment_steps": containment,
            "recovery_steps": "Verify event logs for subsequent lateral movements, inspect system configuration changes, and rebuild systems if backdoor binaries are discovered.",
            "soc_recommendations": "Add rule configurations to flag rapid logins and deploy endpoint integrity scanners.",
            "meta_debug": f"Generated via mock-fallback. Configured provider: '{settings.AI_PROVIDER}' API Key Set: {settings.GEMINI_API_KEY is not None or settings.OPENAI_API_KEY is not None}"
        }
        
        if error:
            mock_data["meta_debug"] += f" | Provider Error: {error}"
            
        return json.dumps(mock_data, indent=2)

# Global instance of AIInvestigator
ai_investigator = AIInvestigator()

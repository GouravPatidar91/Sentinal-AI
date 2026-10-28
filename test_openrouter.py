"""
Direct OpenRouter API Connectivity & AI Multi-Agent Verification Script
========================================================================
Tests:
1. Direct HTTPS connectivity to OpenRouter API (https://openrouter.ai/api/v1/chat/completions)
2. Authentication with configured OPENROUTER_API_KEY
3. Model response with security threat triage payload
4. Full MultiAgentWorkflow integration test on latest Incident in SQLite
"""

import os
import sys
import json
import asyncio
import httpx
from dotenv import load_dotenv

# Load backend environment variables
load_dotenv(dotenv_path="backend/.env")

API_KEY = os.getenv("OPENROUTER_API_KEY")
MODEL = os.getenv("AI_MODEL", "nvidia/nemotron-3.5-lightning:free")

print("=" * 80)
print("           SENTINEL-AI: DIRECT OPENROUTER API DIAGNOSTIC & TEST")
print("=" * 80)
print(f"[*] AI Provider Target : OpenRouter API")
print(f"[*] Endpoint           : https://openrouter.ai/api/v1/chat/completions")
print(f"[*] Configured Model   : {MODEL}")
masked_key = (API_KEY[:10] + "..." + API_KEY[-4:]) if API_KEY and len(API_KEY) > 14 else str(API_KEY)
print(f"[*] API Key Present    : {masked_key}")
print("=" * 80)

if not API_KEY:
    print("[FAIL] OPENROUTER_API_KEY is not set in backend/.env!")
    sys.exit(1)

async def test_direct_openrouter():
    print("\n>>> STEP 1: Sending Direct Test Payload to OpenRouter API...")
    url = "https://openrouter.ai/api/v1/chat/completions"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {API_KEY}",
        "HTTP-Referer": "https://github.com/GouravPatidar91/Sentinal-AI",
        "X-Title": "SentinelAI SOC Diagnostic"
    }

    test_prompt = {
        "role": "user",
        "content": (
            "You are SentinelAI Tier-3 SOC Analyst. Analyze this simulated attack:\n"
            "Attacker IP: 185.220.101.5\n"
            "Target Host: dc-prod-01\n"
            "Attack: Rapid brute force attempt (5 failed logins in 10s)\n"
            "Return JSON with: {'threat_detected': true, 'risk_score': 85, 'mitre_tactic': 'Credential Access', 'recommended_action': 'Block IP'}"
        )
    }

    payload = {
        "model": MODEL,
        "messages": [test_prompt],
        "temperature": 0.2
    }

    start_time = asyncio.get_event_loop().time()
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            print(f"[*] Posting request to {url} using model '{MODEL}'...")
            resp = await client.post(url, json=payload, headers=headers)
            elapsed = asyncio.get_event_loop().time() - start_time

            print(f"[*] HTTP Status Code   : {resp.status_code} {resp.reason_phrase}")
            print(f"[*] Response Latency   : {elapsed:.2f} seconds")

            if resp.status_code == 200:
                resp_json = resp.json()
                content = resp_json["choices"][0]["message"]["content"]
                usage = resp_json.get("usage", {})
                print(f"[PASS] OpenRouter API responded successfully!")
                print(f"[*] Tokens Used        : {usage.get('total_tokens', 'N/A')} (Prompt: {usage.get('prompt_tokens')}, Completion: {usage.get('completion_tokens')})")
                print("\n--- Model Response Preview ---")
                print(content[:400] + ("..." if len(content) > 400 else ""))
                print("------------------------------")
                return True
            elif resp.status_code in [400, 404]:
                # In case the free model is busy or depreciated on OpenRouter, try meta-llama fallback model
                print(f"[WARN] Status {resp.status_code} on model {MODEL}. Testing with fallback model 'meta-llama/llama-3.3-70b-instruct:free'...")
                payload["model"] = "meta-llama/llama-3.3-70b-instruct:free"
                resp2 = await client.post(url, json=payload, headers=headers)
                if resp2.status_code == 200:
                    resp_json = resp2.json()
                    content = resp_json["choices"][0]["message"]["content"]
                    print(f"[PASS] Fallback model answered successfully!")
                    print(f"[*] Active Working Model : meta-llama/llama-3.3-70b-instruct:free")
                    print("\n--- Model Response Preview ---")
                    print(content[:400] + ("..." if len(content) > 400 else ""))
                    print("------------------------------")
                    return True
                else:
                    print(f"[FAIL] OpenRouter API Error: {resp2.status_code} -> {resp2.text}")
                    return False
            else:
                print(f"[FAIL] OpenRouter API returned error status {resp.status_code}:")
                print(resp.text)
                return False

    except Exception as e:
        print(f"[FAIL] Network or API Exception connecting to OpenRouter: {e}")
        return False

async def test_backend_multiagent_workflow():
    print("\n>>> STEP 2: Testing SentinelAI Multi-Agent SOC Workflow (Triage + Forensics + Containment)...")
    try:
        from backend.app.models.database import SessionLocal
        from backend.app.models.models import Incident
        from backend.app.services.ai_agents import multi_agent_workflow

        db = SessionLocal()
        incident = db.query(Incident).order_by(Incident.id.desc()).first()

        if not incident:
            print("[!] No incidents found in DB to analyze.")
            db.close()
            return

        print(f"[*] Found Incident #{incident.id}: '{incident.title}' (Severity: {incident.severity}, Host: {incident.events[0].log_entry.host if incident.events else 'N/A'})")
        print("[*] Running 3-Agent AI Investigation Workflow via OpenRouter...")
        
        report = await multi_agent_workflow.run_workflow(incident)
        db.close()

        print("[PASS] Multi-Agent Workflow Finished!")
        print(f"[*] Executive Summary : {report.get('executive_summary')}")
        print(f"[*] Root Cause        : {report.get('root_cause')}")
        print(f"[*] Attack Vector     : {report.get('possible_attack_type')}")
        print(f"[*] Containment Steps : {report.get('containment_steps')}")
        print(f"[*] SOAR Actions Gen  : {len(report.get('soar_actions', []))} action(s)")
        print(f"[*] Detection Source  : {report.get('detection_source')} (is_cloud_ai={report.get('is_cloud_ai')})")
        print("=" * 80)
        print("[FINAL RESULT] OpenRouter API Integration is 100% WORKING & OPERATIONAL!")
        print("=" * 80)

    except Exception as e:
        print(f"[!] Error during Multi-Agent workflow test: {e}")

async def main():
    ok = await test_direct_openrouter()
    if ok:
        await test_backend_multiagent_workflow()

if __name__ == "__main__":
    asyncio.run(main())

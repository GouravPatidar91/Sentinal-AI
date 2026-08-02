from typing import Dict, Any, Optional

# MITRE ATT&CK database representation for SentinelAI
MITRE_TECHNIQUES = {
    "T1110": {
        "technique": "Brute Force",
        "tactic": "Credential Access",
        "description": "Adversaries may use brute force techniques to attempt access to accounts when passwords or pins are not known.",
        "mitigation": "Implement account lockout policies after a threshold of failed attempts, enforce strong multi-factor authentication (MFA), and monitor login logs for high-frequency failures."
    },
    "T1078": {
        "technique": "Valid Accounts",
        "tactic": "Privilege Escalation",
        "description": "Adversaries may obtain and abuse credentials of existing accounts, obtaining access with administrative privileges.",
        "mitigation": "Enforce principle of least privilege, audit account permissions regularly, use unique passwords for admin accounts, and monitor for administrative access from unusual locations or hours."
    },
    "T1562.001": {
        "technique": "Impair Defenses: Disable or Modify Tools",
        "tactic": "Defense Evasion",
        "description": "Adversaries may modify components of security tools or security policy configurations to avoid detection.",
        "mitigation": "Restrain permission to modify audit policies to highly restricted admin roles, deploy tamper protection for local security agents, and centralize logs immediately."
    },
    "T1136.001": {
        "technique": "Create Account: Local Account",
        "tactic": "Persistence",
        "description": "Adversaries may create local accounts to maintain access to victim systems.",
        "mitigation": "Limit account creation permissions, audit the local users group regularly, and alert on any new user creations on endpoints."
    },
    "T1190": {
        "technique": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "Adversaries may attempt to exploit a weakness in an Internet-facing computer or program to gain access to a system.",
        "mitigation": "Keep public services updated (patching), employ a Web Application Firewall (WAF) to block SQLi/XSS payloads, and perform regular security audits of web code."
    },
    "T1046": {
        "technique": "Network Service Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to get a listing of services running on target hosts to identify potential vulnerabilities.",
        "mitigation": "Disable unnecessary services, restrict access to management ports via local firewalls, and configure network intrusion detection to alert on port scanning behavior."
    },
    "T1048": {
        "technique": "Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration",
        "description": "Adversaries may steal data by transferring it over a different protocol than the main command and control channel, such as uploading bulk traffic over HTTPS/DNS.",
        "mitigation": "Implement network rate-limiting, analyze traffic volumes for outliers, and enforce data loss prevention (DLP) agents."
    },
    "T1090": {
        "technique": "Proxy",
        "tactic": "Command and Control",
        "description": "Adversaries may use proxies to direct network traffic through intermediary hosts to mask the source of their connection.",
        "mitigation": "Block known malicious IP lists (threat intelligence feeds), enforce geographical IP filters on critical assets, and inspect TLS certificates."
    },
    "T1203": {
        "technique": "Exploitation for Client Execution",
        "tactic": "Execution",
        "description": "Adversaries may exploit vulnerabilities to run unauthorized code on target assets.",
        "mitigation": "Implement application whitelisting, configure sandboxing for execution environments, and use modern endpoint detection response (EDR) software."
    },
    "T1083": {
        "technique": "File and Directory Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may enumerate files and directories to find sensitive information or understand system architecture.",
        "mitigation": "Enforce strict DACLs/ACLs on sensitive files, audit access to configurations, and limit folder traverse permissions."
    }
}

def get_mitre_details(technique_id: str) -> Dict[str, str]:
    """
    Returns technique title, tactic, description, and mitigation for a given technique ID.
    """
    details = MITRE_TECHNIQUES.get(technique_id)
    if details:
        return {
            "technique_id": technique_id,
            **details
        }
    return {
        "technique_id": technique_id,
        "technique": "Unknown Technique",
        "tactic": "Unknown Tactic",
        "description": "No MITRE ATT&CK details mapped for this technique ID.",
        "mitigation": "Audit system logs, restrict administrative access, and inspect anomalous activity."
    }

import React, { useState } from "react";
import { ListRestart, Play, HelpCircle } from "lucide-react";
import { useNotifications } from "../context/NotificationContext";
import { API_BASE } from "../config/api";

interface Scenario {
  type: string;
  name: string;
  category: string;
  description: string;
  timeline: string[];
}

export const Simulator: React.FC = () => {
  const { triggerNotification } = useNotifications();
  const [loadingType, setLoadingType] = useState<string | null>(null);

  const scenarios: Scenario[] = [
    {
      type: "brute_force",
      name: "RDP/SSH Brute Force",
      category: "Credential Access",
      description: "Generates 5 authentication failure logs (Event ID 4625) followed by a successful logon (Event ID 4624) from an external IP.",
      timeline: ["5 Failed Logins from 185.220.101.44", "1 Successful Login", "Correlates to Brute Force Incident"]
    },
    {
      type: "sql_injection",
      name: "SQL Injection Payload",
      category: "Initial Access",
      description: "Generates Apache web access logs containing query string SQL injection characters (UNION SELECT).",
      timeline: ["HTTP GET /index.php?id=1%20UNION%20SELECT...", "Apache SQL Injection Alert", "Critical Severity Incident Generated"]
    },
    {
      type: "xss",
      name: "Cross-Site Scripting (XSS)",
      category: "Initial Access",
      description: "Generates web logs targets with script execution injections in URL query fields.",
      timeline: ["HTTP GET /search.php?query=%3Cscript%3E...", "Apache XSS Rule Triggered", "Medium Severity Alert"]
    },
    {
      type: "port_scan",
      name: "Network Port Scan Mapping",
      category: "Discovery",
      description: "Generates a burst of firewall denied connection packets to multiple standard TCP ports within 10 seconds.",
      timeline: ["10 Denied Packets on Ports 21-8080", "Firewall Deny Rule Alerts", "Correlates to Port Scan Discovery"]
    },
    {
      type: "privilege_escalation",
      name: "System Privilege Escalation",
      category: "Privilege Escalation",
      description: "Generates a normal user login log immediately followed by an administrative privilege assignment audit (Event ID 4672).",
      timeline: ["Logon Success for analyst user", "Special Privilege Assigned (SeDebugPrivilege)", "Escalates Incident Risk Score"]
    },
    {
      type: "insider_threat",
      name: "Anomalous Insider Threat",
      category: "Multiple Tactics",
      description: "Simulates service credential login at 2:00 AM (anomalous working hours) followed by large outbound file uploads (Exfiltration).",
      timeline: ["Logon at 02:00 AM (Anomaly Score: 0.85)", "Outbound connection LEN=2500 bytes", "Correlates to Insider Threat Exfiltration"]
    },
    {
      type: "malware",
      name: "PowerShell Malware Execution",
      category: "Defense Evasion / Execution",
      description: "Disables local system audit policies (Event 4719) and triggers a PowerShell web client download execution command.",
      timeline: ["Audit Policy Removed", "Powershell IEX (New-Object Net.WebClient)...", "Critical Security Alarm Broadcaster"]
    }
  ];

  const handleTriggerSimulation = async (type: string) => {
    setLoadingType(type);
    try {
      const resp = await fetch(`${API_BASE}/api/simulation/trigger`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          attack_type: type,
          host: "corp-dc-server01",
          target_ip: "10.0.0.12",
          attacker_ip: "185.220.101.44"
        })
      });

      if (resp.ok) {
        triggerNotification(
          "Simulation Initiated",
          `Injecting logs for '${type}' threat vector. Pipeline updating.`,
          "INFO"
        );
      } else {
        throw new Error("Simulation endpoint returned failure");
      }
    } catch (err) {
      console.error(err);
      triggerNotification(
        "Simulation Failed",
        "Failed to contact the backend simulator service.",
        "CRITICAL"
      );
    } finally {
      setLoadingType(null);
    }
  };

  return (
    <div className="flex-1 p-8 space-y-8 overflow-y-auto h-screen max-w-[calc(100vw-16rem)]">
      
      {/* Title */}
      <div className="flex justify-between items-center border-b border-darkBorder pb-6">
        <div>
          <h2 className="text-3xl font-extrabold text-slate-100 tracking-wide flex items-center gap-3">
            <ListRestart className="w-8 h-8 text-indigo-400" />
            ATTACK PLAYBOOK SIMULATOR
          </h2>
          <p className="text-sm text-slate-500 mt-1">
            Trigger simulated security incidents to evaluate parser, ML, rules, and correlation engines
          </p>
        </div>
      </div>

      {/* Simulator Info */}
      <div className="p-4 rounded-xl bg-slate-900/60 border border-darkBorder flex gap-3 text-xs text-slate-400 max-w-3xl leading-relaxed">
        <HelpCircle className="w-5 h-5 text-indigo-400 shrink-0" />
        <div>
          <strong className="text-slate-200 block mb-1">How it works</strong>
          Each simulator scenario sequentially injects realistic raw syslog/event records into the logs ingestion endpoint. The SentinelAI detection framework will dynamically parse fields, score ML anomalies, inspect rules, and correlate the sequence of events into active SOC incidents. Open the <strong>Dashboard</strong> or <strong>Incident Queue</strong> in another window to see updates occur in real-time.
        </div>
      </div>

      {/* Grid of Scenarios */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {scenarios.map((scen) => (
          <div key={scen.type} className="glass-card rounded-xl p-6 border flex flex-col justify-between h-72">
            <div className="space-y-3">
              <div className="flex justify-between items-center">
                <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">{scen.category}</span>
                <span className="bg-indigo-950/40 text-indigo-400 border border-indigo-900/40 text-[9px] px-2 py-0.5 rounded-full font-bold uppercase">
                  Scenario
                </span>
              </div>
              <h3 className="text-lg font-bold text-slate-200">{scen.name}</h3>
              <p className="text-xs text-slate-400 leading-normal">{scen.description}</p>
              
              {/* Timeline graphic helper */}
              <div className="pt-2">
                <span className="text-[9px] font-bold text-slate-500 uppercase tracking-wider block mb-2">Simulated steps:</span>
                <div className="flex items-center gap-1.5 flex-wrap">
                  {scen.timeline.map((step, i) => (
                    <React.Fragment key={step}>
                      <span className="bg-slate-900/80 border border-darkBorder rounded text-[9px] text-slate-400 px-2 py-1 leading-none">
                        {step}
                      </span>
                      {i < scen.timeline.length - 1 && <span className="text-[9px] text-slate-700 font-bold">→</span>}
                    </React.Fragment>
                  ))}
                </div>
              </div>
            </div>

            <button
              onClick={() => handleTriggerSimulation(scen.type)}
              disabled={loadingType !== null}
              className="mt-6 w-full bg-indigo-600 hover:bg-indigo-500 active:bg-indigo-700 disabled:opacity-50 text-white rounded-lg py-2.5 text-xs font-bold tracking-wider flex items-center justify-center gap-2 shadow-lg shadow-indigo-500/10 hover:shadow-indigo-500/25 transition-all cursor-pointer"
            >
              <Play className="w-3.5 h-3.5 fill-current" />
              {loadingType === scen.type ? "Injecting logs..." : "Execute Simulation"}
            </button>
          </div>
        ))}
      </div>

    </div>
  );
};
export default Simulator;

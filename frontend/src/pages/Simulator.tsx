import React, { useState } from "react";
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
    <div className="flex-1 min-w-0 p-6 space-y-6 overflow-y-auto h-screen bg-[#000000] text-[#66ff66] font-mono select-text">
      
      {/* Top Command Session Bar & Title */}
      <div className="border border-[#255325] p-4 bg-[#000000]">
        <div className="flex items-center justify-between text-[13px] border-b border-[#255325] pb-2 mb-3">
          <div className="flex items-center gap-2">
            <span className="text-[#255325] select-none">[00]</span>
            <span className="text-[#66ff66]">
              <span className="text-[#58ca58]">sentinel@soc:~$</span> sentinel --simulate attack-scenario --inject telemetry --target live-pipeline
            </span>
          </div>
          <span className="px-2 py-0.5 bg-[#66ff66] text-[#000000] font-medium text-[11px] select-none">
            [ CHANNEL: 05 // ATTACK_SIM ]
          </span>
        </div>

        <div className="flex flex-col md:flex-row md:items-center justify-between gap-2">
          <div>
            <h1 className="text-[22px] sm:text-[26px] font-medium text-[#ffffff] tracking-tight uppercase">
              Adversary Attack Simulator // Threat Injector
            </h1>
            <p className="text-[14px] text-[#58ca58] mt-1">
              Inject synthetic multi-stage cyber attack vectors to evaluate normalization, ML anomaly scoring, and SOAR response.
            </p>
          </div>
          <div className="text-[12px] text-[#58ca58] text-right font-mono shrink-0">
            <div>TARGET_ENDPOINT: <span className="text-[#ffffff]">corp-dc-server01</span></div>
            <div>STATUS: <span className="text-[#66ff66]">READY_TO_INJECT</span></div>
          </div>
        </div>
      </div>

      {/* Simulator Architectural Info Callout */}
      <div>
        <div className="text-[12px] text-[#255325] mb-2 select-none">
          [01] $ cat /etc/sentinel/simulator.conf
        </div>

        <div className="border border-[#255325] p-4 bg-[#000000] text-[12px] text-[#58ca58] space-y-2">
          <div className="text-[#ffffff] font-medium">
            // HOW THE SENTINELAI SIMULATION ENGINE WORKS:
          </div>
          <p className="leading-relaxed">
            Each scenario sequentially transmits raw Windows Security EventLogs, Linux auth.log, or Apache access entries to the active WebSocket and database ingestion pipeline. Field normalization, unsupervised Isolation Forest anomaly scoring, Sigma correlation, and OpenRouter AI summaries will execute automatically.
          </p>
          <div className="text-[11px] text-[#255325] pt-1 border-t border-[#255325]">
            TIP: Keep the Dashboard or Incident Queue visible in a split window to observe real-time telemetry reaction.
          </div>
        </div>
      </div>

      {/* Scenarios Catalog Grid */}
      <div>
        <div className="text-[12px] text-[#255325] mb-2 select-none">
          [02] $ sentinel --list scenarios --count {scenarios.length}
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {scenarios.map((scen, idx) => {
            const num = (idx + 1).toString().padStart(2, "0");
            const isInjecting = loadingType === scen.type;

            return (
              <div 
                key={scen.type} 
                className="border border-[#255325] hover:border-[#66ff66] p-5 bg-[#000000] flex flex-col justify-between transition-colors"
              >
                <div className="space-y-3">
                  <div className="flex justify-between items-center border-b border-[#255325] pb-2 text-[11px]">
                    <span className="text-[#255325] font-mono font-medium">
                      VECTOR [{num}] // [{scen.category.toUpperCase()}]
                    </span>
                    <span className="text-[#66ff66] border border-[#255325] px-1.5 py-0.5 select-none">
                      [TTP_PLAYBOOK]
                    </span>
                  </div>

                  <div>
                    <h3 className="font-medium text-[#ffffff] text-[15px]">
                      {scen.name}
                    </h3>
                    <p className="text-[12px] text-[#58ca58] mt-1 leading-relaxed">
                      {scen.description}
                    </p>
                  </div>

                  {/* Execution Timeline Steps */}
                  <div className="pt-2">
                    <span className="text-[10px] text-[#255325] uppercase tracking-wider block mb-1.5">
                      // EXECUTION_SEQUENCE:
                    </span>
                    <div className="space-y-1">
                      {scen.timeline.map((step) => (
                        <div key={step} className="flex items-center gap-2 text-[11px] text-[#58ca58]">
                          <span className="text-[#255325] select-none">&gt;_</span>
                          <span className="truncate">{step}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>

                <div className="mt-5 pt-3 border-t border-[#255325]">
                  <button
                    onClick={() => handleTriggerSimulation(scen.type)}
                    disabled={loadingType !== null}
                    className={`w-full py-2 px-3 text-[12px] font-medium transition-colors select-none text-center cursor-pointer ${
                      isInjecting
                        ? "bg-[#255325] text-[#ffffff] cursor-wait"
                        : "bg-[#66ff66] text-[#000000] hover:bg-[#ffffff]"
                    }`}
                  >
                    {isInjecting 
                      ? "[ INJECTING_ATTACK_TELEMETRY... █ ]" 
                      : "[ ⚡ LAUNCH_ATTACK_VECTOR ↵ ]"
                    }
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      </div>

    </div>
  );
};

export default Simulator;

import React, { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import { useNotifications } from "../context/NotificationContext";
import { useAuth } from "../context/AuthContext";
import { API_BASE, WS_BASE } from "../config/api";
import { formatDateTime } from "../utils/time";

interface Rule {
  name: string;
  description: string;
  severity: string;
  tactic: string;
  technique: string;
}

interface LogEntry {
  id: number;
  timestamp: string;
  host: string;
  source: string;
  log_type: string;
  severity: string;
  username: string | null;
  src_ip: string | null;
  dst_ip: string | null;
  process: string | null;
  message: string;
  raw_log: string;
}

interface IncidentEvent {
  id: number;
  timestamp: string;
  description: string;
  order_index: number;
  rule: Rule | null;
  log_entry: LogEntry;
}

interface SOARAction {
  id: number;
  action_type: string;
  target_host: string;
  payload: string;
  description: string;
  status: string;
  executed_by_id: number | null;
  output: string | null;
  created_at: string;
  executed_at: string | null;
}

interface IncidentDetail {
  id: number;
  title: string;
  description: string;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  status: string;
  risk_score: number;
  anomaly_score: number;
  created_at: string;
  updated_at: string;
  assigned_to_id: number | null;
  ai_report: string | null;
  events: IncidentEvent[];
  soar_actions?: SOARAction[];
}

export const Investigation: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const { triggerNotification } = useNotifications();
  const { token } = useAuth();
  const [incident, setIncident] = useState<IncidentDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [aiLoading, setAiLoading] = useState(false);
  const [aiStep, setAiStep] = useState(0);
  const [expandedLogId, setExpandedLogId] = useState<number | null>(null);
  const [analysts, setAnalysts] = useState<any[]>([]);
  const [isExportingPdf, setIsExportingPdf] = useState(false);

  const aiLoadingSteps = [
    "Compiling incident threat vectors...",
    "Correlating MITRE ATT&CK tactics & techniques...",
    "Querying LLM Cognitive Security Engine...",
    "Synthesizing technical analysis & containment plan..."
  ];

  useEffect(() => {
    fetchIncidentDetail();
    fetchAnalysts();
    
    const ws = new WebSocket(`${WS_BASE}/api/ws`);
    
    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        const currentIncidentId = Number(id);
        if (
          (data.type === "NEW_LOG" && data.incident && data.incident.id === currentIncidentId) ||
          (data.type === "INCIDENT_UPDATE" && data.incident && data.incident.id === currentIncidentId)
        ) {
          fetchIncidentDetail();
        }
      } catch (err) {
        console.error("Error parsing WS message in incident detail:", err);
      }
    };
    
    return () => {
      ws.close();
    };
  }, [id, token]);

  const fetchIncidentDetail = async () => {
    setLoading(true);
    const activeToken = token || localStorage.getItem("token");
    try {
      const resp = await fetch(`${API_BASE}/api/incidents/${id}`, {
        headers: { "Authorization": `Bearer ${activeToken}` }
      });
      if (resp.ok) {
        const data = await resp.json();
        setIncident(data);
      }
    } catch (err) {
      console.error("Error loading incident details:", err);
    } finally {
      setLoading(false);
    }
  };

  const fetchAnalysts = async () => {
    setAnalysts([
      { id: 1, username: "admin", role: "admin" },
      { id: 2, username: "analyst", role: "analyst" }
    ]);
  };

  const handleStatusChange = async (newStatus: string) => {
    if (!incident) return;
    try {
      const resp = await fetch(`${API_BASE}/api/incidents/${id}`, {
        method: "PUT",
        headers: { 
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`
        },
        body: JSON.stringify({ status: newStatus })
      });
      if (resp.ok) {
        setIncident(prev => prev ? { ...prev, status: newStatus } : null);
        triggerNotification(
          "Incident Updated",
          `INC-${id} status changed to ${newStatus}`,
          "INFO"
        );
      }
    } catch (err) {
      console.error("Error updating incident status:", err);
    }
  };

  const handleAssigneeChange = async (userIdStr: string) => {
    if (!incident) return;
    const userId = userIdStr ? parseInt(userIdStr) : null;
    try {
      const resp = await fetch(`${API_BASE}/api/incidents/${id}`, {
        method: "PUT",
        headers: { 
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`
        },
        body: JSON.stringify({ assigned_to_id: userId })
      });
      if (resp.ok) {
        setIncident(prev => prev ? { ...prev, assigned_to_id: userId } : null);
        triggerNotification(
          "Incident Assigned",
          `INC-${id} assigned updated.`,
          "INFO"
        );
      }
    } catch (err) {
      console.error("Error assigning incident:", err);
    }
  };

  const handleExportPdf = async () => {
    if (!incident || isExportingPdf) return;
    try {
      setIsExportingPdf(true);
      const resp = await fetch(`${API_BASE}/api/incidents/${incident.id}/pdf`);
      if (!resp.ok) throw new Error("Failed to export PDF");
      const blob = await resp.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `incident_INC_${incident.id}_report.pdf`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
      fetchIncidentDetail();
    } catch (e) {
      console.error("PDF export error:", e);
      window.open(`${API_BASE}/api/incidents/${incident.id}/pdf`, "_blank");
    } finally {
      setIsExportingPdf(false);
    }
  };

  const triggerAIInvestigation = async () => {
    if (!incident) return;
    setAiLoading(true);
    setAiStep(0);
    
    const interval = setInterval(() => {
      setAiStep(prev => (prev < aiLoadingSteps.length - 1 ? prev + 1 : prev));
    }, 1500);

    try {
      const resp = await fetch(`${API_BASE}/api/incidents/${id}/investigate`, {
        method: "POST",
        headers: { "Authorization": `Bearer ${token}` }
      });
      if (resp.ok) {
        const data = await resp.json();
        setIncident(data);
        triggerNotification(
          "AI Investigation Ready",
          "Cognitive investigation report generated by SentinelAI.",
          "INFO"
        );
      }
    } catch (err) {
      console.error("AI Investigation failed:", err);
    } finally {
      clearInterval(interval);
      setAiLoading(false);
    }
  };

  const handleApproveSoarAction = async (actionId: number) => {
    try {
      const resp = await fetch(`${API_BASE}/api/soar/approve/${actionId}`, {
        method: "POST",
        headers: { "Authorization": `Bearer ${token}` }
      });
      if (resp.ok) {
        triggerNotification("SOAR Action Approved", `Remediation command #${actionId} dispatched to target endpoint.`, "HIGH");
        fetchIncidentDetail();
      }
    } catch (err) {
      console.error("Error approving SOAR action:", err);
    }
  };

  const handleCreateAndApproveSoarAction = async (actionType: string, payload: string, description: string) => {
    if (!incident) return;
    const targetHost = incident.events?.find(ev => ev.log_entry?.host && ev.log_entry.host !== "unknown-host")?.log_entry?.host || "Unknown Host";
    try {
      const createResp = await fetch(`${API_BASE}/api/soar/actions`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "Authorization": `Bearer ${token}` },
        body: JSON.stringify({
          incident_id: Number(id),
          action_type: actionType,
          target_host: targetHost,
          payload: payload,
          description: description
        })
      });
      if (createResp.ok) {
        const actionData = await createResp.json();
        await handleApproveSoarAction(actionData.id);
      }
    } catch (err) {
      console.error("Error creating SOAR action:", err);
    }
  };

  const renderAsciiMeter = (val: number, max: number, chars = 8) => {
    const filled = Math.min(chars, Math.max(0, Math.round((val / max) * chars)));
    return "█".repeat(filled) + "░".repeat(chars - filled);
  };

  const getSeverityBadge = (sev: string) => {
    switch (sev?.toUpperCase()) {
      case "CRITICAL":
        return <span className="bg-[#66ff66] text-[#000000] font-bold px-1.5 py-0.5 select-none">[CRITICAL]</span>;
      case "HIGH":
        return <span className="text-[#ffffff] border border-[#66ff66] px-1.5 py-0.5 select-none">[HIGH]</span>;
      case "WARNING":
        return <span className="text-[#66ff66] border border-[#255325] px-1.5 py-0.5 select-none">[WARNING]</span>;
      default:
        return <span className="text-[#58ca58] border border-[#255325] px-1.5 py-0.5 select-none">[INFO]</span>;
    }
  };

  if (loading) {
    return (
      <div className="flex-1 p-8 text-center text-[#58ca58] font-mono text-[13px] bg-[#000000]">
        &gt; Retrieving incident ledger and correlated event chain...
      </div>
    );
  }

  if (!incident) {
    return (
      <div className="flex-1 p-8 text-center space-y-4 font-mono bg-[#000000] text-[#66ff66]">
        <h3 className="text-[18px] text-[#ffffff] font-medium">[ ✕ ] INCIDENT_NOT_FOUND</h3>
        <Link to="/incidents" className="text-[#58ca58] hover:text-[#66ff66] underline">
          [ ← RETURN_TO_INCIDENT_QUEUE ]
        </Link>
      </div>
    );
  }

  let aiReportData: any = null;
  if (incident.ai_report) {
    try {
      aiReportData = JSON.parse(incident.ai_report);
    } catch (e) {
      aiReportData = { executive_summary: incident.ai_report };
    }
  }

  const attackerIp = incident.events?.find(ev => ev.log_entry?.src_ip && ev.log_entry.src_ip !== "-")?.log_entry?.src_ip || "Unknown IP";
  const targetHost = incident.events?.find(ev => ev.log_entry?.host && ev.log_entry.host !== "unknown-host")?.log_entry?.host || "Unknown Host";
  const targetIp = incident.events?.find(ev => ev.log_entry?.dst_ip && ev.log_entry.dst_ip !== "-")?.log_entry?.dst_ip;
  const entryVector = incident.events?.find(ev => ev.rule?.tactic)?.rule?.tactic || "Initial Access";

  return (
    <div className="flex-1 min-w-0 p-6 space-y-6 overflow-y-auto h-screen bg-[#000000] text-[#66ff66] font-mono select-text">
      
      {/* Return Link & Session Header */}
      <div className="flex items-center justify-between text-[12px] border-b border-[#255325] pb-2">
        <Link 
          to="/incidents" 
          className="text-[#58ca58] hover:text-[#000000] hover:bg-[#66ff66] px-2 py-0.5 border border-[#255325] transition-colors select-none"
        >
          [ ← RETURN_TO_INCIDENTS_QUEUE ]
        </Link>
        <span className="text-[#255325]">
          INCIDENT_SESSION: INC-{incident.id} // ACTIVE_CASE
        </span>
      </div>

      {/* Main Incident Dossier Card */}
      <div className="border border-[#255325] p-5 bg-[#000000] flex flex-col md:flex-row justify-between items-start md:items-center gap-6">
        <div className="space-y-2">
          <div className="flex items-center gap-3 text-[12px]">
            <span className="text-[#ffffff] font-medium">INCIDENT #{incident.id}</span>
            {getSeverityBadge(incident.severity)}
            <span className="text-[#58ca58]">
              RISK: <strong className="text-[#66ff66]">[{renderAsciiMeter(incident.risk_score, 100, 8)}] {incident.risk_score}/100</strong>
            </span>
          </div>

          <h1 className="text-[20px] sm:text-[24px] font-medium text-[#ffffff] tracking-tight uppercase">
            {incident.title}
          </h1>

          <div className="flex flex-wrap gap-4 text-[12px] text-[#58ca58]">
            <span>TIMESTAMP: <strong className="text-[#ffffff]">{formatDateTime(incident.created_at)}</strong></span>
            <span>ATTACKER_IP: <strong className="text-[#ffffff]">{attackerIp}</strong></span>
            <span>TARGET_HOST: <strong className="text-[#ffffff]">{targetHost.toUpperCase()}{targetIp ? ` (${targetIp})` : ""}</strong></span>
          </div>
        </div>

        {/* Triage Status & Controls */}
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex flex-col gap-1 text-[11px]">
            <span className="text-[#255325] uppercase">ASSIGNEE:</span>
            <select
              value={incident.assigned_to_id || ""}
              onChange={(e) => handleAssigneeChange(e.target.value)}
              className="bg-[#000000] border border-[#255325] text-[#66ff66] px-2 py-1 text-[11px] outline-none cursor-pointer hover:border-[#66ff66] transition-colors"
            >
              <option value="">[UNASSIGNED]</option>
              {analysts.map(a => (
                <option key={a.id} value={a.id}>[{a.username.toUpperCase()}]</option>
              ))}
            </select>
          </div>

          <div className="flex flex-col gap-1 text-[11px]">
            <span className="text-[#255325] uppercase">STATUS:</span>
            <select
              value={incident.status}
              onChange={(e) => handleStatusChange(e.target.value)}
              className="bg-[#000000] border border-[#255325] text-[#66ff66] px-2 py-1 text-[11px] outline-none cursor-pointer hover:border-[#66ff66] transition-colors"
            >
              <option value="New">[NEW]</option>
              <option value="Investigating">[INVESTIGATING]</option>
              <option value="Contained">[CONTAINED]</option>
              <option value="Resolved">[RESOLVED]</option>
              <option value="Closed">[CLOSED]</option>
            </select>
          </div>

          <button
            onClick={handleExportPdf}
            disabled={isExportingPdf}
            className={`mt-4 px-3 py-1.5 border text-[11px] font-medium transition-colors select-none cursor-pointer ${
              isExportingPdf
                ? "border-[#66ff66] bg-[#66ff66] text-[#000000] animate-pulse"
                : "border-[#255325] text-[#58ca58] hover:text-[#000000] hover:bg-[#66ff66] hover:border-[#66ff66]"
            }`}
          >
            {isExportingPdf ? "[ ⚡ GENERATING AI REPORT & PDF... ]" : "[ ⇩ EXPORT_PDF ↵ ]"}
          </button>
        </div>
      </div>

      {/* Interactive Attack Chain Flow Box */}
      <div>
        <div className="text-[12px] text-[#255325] mb-2 select-none">
          [01] $ sentinel --trace-flow --incident INC-{incident.id}
        </div>

        <div className="border border-[#255325] p-4 bg-[#000000]">
          <div className="border-b border-[#255325] pb-2 mb-3 text-[12px] flex justify-between items-center">
            <span className="text-[#ffffff] font-medium">
              ATTACK_CHAIN_CORRELATION // END-TO-END RECONSTRUCTION
            </span>
            <span className="text-[#58ca58] text-[11px]">
              TTP_VECTOR: {entryVector.toUpperCase()}
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-[12px]">
            <div className="border border-[#255325] p-3 bg-[#000000]">
              <div className="text-[#255325] text-[10px] uppercase">STAGE 01: THREAT_ORIGIN</div>
              <div className="text-[#ffffff] font-bold text-[14px] mt-1">{attackerIp}</div>
              <div className="text-[#58ca58] text-[10px] mt-1">External Ingress Node</div>
            </div>

            <div className="border border-[#255325] p-3 bg-[#000000]">
              <div className="text-[#255325] text-[10px] uppercase">STAGE 02: MITRE_TACTIC</div>
              <div className="text-[#66ff66] font-bold text-[14px] mt-1">{entryVector}</div>
              <div className="text-[#58ca58] text-[10px] mt-1">Rule Signature Match</div>
            </div>

            <div className="border border-[#255325] p-3 bg-[#000000]">
              <div className="text-[#255325] text-[10px] uppercase">STAGE 03: TARGET_ASSET</div>
              <div className="text-[#ffffff] font-bold text-[14px] mt-1">
                {targetHost.toUpperCase()}{targetIp ? ` (${targetIp})` : ""}
              </div>
              <div className="text-[#58ca58] text-[10px] mt-1">Internal Endpoint Monitored</div>
            </div>
          </div>
        </div>
      </div>

      {/* Two-Column Detail Grid: Timeline & Multi-Agent AI SOAR */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Evidence & Event Timeline (1 Col) */}
        <div className="border border-[#255325] p-4 bg-[#000000] lg:col-span-1 flex flex-col h-[650px]">
          <div className="flex justify-between items-center border-b border-[#255325] pb-2 mb-3 text-[12px]">
            <span className="text-[#ffffff] font-medium">
              EVIDENCE_TIMELINE // CHRONOLOGICAL
            </span>
            <span className="text-[#58ca58] text-[11px]">
              EVENTS: {incident.events?.length || 0}
            </span>
          </div>

          <div className="flex-1 overflow-y-auto space-y-3 pr-1 text-[11px]">
            {(incident.events || []).map((ev, index) => {
              const expanded = expandedLogId === ev.id;
              const stepNo = (index + 1).toString().padStart(2, "0");
              return (
                <div key={ev.id} className="border border-[#255325] p-2.5 bg-[#000000] space-y-1.5">
                  <div className="flex justify-between items-center text-[10px] text-[#255325]">
                    <span>[{stepNo}] {formatDateTime(ev.timestamp)}</span>
                    {ev.rule && (
                      <span className="text-[#66ff66] font-bold">
                        [{ev.rule.name}]
                      </span>
                    )}
                  </div>
                  <div className="text-[#ffffff] font-medium">
                    {ev.description}
                  </div>
                  <button 
                    onClick={() => setExpandedLogId(expanded ? null : ev.id)}
                    className="text-[10px] text-[#58ca58] hover:text-[#66ff66] cursor-pointer"
                  >
                    {expanded ? "[- HIDE_RAW_PAYLOAD]" : "[+ VIEW_RAW_PAYLOAD]"}
                  </button>
                  {expanded && ev.log_entry && (
                    <div className="mt-2 p-2 bg-[#255325]/10 border border-[#255325] font-mono text-[10px] text-[#58ca58] space-y-1">
                      <div>SOURCE: <span className="text-[#ffffff]">{ev.log_entry.source}</span></div>
                      <div>HOST: <span className="text-[#ffffff]">{ev.log_entry.host}</span></div>
                      {ev.log_entry.src_ip && <div>IP: <span className="text-[#ffffff]">{ev.log_entry.src_ip}</span></div>}
                      <pre className="pt-1 text-[#66ff66] border-t border-[#255325] whitespace-pre-wrap select-all">
                        {ev.log_entry.raw_log}
                      </pre>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>

        {/* Multi-Agent AI & SOAR Closed-Loop Remediation (2 Cols) */}
        <div className="border border-[#255325] p-4 bg-[#000000] lg:col-span-2 flex flex-col h-[650px] overflow-y-auto">
          <div className="flex justify-between items-center border-b border-[#255325] pb-2 mb-4 text-[12px]">
            <span className="text-[#ffffff] font-medium">
              MULTI-AGENT AI SOC // CLOSED-LOOP SOAR CONTAINMENT
            </span>
            
            {!incident.ai_report && !aiLoading && (
              <button 
                onClick={triggerAIInvestigation}
                className="px-3 py-1 bg-[#66ff66] text-[#000000] hover:bg-[#ffffff] font-medium text-[11px] transition-colors cursor-pointer select-none"
              >
                [ ⚡ INITIALIZE_MULTI_AGENT_SOC ↵ ]
              </button>
            )}
          </div>

          {aiLoading && (
            <div className="flex-1 flex flex-col items-center justify-center space-y-3">
              <span className="text-[#66ff66] text-[13px] animate-pulse">
                [ AI_AGENT_BUS: ORCHESTRATING (TRIAGE ➔ FORENSICS ➔ CONTAINMENT) ]
              </span>
              <span className="text-[11px] text-[#58ca58]">
                &gt; {aiLoadingSteps[aiStep]}
              </span>
            </div>
          )}

          {!aiLoading && (
            <div className="flex-1 flex flex-col space-y-4">
              {aiReportData ? (
                <div className="space-y-4 text-[12px]">
                  
                  {/* Executive Summary */}
                  <div className="border border-[#255325] p-3 bg-[#255325]/10">
                    <span className="text-[10px] text-[#255325] uppercase tracking-wider block mb-1">
                      // TRIAGE AGENT EXECUTIVE SUMMARY:
                    </span>
                    <p className="text-[#ffffff] leading-relaxed">
                      {aiReportData.executive_summary}
                    </p>
                  </div>
                  
                  {/* Forensic & Root Cause Analysis */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    <div className="border border-[#255325] p-3 bg-[#000000]">
                      <span className="text-[10px] text-[#255325] uppercase tracking-wider block mb-1">
                        // FORENSIC AGENT ANALYSIS:
                      </span>
                      <p className="text-[#58ca58] leading-relaxed">
                        {aiReportData.technical_analysis}
                      </p>
                    </div>
                    <div className="border border-[#255325] p-3 bg-[#000000]">
                      <span className="text-[10px] text-[#255325] uppercase tracking-wider block mb-1">
                        // ROOT CAUSE VECTOR:
                      </span>
                      <p className="text-[#58ca58] leading-relaxed">
                        {aiReportData.root_cause}
                      </p>
                    </div>
                  </div>

                  {/* SOAR Remediation Protocol Actions */}
                  <div className="border border-[#66ff66] p-4 bg-[#255325]/15 space-y-3">
                    <div className="flex justify-between items-center border-b border-[#255325] pb-2 text-[11px]">
                      <span className="text-[#ffffff] font-medium">
                        [ ⚡ ] SOAR CLOSED-LOOP REMEDIATION COMMANDS
                      </span>
                      <span className="text-[#58ca58]">TARGET: {targetHost}</span>
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                      <div className="border border-[#255325] p-3 bg-[#000000] flex flex-col justify-between space-y-2">
                        <div>
                          <div className="text-[10px] text-[#255325] uppercase">KILL_PROCESS</div>
                          <div className="text-[#ffffff] font-medium text-[11px]">PID: 4082 (cmd.exe)</div>
                        </div>
                        <button
                          onClick={() => handleCreateAndApproveSoarAction("KILL_PROCESS", "4082", "Terminate suspicious process ID 4082")}
                          className="w-full py-1.5 px-2 bg-[#66ff66] text-[#000000] hover:bg-[#ffffff] font-medium text-[10px] transition-colors cursor-pointer"
                        >
                          [ ↵ DISPATCH KILL_PID ]
                        </button>
                      </div>

                      <div className="border border-[#255325] p-3 bg-[#000000] flex flex-col justify-between space-y-2">
                        <div>
                          <div className="text-[10px] text-[#255325] uppercase">BLOCK_FIREWALL_IP</div>
                          <div className="text-[#ffffff] font-medium text-[11px] truncate">IP: {attackerIp}</div>
                        </div>
                        <button
                          onClick={() => handleCreateAndApproveSoarAction("BLOCK_IP", attackerIp, `Block external attacker IP ${attackerIp} on host firewall`)}
                          className="w-full py-1.5 px-2 bg-[#66ff66] text-[#000000] hover:bg-[#ffffff] font-medium text-[10px] transition-colors cursor-pointer"
                        >
                          [ ↵ DISPATCH BLOCK_IP ]
                        </button>
                      </div>

                      <div className="border border-[#255325] p-3 bg-[#000000] flex flex-col justify-between space-y-2">
                        <div>
                          <div className="text-[10px] text-[#255325] uppercase">QUARANTINE_INTERFACE</div>
                          <div className="text-[#ffffff] font-medium text-[11px] truncate">Host: {targetHost}</div>
                        </div>
                        <button
                          onClick={() => handleCreateAndApproveSoarAction("QUARANTINE_INTERFACE", "Ethernet0", `Isolate network interface on ${targetHost}`)}
                          className="w-full py-1.5 px-2 bg-[#66ff66] text-[#000000] hover:bg-[#ffffff] font-medium text-[10px] transition-colors cursor-pointer"
                        >
                          [ ↵ DISPATCH ISOLATE ]
                        </button>
                      </div>
                    </div>

                    {/* SOAR Action Execution History */}
                    {incident.soar_actions && incident.soar_actions.length > 0 && (
                      <div className="mt-3 pt-3 border-t border-[#255325] space-y-2">
                        <span className="text-[10px] text-[#255325] uppercase block">
                          // SOAR ACTION EXECUTION LEDGER:
                        </span>
                        <div className="space-y-1">
                          {incident.soar_actions.map((act: SOARAction) => (
                            <div key={act.id} className="p-2 border border-[#255325] bg-[#000000] flex justify-between items-center text-[11px]">
                              <div>
                                <span className="text-[#ffffff]">#{act.id} {act.action_type}</span> ({act.payload}) - {act.description}
                              </div>
                              <span className={`px-1.5 py-0.5 text-[10px] font-bold ${
                                act.status === "EXECUTED" ? "bg-[#66ff66] text-[#000000]" :
                                act.status === "APPROVED" ? "border border-[#66ff66] text-[#66ff66]" :
                                act.status === "FAILED" ? "border border-[#255325] text-[#ffffff]" :
                                "text-[#58ca58]"
                              }`}>
                                [{act.status}]
                              </span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    <div className="border-t border-[#255325] pt-2 space-y-2 text-[11px]">
                      <div>
                        <span className="text-[10px] text-[#255325] uppercase block">RECOVERY_PROTOCOL:</span>
                        <p className="text-[#58ca58] mt-0.5">{aiReportData.recovery_steps}</p>
                      </div>
                      <div>
                        <span className="text-[10px] text-[#255325] uppercase block">SOC_HARDENING_RECOMMENDATIONS:</span>
                        <p className="text-[#58ca58] mt-0.5">{aiReportData.soc_recommendations}</p>
                      </div>
                    </div>
                  </div>

                  <button 
                    onClick={triggerAIInvestigation}
                    className="text-[11px] text-[#58ca58] hover:text-[#66ff66] border border-[#255325] hover:border-[#66ff66] px-3 py-1 cursor-pointer transition-colors"
                  >
                    [ ↻ RE-RUN_MULTI_AGENT_WORKFLOW ]
                  </button>
                </div>
              ) : (
                <div className="flex-1 flex flex-col items-center justify-center border border-dashed border-[#255325] p-8 text-center space-y-3">
                  <div className="text-[13px] text-[#ffffff] font-medium">
                    [ NO_AI_INVESTIGATION_LOGGED ]
                  </div>
                  <p className="text-[11px] text-[#58ca58] max-w-sm leading-relaxed">
                    Trigger the SentinelAI Multi-Agent SOC (Triage ➔ Forensics ➔ Containment) to analyze event timelines, query threat telemetry, and build SOAR remediation playbooks.
                  </p>
                  <button 
                    onClick={triggerAIInvestigation}
                    className="mt-3 px-3 py-1.5 bg-[#66ff66] text-[#000000] hover:bg-[#ffffff] font-medium text-[11px] transition-colors cursor-pointer select-none"
                  >
                    [ ⚡ INITIALIZE_MULTI_AGENT_SOC ↵ ]
                  </button>
                </div>
              )}
            </div>
          )}
        </div>
      </div>

    </div>
  );
};

export default Investigation;

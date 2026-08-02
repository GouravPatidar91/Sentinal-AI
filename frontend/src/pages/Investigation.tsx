import React, { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import { 
  ArrowLeft, 
  Shield, 
  FileText, 
  Download, 
  Play, 
  Cpu, 
  Calendar, 
  Server, 
  Network,
  Clock
} from "lucide-react";
import { useNotifications } from "../context/NotificationContext";
import { useAuth } from "../context/AuthContext";
import { API_BASE, WS_BASE } from "../config/api";

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
          // Re-fetch details to dynamically load new timeline items/metrics
          fetchIncidentDetail();
        }
      } catch (err) {
        console.error("Error parsing WS message in incident detail:", err);
      }
    };
    
    return () => {
      ws.close();
    };
  }, [id]);

  const fetchIncidentDetail = async () => {
    setLoading(true);
    try {
      const resp = await fetch(`${API_BASE}/api/incidents/${id}`, {
        headers: { "Authorization": `Bearer ${token}` }
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
    // Simulated simple analyst list for assignment
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

  const triggerAIInvestigation = async () => {
    if (!incident) return;
    setAiLoading(true);
    setAiStep(0);
    
    // Cycle through loading steps text for dramatic cognitive effect
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

  const executeContainmentAction = (actionName: string) => {
    triggerNotification(
      "Containment Action Triggered",
      `Successfully executed: ${actionName}`,
      "HIGH"
    );
  };

  const getSeverityColor = (sev: string) => {
    switch (sev?.toUpperCase()) {
      case "CRITICAL": return "text-red-500 border-red-500/30 bg-red-500/10";
      case "HIGH": return "text-orange-500 border-orange-500/30 bg-orange-500/10";
      case "WARNING": return "text-yellow-500 border-yellow-500/30 bg-yellow-500/10";
      default: return "text-blue-500 border-blue-500/30 bg-blue-500/10";
    }
  };

  if (loading) {
    return <div className="flex-1 p-8 text-center text-slate-400 font-medium">Gathering threat timeline data...</div>;
  }

  if (!incident) {
    return (
      <div className="flex-1 p-8 text-center space-y-4">
        <h3 className="text-xl text-slate-300 font-bold">Incident Not Found</h3>
        <Link to="/incidents" className="text-blue-400 hover:underline">Return to queue</Link>
      </div>
    );
  }

  // Parse AI report if available
  let aiReportData: any = null;
  if (incident.ai_report) {
    try {
      aiReportData = JSON.parse(incident.ai_report);
    } catch (e) {
      aiReportData = { executive_summary: incident.ai_report };
    }
  }

  // Extracted attacker IP & target details for visualization
  const attackerIp = incident.events?.find(ev => ev.log_entry?.src_ip && ev.log_entry.src_ip !== "-")?.log_entry?.src_ip || "Unknown IP";
  const targetHost = incident.events?.find(ev => ev.log_entry?.host && ev.log_entry.host !== "unknown-host")?.log_entry?.host || "Unknown Host";
  const targetIp = incident.events?.find(ev => ev.log_entry?.dst_ip && ev.log_entry.dst_ip !== "-")?.log_entry?.dst_ip;
  const entryVector = incident.events?.find(ev => ev.rule?.tactic)?.rule?.tactic || "Initial Access";

  return (
    <div className="flex-1 p-8 space-y-8 overflow-y-auto h-screen max-w-[calc(100vw-16rem)]">
      
      {/* Header Link */}
      <div className="flex items-center gap-2 text-xs text-slate-500 hover:text-slate-300 transition-colors">
        <ArrowLeft className="w-4 h-4" />
        <Link to="/incidents" className="font-semibold uppercase tracking-wider">Back to Incident Queue</Link>
      </div>

      {/* Incident Header Deck */}
      <div className="glass-card rounded-xl p-6 border flex flex-col md:flex-row justify-between items-start md:items-center gap-6">
        <div className="space-y-2">
          <div className="flex items-center gap-3">
            <span className="font-mono text-sm text-slate-500 font-semibold">INCIDENT INC-{incident.id}</span>
            <span className={`px-2.5 py-0.5 rounded border text-[10px] font-bold uppercase tracking-wider ${getSeverityColor(incident.severity)}`}>
              {incident.severity}
            </span>
          </div>
          <h2 className="text-2xl font-bold text-slate-100">{incident.title}</h2>
          <div className="flex flex-wrap gap-4 text-xs text-slate-400 font-medium">
            <span className="flex items-center gap-1.5"><Calendar className="w-3.5 h-3.5 text-slate-500" /> {new Date(incident.created_at).toLocaleString()}</span>
            <span className="flex items-center gap-1.5"><Clock className="w-3.5 h-3.5 text-slate-500" /> Risk Score: <strong className="text-slate-200">{incident.risk_score}/100</strong></span>
            <span className="flex items-center gap-1.5"><Network className="w-3.5 h-3.5 text-slate-500" /> Attacker: <strong className="text-slate-200">{attackerIp}</strong></span>
            <span className="flex items-center gap-1.5"><Server className="w-3.5 h-3.5 text-slate-500" /> Target Asset: <strong className="text-slate-200">{targetHost.toUpperCase()}{targetIp ? ` (${targetIp})` : ""}</strong></span>
          </div>
        </div>

        {/* Triage controls */}
        <div className="flex flex-wrap gap-4 items-center">
          
          {/* Assignee Selection */}
          <div className="flex flex-col gap-1">
            <span className="text-[10px] text-slate-500 uppercase tracking-widest font-bold">Assignee</span>
            <select
              value={incident.assigned_to_id || ""}
              onChange={(e) => handleAssigneeChange(e.target.value)}
              className="bg-slate-950 border border-darkBorder rounded px-3 py-1.5 text-xs text-slate-300 outline-none cursor-pointer"
            >
              <option value="">Unassigned</option>
              {analysts.map(a => (
                <option key={a.id} value={a.id}>{a.username}</option>
              ))}
            </select>
          </div>

          {/* Status Selection */}
          <div className="flex flex-col gap-1">
            <span className="text-[10px] text-slate-500 uppercase tracking-widest font-bold">Status</span>
            <select
              value={incident.status}
              onChange={(e) => handleStatusChange(e.target.value)}
              className="bg-slate-950 border border-darkBorder rounded px-3 py-1.5 text-xs text-slate-300 outline-none cursor-pointer"
            >
              <option value="New">New</option>
              <option value="Investigating">Investigating</option>
              <option value="Contained">Contained</option>
              <option value="Resolved">Resolved</option>
              <option value="Closed">Closed</option>
            </select>
          </div>

          {/* PDF Report Download */}
          <a
            href={`${API_BASE}/api/incidents/${incident.id}/pdf`}
            className="flex items-center gap-2 bg-slate-900 border border-darkBorder hover:bg-slate-800 text-slate-300 px-4 py-2 rounded-lg text-xs font-semibold mt-4 transition-colors"
          >
            <Download className="w-4 h-4" />
            Export PDF
          </a>

        </div>
      </div>

      {/* Interactive Attack Chain Grid */}
      <div className="glass-card rounded-xl p-6 border flex flex-col">
        <h3 className="font-bold text-base text-slate-100 flex items-center gap-2 mb-6">
          <Shield className="w-4 h-4 text-emerald-400" />
          Interactive Attack Chain Flow
        </h3>
        
        <div className="flex flex-col md:flex-row items-center justify-around gap-6 py-4 relative">
          
          {/* Node 1: Attacker IP */}
          <div className="flex flex-col items-center p-4 rounded-xl border border-red-500/20 bg-red-950/10 w-44 text-center">
            <Network className="w-7 h-7 text-red-500 mb-2" />
            <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">Threat Origin</span>
            <span className="font-mono text-xs font-bold text-slate-200 mt-1">{attackerIp}</span>
          </div>

          <div className="text-slate-700 text-xl font-bold hidden md:block">→</div>

          {/* Node 2: Entry Vector Tactic */}
          <div className="flex flex-col items-center p-4 rounded-xl border border-yellow-500/20 bg-yellow-950/10 w-44 text-center">
            <FileText className="w-7 h-7 text-yellow-500 mb-2" />
            <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">Attack Vector</span>
            <span className="font-mono text-xs font-bold text-slate-200 mt-1">{entryVector}</span>
          </div>

          <div className="text-slate-700 text-xl font-bold hidden md:block">→</div>

          {/* Node 3: Target Host compromise */}
          <div className="flex flex-col items-center p-4 rounded-xl border border-blue-500/20 bg-blue-950/10 w-44 text-center">
            <Server className="w-7 h-7 text-blue-500 mb-2" />
            <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">Target Asset</span>
            <span className="font-mono text-xs font-bold text-slate-200 mt-1">
              {targetHost.toUpperCase()}
              {targetIp ? ` (${targetIp})` : ""}
            </span>
          </div>
          
        </div>
      </div>

      {/* Main Analysis Column & Logs timeline split */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Left Column: Attack Timeline Events */}
        <div className="glass-card rounded-xl p-6 border lg:col-span-1 flex flex-col h-[600px]">
          <h3 className="font-bold text-base text-slate-100 flex items-center gap-2 mb-6">
            <Clock className="w-4 h-4 text-blue-400" />
            Evidence & Event Timeline
          </h3>
          <div className="flex-1 overflow-y-auto space-y-4 pr-1">
            {(incident.events || []).map((ev) => {
              const expanded = expandedLogId === ev.id;
              return (
                <div key={ev.id} className="border-l-2 border-slate-700 pl-4 py-1 relative">
                  {/* Timeline point */}
                  <span className="absolute -left-[6px] top-2.5 w-2.5 h-2.5 rounded-full bg-blue-500 border border-darkBg" />
                  
                  <div className="flex justify-between items-start">
                    <span className="text-[10px] font-mono text-slate-500">{new Date(ev.timestamp).toLocaleTimeString()}</span>
                    {ev.rule && (
                      <span className="bg-red-500/10 border border-red-500/20 text-red-400 text-[9px] px-1.5 py-0.5 rounded font-bold uppercase">
                        {ev.rule.name}
                      </span>
                    )}
                  </div>
                  <h4 className="text-xs font-semibold text-slate-200 mt-1">{ev.description}</h4>
                  
                  {/* Toggle Log expand */}
                  <button 
                    onClick={() => setExpandedLogId(expanded ? null : ev.id)}
                    className="text-[10px] text-blue-400 hover:text-blue-300 font-semibold mt-2 block"
                  >
                    {expanded ? "Collapse Raw Log ▲" : "View Raw Event ▼"}
                  </button>
                  
                  {expanded && (
                    <div className="mt-3 bg-slate-950 border border-darkBorder rounded p-2.5 font-mono text-[10px] text-slate-400 space-y-2 max-w-full overflow-x-auto">
                      <div>
                        <span className="text-slate-600 block mb-0.5">// Parsed Fields:</span>
                        <div className="grid grid-cols-2 gap-1 bg-slate-900/60 p-2 rounded">
                          <div><span className="text-slate-500">Host:</span> {ev.log_entry.host}</div>
                          <div><span className="text-slate-500">Source:</span> {ev.log_entry.source}</div>
                          <div><span className="text-slate-500">IP:</span> {ev.log_entry.src_ip || "-"}</div>
                          <div><span className="text-slate-500">User:</span> {ev.log_entry.username || "-"}</div>
                          <div><span className="text-slate-500">Process:</span> {ev.log_entry.process || "-"}</div>
                          <div><span className="text-slate-500">Severity:</span> {ev.log_entry.severity}</div>
                        </div>
                      </div>
                      <div>
                        <span className="text-slate-600 block mb-0.5">// Raw Message:</span>
                        <div className="whitespace-pre-wrap select-all bg-slate-900/40 p-2 rounded max-h-40 overflow-y-auto">{ev.log_entry.raw_log}</div>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>

        {/* Right Column: AI Insights & Remediation Actions */}
        <div className="glass-card rounded-xl p-6 border lg:col-span-2 flex flex-col h-[600px] overflow-y-auto">
          
          <div className="flex justify-between items-center mb-6">
            <h3 className="font-bold text-base text-slate-100 flex items-center gap-2">
              <Cpu className="w-4 h-4 text-indigo-400 animate-pulse" />
              SentinelAI Investigation Report
            </h3>
            
            {!incident.ai_report && !aiLoading && (
              <button 
                onClick={triggerAIInvestigation}
                className="bg-indigo-600 hover:bg-indigo-500 text-white font-bold px-3 py-1.5 rounded text-xs flex items-center gap-1.5 shadow-md shadow-indigo-500/10 cursor-pointer transition-colors"
              >
                <Play className="w-3 h-3 fill-current" />
                Initialize AI Investigation
              </button>
            )}
          </div>

          {/* AI Loader screen */}
          {aiLoading && (
            <div className="flex-1 flex flex-col items-center justify-center space-y-4">
              <div className="w-16 h-16 border-4 border-indigo-500/20 border-t-indigo-500 rounded-full animate-spin" />
              <div className="text-center">
                <span className="text-sm font-semibold text-slate-300 block">Investigating Incident INC-{incident.id}</span>
                <span className="text-xs text-slate-500 italic mt-1 block">{aiLoadingSteps[aiStep]}</span>
              </div>
            </div>
          )}

          {/* Report Viewer */}
          {!aiLoading && (
            <div className="flex-1 flex flex-col space-y-6">
              {aiReportData ? (
                <div className="space-y-6 text-sm">
                  
                  {/* Executive Summary Banner */}
                  <div className="p-4 rounded-xl border border-indigo-500/20 bg-indigo-950/15">
                    <span className="text-[10px] font-bold text-indigo-400 tracking-widest uppercase block mb-1">Executive Summary</span>
                    <p className="text-slate-300 leading-relaxed font-medium">{aiReportData.executive_summary}</p>
                  </div>
                  
                  {/* Analysis Breakdown */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="p-4 rounded-lg bg-slate-900/60 border border-darkBorder">
                      <span className="text-[10px] font-bold text-slate-500 tracking-widest uppercase block mb-2">Technical Analysis</span>
                      <p className="text-slate-400 text-xs leading-relaxed">{aiReportData.technical_analysis}</p>
                    </div>
                    <div className="p-4 rounded-lg bg-slate-900/60 border border-darkBorder">
                      <span className="text-[10px] font-bold text-slate-500 tracking-widest uppercase block mb-2">Root Cause</span>
                      <p className="text-slate-400 text-xs leading-relaxed">{aiReportData.root_cause}</p>
                    </div>
                  </div>

                  {/* Remediation Cards */}
                  <div className="border border-darkBorder rounded-xl overflow-hidden">
                    <div className="bg-slate-900/80 px-4 py-3 border-b border-darkBorder font-bold text-xs uppercase tracking-wider text-slate-300">
                      Response & Containment Playbook
                    </div>
                    <div className="p-4 space-y-4">
                      
                      <div>
                        <span className="text-[10px] font-bold text-red-400 uppercase block mb-1">Immediate Containment</span>
                        <p className="text-slate-300 text-xs">{aiReportData.containment_steps}</p>
                        <button 
                          onClick={() => executeContainmentAction(aiReportData.containment_steps)}
                          className="mt-2 text-[10px] bg-red-950/40 text-red-400 border border-red-900/50 hover:bg-red-900/20 px-2.5 py-1 rounded font-bold cursor-pointer transition-all"
                        >
                          Execute Containment Protocol
                        </button>
                      </div>
                      
                      <div className="border-t border-darkBorder pt-3">
                        <span className="text-[10px] font-bold text-yellow-400 uppercase block mb-1">Recovery Phase</span>
                        <p className="text-slate-300 text-xs">{aiReportData.recovery_steps}</p>
                      </div>

                      <div className="border-t border-darkBorder pt-3">
                        <span className="text-[10px] font-bold text-emerald-400 uppercase block mb-1">SOC Best Practices</span>
                        <p className="text-slate-300 text-xs">{aiReportData.soc_recommendations}</p>
                      </div>

                    </div>
                  </div>

                  {/* Re-investigate button */}
                  <button 
                    onClick={triggerAIInvestigation}
                    className="text-xs text-indigo-400 hover:text-indigo-300 font-semibold border border-indigo-900/30 hover:border-indigo-800 bg-slate-950/40 px-3 py-1.5 rounded w-max cursor-pointer"
                  >
                    ✕ Recalculate Investigation report
                  </button>

                </div>
              ) : (
                <div className="flex-1 flex flex-col items-center justify-center border-2 border-dashed border-darkBorder rounded-xl p-8 text-center text-slate-500">
                  <Cpu className="w-12 h-12 text-slate-700 mb-3 animate-pulse" />
                  <h4 className="font-bold text-slate-300 text-sm">No Investigation Logged</h4>
                  <p className="text-xs max-w-sm mt-1 leading-relaxed">
                    Trigger the SentinelAI Security Agent to scan the event timelines, evaluate MITRE patterns, and formulate remediations.
                  </p>
                  <button 
                    onClick={triggerAIInvestigation}
                    className="mt-5 bg-indigo-600 hover:bg-indigo-500 text-white font-bold px-4 py-2 rounded text-xs flex items-center gap-1.5 shadow-md shadow-indigo-500/10 cursor-pointer transition-all"
                  >
                    <Play className="w-3 h-3 fill-current" />
                    Initialize AI Agent
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

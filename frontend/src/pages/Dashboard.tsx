import React, { useEffect, useState, useRef } from "react";
import { API_BASE, WS_BASE } from "../config/api";
import { 
  ShieldAlert, 
  Activity, 
  Terminal, 
  AlertTriangle, 
  CheckCircle, 
  TrendingUp, 
  Layers 
} from "lucide-react";
import { 
  AreaChart, 
  Area, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  ResponsiveContainer 
} from "recharts";
import { Link } from "react-router-dom";
import { useNotifications } from "../context/NotificationContext";
import { useAuth } from "../context/AuthContext";

interface Incident {
  id: number;
  title: string;
  description: string;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  status: string;
  risk_score: number;
  anomaly_score: number;
  created_at: string;
}

interface Log {
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
  anomaly_score: number;
}

export const Dashboard: React.FC = () => {
  const { triggerNotification } = useNotifications();
  const { token } = useAuth();
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [liveLogs, setLiveLogs] = useState<Log[]>([]);
  const [stats, setStats] = useState<any>({
    total_logs: 0,
    by_severity: { INFO: 0, WARNING: 0, ERROR: 0, CRITICAL: 0 },
    by_source: { Windows: 0, Linux: 0, Apache: 0, Firewall: 0 }
  });
  
  const [trendData, setTrendData] = useState<any[]>([]);
  const wsRef = useRef<WebSocket | null>(null);

  // Fetch initial data
  useEffect(() => {
    const fetchInitData = async () => {
      try {
        const incResp = await fetch(`${API_BASE}/api/incidents`, {
          headers: { "Authorization": `Bearer ${token}` }
        });
        const incData = await incResp.json();
        setIncidents(incData.slice(0, 8)); // Top 8 incidents
        
        const logResp = await fetch(`${API_BASE}/api/logs/search?limit=15`, {
          headers: { "Authorization": `Bearer ${token}` }
        });
        const logData = await logResp.json();
        setLiveLogs(logData);
        
        const statResp = await fetch(`${API_BASE}/api/logs/stats`, {
          headers: { "Authorization": `Bearer ${token}` }
        });
        const statData = await statResp.json();
        setStats(statData);
        
        // Generate mock timeline trends for visual graphs
        const hours = Array.from({ length: 12 }, (_, i) => {
          const time = new Date();
          time.setHours(time.getHours() - (11 - i));
          return {
            time: time.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
            logs: Math.floor(Math.random() * 50) + 10,
            threats: Math.floor(Math.random() * 4)
          };
        });
        setTrendData(hours);
      } catch (err) {
        console.error("Error fetching initial dashboard stats:", err);
      }
    };
    
    fetchInitData();
    
    // Connect WebSockets for real-time updates
    const connectWS = () => {
      const ws = new WebSocket(`${WS_BASE}/api/ws`);
      wsRef.current = ws;
      
      ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        
        if (data.type === "NEW_LOG") {
          // 1. Add to live log list
          setLiveLogs((prev) => [data.log, ...prev].slice(0, 15));
          
          // 2. Increment stats
          setStats((prev: any) => {
            const nextSev = { ...prev.by_severity };
            const nextSrc = { ...prev.by_source };
            
            const logSev = data.log.severity;
            const logSrc = data.log.source;
            
            if (logSev in nextSev) nextSev[logSev] += 1;
            if (logSrc in nextSrc) nextSrc[logSrc] += 1;
            
            return {
              total_logs: prev.total_logs + 1,
              by_severity: nextSev,
              by_source: nextSrc
            };
          });
          
          // 3. Trigger Toast alert if rule matched
          if (data.alert) {
            triggerNotification(
              `Alert: ${data.alert.rule_name}`,
              `${data.alert.description} triggered on ${data.log.host}`,
              data.alert.severity
            );
          }
          
          // 4. Trigger Toast alert for Incident
          if (data.incident) {
            // Update Incidents list
            setIncidents((prev) => {
              const filtered = prev.filter(i => i.id !== data.incident.id);
              return [data.incident, ...filtered].slice(0, 8);
            });
            
            triggerNotification(
              `New Incident: ${data.incident.title}`,
              `Severity: ${data.incident.severity} | Risk Score: ${data.incident.risk_score}`,
              data.incident.severity
            );
          }
        } else if (data.type === "INCIDENT_UPDATE") {
          setIncidents((prev) => {
            return prev.map(inc => inc.id === data.incident.id ? data.incident : inc);
          });
        }
      };
      
      ws.onerror = (e) => {
        console.error("WebSocket encountered error:", e);
        ws.close();
      };
      
      ws.onclose = () => {
        console.log("WebSocket disconnected. Reconnecting in 3s...");
        setTimeout(() => connectWS(), 3000);
      };
    };
    
    connectWS();
    
    return () => {
      if (wsRef.current) wsRef.current.close();
    };
  }, [triggerNotification]);

  // MITRE Matrix techniques mapping
  const mitreTactics = [
    { name: "Initial Access", technique: "T1190", label: "Exploit Web App", active: incidents.some(i => i.title.toLowerCase().includes("sql") || i.title.toLowerCase().includes("xss")) },
    { name: "Execution", technique: "T1203", label: "Client Execution", active: incidents.some(i => i.title.toLowerCase().includes("powershell") || i.title.toLowerCase().includes("malware")) },
    { name: "Persistence", technique: "T1136.001", label: "Create Account", active: incidents.some(i => i.title.toLowerCase().includes("account") || i.title.toLowerCase().includes("sudoer")) },
    { name: "Privilege Escalation", technique: "T1078", label: "Valid Accounts", active: incidents.some(i => i.title.toLowerCase().includes("privilege") || i.title.toLowerCase().includes("sudo")) },
    { name: "Defense Evasion", technique: "T1562.001", label: "Impair Defenses", active: incidents.some(i => i.title.toLowerCase().includes("audit") || i.title.toLowerCase().includes("policy")) },
    { name: "Credential Access", technique: "T1110", label: "Brute Force", active: incidents.some(i => i.title.toLowerCase().includes("brute") || i.title.toLowerCase().includes("ssh-failure")) },
    { name: "Discovery", technique: "T1046", label: "Network Service Disc.", active: incidents.some(i => i.title.toLowerCase().includes("scan") || i.title.toLowerCase().includes("denied")) },
    { name: "Command & Control", technique: "T1090", label: "Proxy Traffic", active: incidents.some(i => i.title.toLowerCase().includes("country") || i.title.toLowerCase().includes("suspicious")) },
    { name: "Exfiltration", technique: "T1048", label: "Alternative Protocol", active: incidents.some(i => i.title.toLowerCase().includes("traffic") || i.title.toLowerCase().includes("large")) }
  ];

  // Helper for colors
  const getSeverityBg = (sev: string) => {
    switch (sev.toUpperCase()) {
      case "CRITICAL": return "bg-red-500/10 text-red-400 border-red-500/20";
      case "HIGH": return "bg-orange-500/10 text-orange-400 border-orange-500/20";
      case "WARNING": return "bg-yellow-500/10 text-yellow-400 border-yellow-500/20";
      default: return "bg-blue-500/10 text-blue-400 border-blue-500/20";
    }
  };

  const activeIncidentsCount = incidents.filter(i => i.status !== "Closed" && i.status !== "Resolved").length;
  const criticalAlertsCount = stats.by_severity.CRITICAL || 0;

  return (
    <div className="flex-1 p-8 space-y-8 overflow-y-auto h-screen max-w-[calc(100vw-16rem)]">
      
      {/* Dashboard Title Banner */}
      <div className="flex justify-between items-center border-b border-darkBorder pb-6">
        <div>
          <h2 className="text-3xl font-extrabold text-slate-100 tracking-wide">SOC COMMAND CENTER</h2>
          <p className="text-sm text-slate-500 mt-1">Autonomous threat detection, incident correlation and AI assistance</p>
        </div>
        <div className="flex items-center gap-3 bg-slate-900/60 border border-darkBorder px-4 py-2 rounded-lg">
          <Activity className="w-4 h-4 text-emerald-400 animate-pulse" />
          <span className="text-xs font-semibold text-emerald-400">PIPELINE STATUS: ONLINE</span>
        </div>
      </div>

      {/* Metrics Widgets */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <div className="glass-card rounded-xl p-6 border flex justify-between items-center">
          <div className="space-y-1">
            <span className="text-xs font-semibold tracking-wider text-slate-500 uppercase">Live Log Ingestion</span>
            <h3 className="text-2xl font-bold text-slate-100">{stats.total_logs.toLocaleString()}</h3>
          </div>
          <div className="w-12 h-12 bg-blue-500/10 border border-blue-500/30 rounded-xl flex items-center justify-center">
            <Terminal className="w-6 h-6 text-blue-400" />
          </div>
        </div>

        <div className="glass-card rounded-xl p-6 border flex justify-between items-center">
          <div className="space-y-1">
            <span className="text-xs font-semibold tracking-wider text-slate-500 uppercase">Active Incidents</span>
            <h3 className="text-2xl font-bold text-red-500">{activeIncidentsCount}</h3>
          </div>
          <div className="w-12 h-12 bg-red-500/10 border border-red-500/30 rounded-xl flex items-center justify-center">
            <ShieldAlert className="w-6 h-6 text-red-400 animate-bounce" />
          </div>
        </div>

        <div className="glass-card rounded-xl p-6 border flex justify-between items-center">
          <div className="space-y-1">
            <span className="text-xs font-semibold tracking-wider text-slate-500 uppercase">Critical Detections</span>
            <h3 className="text-2xl font-bold text-orange-500">{criticalAlertsCount}</h3>
          </div>
          <div className="w-12 h-12 bg-orange-500/10 border border-orange-500/30 rounded-xl flex items-center justify-center">
            <AlertTriangle className="w-6 h-6 text-orange-400" />
          </div>
        </div>

        <div className="glass-card rounded-xl p-6 border flex justify-between items-center">
          <div className="space-y-1">
            <span className="text-xs font-semibold tracking-wider text-slate-500 uppercase">Monitored Assets</span>
            <h3 className="text-2xl font-bold text-teal-400">4</h3>
          </div>
          <div className="w-12 h-12 bg-teal-500/10 border border-teal-500/30 rounded-xl flex items-center justify-center">
            <CheckCircle className="w-6 h-6 text-teal-400" />
          </div>
        </div>
      </div>

      {/* Main Charts & Live Feed Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Trend Area Chart */}
        <div className="glass-card rounded-xl p-6 border lg:col-span-2 flex flex-col h-96">
          <div className="flex justify-between items-center mb-6">
            <h3 className="font-bold text-base text-slate-100 flex items-center gap-2">
              <TrendingUp className="w-4 h-4 text-blue-500" />
              Attack Trend (12h Window)
            </h3>
            <span className="text-[10px] bg-slate-900 border border-darkBorder px-2.5 py-1 rounded text-slate-400 uppercase tracking-widest font-mono">Realtime volume</span>
          </div>
          <div className="w-full h-[300px] relative">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={trendData} margin={{ top: 10, right: 10, left: -25, bottom: 0 }}>
                <defs>
                  <linearGradient id="colorLogs" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.2}/>
                    <stop offset="95%" stopColor="#3b82f6" stopOpacity={0}/>
                  </linearGradient>
                  <linearGradient id="colorThreats" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ef4444" stopOpacity={0.2}/>
                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.03)" />
                <XAxis dataKey="time" stroke="#475569" fontSize={10} />
                <YAxis stroke="#475569" fontSize={10} />
                <Tooltip contentStyle={{ backgroundColor: "#0b0f19", borderColor: "#1f2937", color: "#f1f5f9" }} />
                <Area type="monotone" dataKey="logs" name="Log Volume" stroke="#3b82f6" fillOpacity={1} fill="url(#colorLogs)" strokeWidth={2} />
                <Area type="monotone" dataKey="threats" name="Threat Triggers" stroke="#ef4444" fillOpacity={1} fill="url(#colorThreats)" strokeWidth={2} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Live Logs Ticker Feed */}
        <div className="glass-card rounded-xl p-6 border flex flex-col h-96">
          <div className="flex justify-between items-center mb-6">
            <h3 className="font-bold text-base text-slate-100 flex items-center gap-2">
              <Terminal className="w-4 h-4 text-emerald-400" />
              Live Ingested Feed
            </h3>
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 animate-ping" />
          </div>
          <div className="flex-1 overflow-y-auto space-y-3 pr-1 font-mono text-[11px]">
            {liveLogs.length === 0 ? (
              <div className="h-full flex items-center justify-center text-slate-600">Waiting for agent connection...</div>
            ) : (
              liveLogs.map((log, index) => (
                <div 
                  key={log.id || index} 
                  className={`p-2.5 rounded border border-darkBorder flex flex-col gap-1 transition-all ${
                    log.severity === "CRITICAL" ? "bg-red-950/20 border-red-900/30" : 
                    log.severity === "ERROR" ? "bg-orange-950/20 border-orange-900/30" : 
                    log.severity === "WARNING" ? "bg-yellow-950/20 border-yellow-900/30" : "bg-slate-900/40"
                  }`}
                >
                  <div className="flex justify-between items-center">
                    <span className="text-slate-500 text-[10px]">{new Date(log.timestamp).toLocaleTimeString()}</span>
                    <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold ${
                      log.severity === "CRITICAL" ? "bg-red-500/20 text-red-400" :
                      log.severity === "ERROR" ? "bg-orange-500/20 text-orange-400" :
                      log.severity === "WARNING" ? "bg-yellow-500/20 text-yellow-400" : "bg-slate-800 text-slate-400"
                    }`}>
                      {log.source.toUpperCase()}
                    </span>
                  </div>
                  <span className="text-slate-300 font-semibold">{log.host}</span>
                  <span className="text-slate-400 truncate mt-0.5">{log.message}</span>
                  {log.anomaly_score > 0.4 && (
                    <span className="text-purple-400 text-[9px] font-semibold self-end">
                      Anomaly Score: {log.anomaly_score.toFixed(2)}
                    </span>
                  )}
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      {/* MITRE ATT&CK Matrix */}
      <div className="glass-card rounded-xl p-6 border flex flex-col">
        <h3 className="font-bold text-base text-slate-100 flex items-center gap-2 mb-6">
          <Layers className="w-4 h-4 text-indigo-400" />
          MITRE ATT&CK Matrix Mapping
        </h3>
        
        <div className="grid grid-cols-2 md:grid-cols-9 gap-3">
          {mitreTactics.map((tactic) => (
            <div 
              key={tactic.name}
              className={`p-3.5 rounded-lg border flex flex-col justify-between h-28 text-center transition-all ${
                tactic.active 
                  ? "bg-red-500/10 border-red-500/40 text-red-300 pulse-critical" 
                  : "bg-slate-900/40 border-darkBorder text-slate-400"
              }`}
            >
              <div className="text-[10px] font-bold uppercase tracking-wider leading-tight h-10 flex items-center justify-center">
                {tactic.name}
              </div>
              <div className="mt-2">
                <span className="font-mono text-xs font-bold block">{tactic.technique}</span>
                <span className="text-[9px] opacity-75 mt-0.5 block">{tactic.label}</span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Incidents Queue Triage */}
      <div className="glass-card rounded-xl p-6 border flex flex-col">
        <div className="flex justify-between items-center mb-6">
          <h3 className="font-bold text-base text-slate-100 flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-red-500" />
            Correlated Incident Queue (Triage)
          </h3>
          <Link to="/incidents" className="text-xs text-blue-400 hover:text-blue-300 font-semibold">
            View All Incidents →
          </Link>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-darkBorder text-slate-500 font-semibold">
                <th className="pb-3 w-16">ID</th>
                <th className="pb-3">Threat Description</th>
                <th className="pb-3 w-28">Severity</th>
                <th className="pb-3 w-28">Risk Score</th>
                <th className="pb-3 w-28">Status</th>
                <th className="pb-3 w-36">Timestamp</th>
                <th className="pb-3 w-24">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-darkBorder">
              {incidents.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-slate-500">
                    No active threat incidents detected in the environment.
                  </td>
                </tr>
              ) : (
                incidents.map((inc) => (
                  <tr key={inc.id} className="hover:bg-slate-900/30 transition-colors">
                    <td className="py-3.5 font-mono text-slate-400">INC-{inc.id}</td>
                    <td className="py-3.5 pr-4">
                      <div className="flex flex-col">
                        <span className="font-semibold text-slate-200">{inc.title}</span>
                        <span className="text-[10px] text-slate-500 truncate max-w-md mt-0.5">{inc.description}</span>
                      </div>
                    </td>
                    <td className="py-3.5">
                      <span className={`px-2 py-0.5 rounded border text-[10px] font-bold ${getSeverityBg(inc.severity)}`}>
                        {inc.severity}
                      </span>
                    </td>
                    <td className="py-3.5">
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-slate-200">{inc.risk_score}</span>
                        <div className="w-16 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                          <div 
                            className={`h-full ${
                              inc.risk_score > 75 ? "bg-red-500" :
                              inc.risk_score > 40 ? "bg-orange-500" : "bg-yellow-500"
                            }`}
                            style={{ width: `${inc.risk_score}%` }}
                          />
                        </div>
                      </div>
                    </td>
                    <td className="py-3.5">
                      <span className="text-slate-300 font-semibold">{inc.status}</span>
                    </td>
                    <td className="py-3.5 text-slate-400 font-mono">
                      {new Date(inc.created_at).toLocaleString()}
                    </td>
                    <td className="py-3.5">
                      <Link 
                        to={`/incidents/${inc.id}`}
                        className="bg-blue-600/10 hover:bg-blue-600 border border-blue-500/20 hover:border-blue-500 text-blue-400 hover:text-white px-3 py-1.5 rounded text-[11px] font-bold tracking-wide transition-all"
                      >
                        Investigate
                      </Link>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
      
    </div>
  );
};
export default Dashboard;

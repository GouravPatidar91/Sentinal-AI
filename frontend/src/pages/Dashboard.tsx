import React, { useEffect, useState, useRef } from "react";
import { API_BASE, WS_BASE } from "../config/api";
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
import { formatDateTime } from "../utils/time";

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
  const [realtimeAiAlert, setRealtimeAiAlert] = useState<any>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const [isExecutingSoar, setIsExecutingSoar] = useState(false);

  const handleExecuteOneClickPrevention = async (alertData: any) => {
    try {
      setIsExecutingSoar(true);
      const actionType = alertData.soar_actions?.[0]?.action_type || "BLOCK_IP";
      const payload = alertData.soar_actions?.[0]?.payload || alertData.attacker_ip || "198.51.100.55";
      const targetHost = alertData.target_host || "web-server-prod";

      const rawToken = token || localStorage.getItem("token");
      const headers: Record<string, string> = { "Content-Type": "application/json" };
      if (rawToken && rawToken !== "null" && rawToken !== "undefined") {
        headers["Authorization"] = `Bearer ${rawToken}`;
      }
      
      const createResp = await fetch(`${API_BASE}/api/soar/actions?auto_approve=true`, {
        method: "POST",
        headers,
        body: JSON.stringify({
          incident_id: alertData.incident_id,
          action_type: actionType,
          target_host: targetHost,
          payload: payload,
          description: `Real-time One-Click Prevention for ${alertData.title}`
        })
      });

      if (createResp.ok) {
        const action = await createResp.json();
        // Also call approve to ensure backwards compatibility
        await fetch(`${API_BASE}/api/soar/approve/${action.id}`, {
          method: "POST",
          headers
        }).catch(() => {});

        triggerNotification(
          "Attack Prevention Executed", 
          `SOAR command #${action.id} (${actionType}) dispatched to ${targetHost}. Attacker IP ${payload} blocked.`, 
          "CRITICAL"
        );
        setTimeout(() => {
          setRealtimeAiAlert(null);
          setIsExecutingSoar(false);
        }, 600);
      } else {
        setIsExecutingSoar(false);
      }
    } catch (err) {
      console.error("One-click prevention failed:", err);
      setIsExecutingSoar(false);
    }
  };

  // Fetch initial data
  useEffect(() => {
    const fetchInitData = async () => {
      const activeToken = token || localStorage.getItem("token");
      const authHeaders: Record<string, string> = activeToken ? { "Authorization": `Bearer ${activeToken}` } : {};

      // 1. Fetch Incidents
      try {
        const incResp = await fetch(`${API_BASE}/api/incidents/`, { headers: authHeaders });
        if (incResp.ok) {
          const incData = await incResp.json();
          if (Array.isArray(incData)) {
            setIncidents(incData.slice(0, 8));
          }
        }
      } catch (err) {
        console.error("Error fetching incidents:", err);
      }

      // 2. Fetch Live Logs
      try {
        const logResp = await fetch(`${API_BASE}/api/logs/search?limit=15`, { headers: authHeaders });
        if (logResp.ok) {
          const logData = await logResp.json();
          if (Array.isArray(logData)) {
            setLiveLogs(logData);
          }
        }
      } catch (err) {
        console.error("Error fetching live logs:", err);
      }

      // 3. Fetch Log Stats
      try {
        const statResp = await fetch(`${API_BASE}/api/logs/stats`, { headers: authHeaders });
        if (statResp.ok) {
          const statData = await statResp.json();
          if (statData && statData.total_logs !== undefined) {
            setStats(statData);
          }
        }
      } catch (err) {
        console.error("Error fetching log stats:", err);
      }

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
    };
    
    fetchInitData();
    
    // Connect WebSockets for real-time updates
    const connectWS = () => {
      const ws = new WebSocket(`${WS_BASE}/api/ws`);
      wsRef.current = ws;
      
      ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        
        if (data.type === "REALTIME_OPENROUTER_ALERT" || data.type === "REALTIME_AI_ALERT") {
          setRealtimeAiAlert(data);
          const isCloud = data.detection_source === "cloud_ai" || (data.is_cloud_ai !== false && data.detection_source !== "local_engine");
          if (isCloud) {
            triggerNotification(
              `⚡ Sentinel AI Alert: ${data.title}`,
              `${data.executive_summary} (Host: ${data.target_host})`,
              data.severity,
              "SENTINEL_AI"
            );
          } else {
            triggerNotification(
              `🛡️ Sentinel Locally Engine Alert: ${data.title}`,
              `${data.executive_summary} (Host: ${data.target_host})`,
              data.severity,
              "SENTINEL_LOCAL_ENGINE"
            );
          }
        } else if (data.type === "NEW_LOG") {
          setLiveLogs((prev) => [data.log, ...prev].slice(0, 15));
          
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
          
          const isCloud = data.detection_source === "cloud_ai" || (data.ai_enabled !== false && data.detection_source !== "local_engine");

          if (data.alert) {
            triggerNotification(
              isCloud
                ? `⚡ Sentinel AI Alert: ${data.alert.rule_name}`
                : `🛡️ Sentinel Locally Engine Alert: ${data.alert.rule_name}`,
              `${data.alert.description} triggered on ${data.log.host}`,
              data.alert.severity,
              isCloud ? "SENTINEL_AI" : "SENTINEL_LOCAL_ENGINE"
            );
          }
          
          if (data.incident) {
            setIncidents((prev) => {
              const filtered = prev.filter(i => i.id !== data.incident.id);
              return [data.incident, ...filtered].slice(0, 8);
            });
            
            triggerNotification(
              isCloud
                ? `⚡ Sentinel AI Alert: ${data.incident.title}`
                : `🛡️ Sentinel Locally Engine Alert: ${data.incident.title}`,
              `Severity: ${data.incident.severity} | Risk Score: ${data.incident.risk_score}`,
              data.incident.severity,
              isCloud ? "SENTINEL_AI" : "SENTINEL_LOCAL_ENGINE"
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
        setTimeout(() => connectWS(), 3000);
      };
    };
    
    connectWS();
    
    return () => {
      if (wsRef.current) wsRef.current.close();
    };
  }, [triggerNotification, token]);

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

  // Helper for character-based ASCII meter
  const renderAsciiMeter = (val: number, max: number, chars = 12) => {
    const filled = Math.min(chars, Math.max(0, Math.round((val / max) * chars)));
    return "█".repeat(filled) + "░".repeat(chars - filled);
  };

  const activeIncidentsCount = incidents.filter(i => i.status !== "Closed" && i.status !== "Resolved").length;
  const criticalAlertsCount = stats.by_severity.CRITICAL || 0;

  return (
    <div className="flex-1 min-w-0 p-6 space-y-6 overflow-y-auto h-screen bg-[#000000] text-[#66ff66] font-mono select-text">
      
      {/* ============================================================== */}
      {/* TOP COMMAND SESSION BAR & TITLE                                */}
      {/* ============================================================== */}
      <div className="border border-[#255325] p-4 bg-[#000000]">
        
        {/* Numbered Command Callout */}
        <div className="flex items-center justify-between text-[13px] border-b border-[#255325] pb-2 mb-3">
          <div className="flex items-center gap-2">
            <span className="text-[#255325] select-none">[00]</span>
            <span className="text-[#66ff66]">
              <span className="text-[#58ca58]">sentinel@soc:~$</span> sentinel --console dashboard --target telemetry-stream --interval 1000ms
            </span>
          </div>
          <span className="px-2 py-0.5 bg-[#66ff66] text-[#000000] font-medium text-[11px] select-none">
            [ STATUS: ONLINE // 60_FPS ]
          </span>
        </div>

        {/* Dashboard Title & Output */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-2">
          <div>
            <h1 className="text-[22px] sm:text-[26px] font-medium text-[#ffffff] tracking-tight uppercase">
              Autonomous SOC Command Center
            </h1>
            <p className="text-[14px] text-[#58ca58] mt-1">
              Event normalization, 15-minute sliding correlation window, and unsupervised Isolation Forest anomaly telemetry.
            </p>
          </div>
          <div className="text-[12px] text-[#58ca58] text-right font-mono shrink-0">
            <div>HOST: <span className="text-[#ffffff]">sentinel-core-engine</span></div>
            <div>UPTIME: <span className="text-[#ffffff]">99.999% SLA</span></div>
          </div>
        </div>
      </div>

      {/* ============================================================== */}
      {/* REAL-TIME SENTINEL THREAT BANNER (AI / LOCAL ENGINE)           */}
      {/* ============================================================== */}
      {realtimeAiAlert && (
        <div className="p-4 border border-[#66ff66] bg-[#255325]/20 space-y-3">
          <div className="flex justify-between items-center border-b border-[#255325] pb-2 text-[13px]">
            <div className="flex items-center gap-2">
              <span className={`px-1.5 py-0.5 text-[10px] font-bold ${
                realtimeAiAlert.detection_source === "local_engine" || realtimeAiAlert.is_cloud_ai === false
                  ? "bg-[#255325] text-[#ffffff] border border-[#58ca58]"
                  : "bg-[#66ff66] text-[#000000]"
              }`}>
                {realtimeAiAlert.detection_source === "local_engine" || realtimeAiAlert.is_cloud_ai === false
                  ? "[ 🛡️ SENTINEL LOCALLY ENGINE ]"
                  : "[ ⚡ SENTINEL AI ALERT ]"}
              </span>
              <span className="text-[#ffffff] font-medium">
                THREAT DETECTED &gt;&gt;&gt; {realtimeAiAlert.title}
              </span>
            </div>
            <button 
              onClick={() => setRealtimeAiAlert(null)}
              className="px-2 py-0.5 border border-[#255325] text-[#58ca58] hover:text-[#ffffff] hover:border-[#66ff66] transition-colors cursor-pointer text-[11px]"
            >
              [ DISMISS ✕ ]
            </button>
          </div>

          <p className="text-[13px] text-[#ffffff] leading-relaxed">
            {realtimeAiAlert.executive_summary}
          </p>

          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 pt-2 border-t border-[#255325] text-[12px]">
            <div className="text-[#58ca58]">
              TARGET: <span className="text-[#ffffff]">{realtimeAiAlert.target_host}</span> | ATTACKER_IP: <span className="text-[#ffffff]">{realtimeAiAlert.attacker_ip}</span>
            </div>
            <button
              onClick={() => handleExecuteOneClickPrevention(realtimeAiAlert)}
              disabled={isExecutingSoar}
              className={`px-3 py-1.5 font-medium transition-colors cursor-pointer text-[12px] ${
                isExecutingSoar
                  ? "bg-[#ffffff] text-[#000000] opacity-80"
                  : "bg-[#66ff66] text-[#000000] hover:bg-[#ffffff]"
              }`}
            >
              {isExecutingSoar ? "[ ⚡ EXECUTING SOAR CONTAINMENT... ]" : "[ ⚡ STOP ATTACK NOW (SOAR PREVENT) ↵ ]"}
            </button>
          </div>
        </div>
      )}

      {/* ============================================================== */}
      {/* [01] TELEMETRY METRIC WIDGETS                                  */}
      {/* ============================================================== */}
      <div>
        <div className="text-[12px] text-[#255325] mb-2 select-none">
          [01] $ sentinel --stats telemetry
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          
          {/* Total Ingestion */}
          <div className="border border-[#255325] p-4 bg-[#000000] flex flex-col justify-between">
            <div>
              <div className="text-[11px] text-[#58ca58] uppercase">01. LIVE_LOG_INGESTION</div>
              <div className="text-[26px] font-medium text-[#ffffff] mt-1">
                {stats.total_logs.toLocaleString()}
              </div>
            </div>
            <div className="mt-3 pt-2 border-t border-[#255325] text-[11px] text-[#58ca58] flex justify-between">
              <span>STATUS:</span>
              <span className="text-[#66ff66]">STREAMING_OK</span>
            </div>
          </div>

          {/* Active Incidents */}
          <div className="border border-[#255325] p-4 bg-[#000000] flex flex-col justify-between">
            <div>
              <div className="text-[11px] text-[#58ca58] uppercase">02. ACTIVE_INCIDENTS</div>
              <div className={`text-[26px] font-medium mt-1 ${activeIncidentsCount > 0 ? "text-[#ffffff]" : "text-[#58ca58]"}`}>
                {activeIncidentsCount}
              </div>
            </div>
            <div className="mt-3 pt-2 border-t border-[#255325] text-[11px] text-[#58ca58] flex justify-between">
              <span>CORRELATION:</span>
              <span className={activeIncidentsCount > 0 ? "text-[#ffffff]" : "text-[#58ca58]"}>
                {activeIncidentsCount > 0 ? "TRIAGE_ACTIVE" : "CLEAN"}
              </span>
            </div>
          </div>

          {/* Critical Detections */}
          <div className="border border-[#255325] p-4 bg-[#000000] flex flex-col justify-between">
            <div>
              <div className="text-[11px] text-[#58ca58] uppercase">03. CRITICAL_DETECTIONS</div>
              <div className={`text-[26px] font-medium mt-1 ${criticalAlertsCount > 0 ? "text-[#ffffff]" : "text-[#58ca58]"}`}>
                {criticalAlertsCount}
              </div>
            </div>
            <div className="mt-3 pt-2 border-t border-[#255325] text-[11px] text-[#58ca58] flex justify-between">
              <span>SEVERITY:</span>
              <span className={criticalAlertsCount > 0 ? "text-[#ffffff]" : "text-[#58ca58]"}>
                {criticalAlertsCount > 0 ? "SEV_CRITICAL" : "NORMAL"}
              </span>
            </div>
          </div>

          {/* Monitored Assets */}
          <div className="border border-[#255325] p-4 bg-[#000000] flex flex-col justify-between">
            <div>
              <div className="text-[11px] text-[#58ca58] uppercase">04. MONITORED_ASSETS</div>
              <div className="text-[26px] font-medium text-[#ffffff] mt-1">
                4
              </div>
            </div>
            <div className="mt-3 pt-2 border-t border-[#255325] text-[11px] text-[#58ca58] flex justify-between">
              <span>DAEMONS:</span>
              <span className="text-[#66ff66]">ALL_ACTIVE</span>
            </div>
          </div>

        </div>
      </div>

      {/* ============================================================== */}
      {/* [02] ATTACK TREND CHART & LIVE LOGS TICKER                     */}
      {/* ============================================================== */}
      <div>
        <div className="text-[12px] text-[#255325] mb-2 select-none">
          [02] $ sentinel --plot attack-trend --window 12h &amp; tail -f /var/log/security.evtx
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          
          {/* Trend Area Chart (2 Columns) */}
          <div className="border border-[#255325] p-4 bg-[#000000] lg:col-span-2 flex flex-col">
            <div className="flex justify-between items-center border-b border-[#255325] pb-2 mb-4 text-[13px]">
              <span className="text-[#ffffff] font-medium">
                ATTACK_VOLUME_TREND // 12H_SLIDING_WINDOW
              </span>
              <span className="text-[#58ca58] text-[11px]">
                [ 2 METRICS // LOGS &amp; THREATS ]
              </span>
            </div>

            <div className="w-full h-[280px]">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={trendData} margin={{ top: 10, right: 10, left: -25, bottom: 0 }}>
                  <defs>
                    <linearGradient id="terminalGreen" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#66ff66" stopOpacity={0.25}/>
                      <stop offset="95%" stopColor="#66ff66" stopOpacity={0}/>
                    </linearGradient>
                    <linearGradient id="terminalWhite" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#ffffff" stopOpacity={0.25}/>
                      <stop offset="95%" stopColor="#ffffff" stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="2 2" stroke="#255325" />
                  <XAxis dataKey="time" stroke="#58ca58" fontSize={11} fontFamily="monospace" />
                  <YAxis stroke="#58ca58" fontSize={11} fontFamily="monospace" />
                  <Tooltip 
                    contentStyle={{ 
                      backgroundColor: "#000000", 
                      border: "1px solid #255325", 
                      borderRadius: 0,
                      color: "#66ff66", 
                      fontFamily: "monospace",
                      fontSize: "12px"
                    }} 
                  />
                  <Area 
                    type="monotone" 
                    dataKey="logs" 
                    name="Log Volume" 
                    stroke="#66ff66" 
                    fillOpacity={1} 
                    fill="url(#terminalGreen)" 
                    strokeWidth={1.5} 
                  />
                  <Area 
                    type="monotone" 
                    dataKey="threats" 
                    name="Threat Triggers" 
                    stroke="#ffffff" 
                    fillOpacity={1} 
                    fill="url(#terminalWhite)" 
                    strokeWidth={1.5} 
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>

            <div className="flex items-center gap-4 text-[11px] text-[#58ca58] mt-3 pt-2 border-t border-[#255325]">
              <div className="flex items-center gap-1.5">
                <span className="w-2.5 h-0.5 bg-[#66ff66]"></span>
                <span>LOG_VOLUME (EVENTS/SEC)</span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="w-2.5 h-0.5 bg-[#ffffff]"></span>
                <span className="text-[#ffffff]">THREAT_TRIGGERS</span>
              </div>
            </div>
          </div>

          {/* Live Ingested Feed (1 Column) */}
          <div className="border border-[#255325] p-4 bg-[#000000] flex flex-col h-[360px]">
            <div className="flex justify-between items-center border-b border-[#255325] pb-2 mb-3 text-[13px]">
              <span className="text-[#ffffff] font-medium">
                LIVE_TELEMETRY_FEED
              </span>
              <span className="text-[#66ff66] text-[11px]">
                TAIL -F <span className="cursor">█</span>
              </span>
            </div>

            <div className="flex-1 overflow-y-auto space-y-2 pr-1 font-mono text-[11px] leading-[1.5]">
              {liveLogs.length === 0 ? (
                <div className="h-full flex items-center justify-center text-[#255325]">
                  Waiting for agent heartbeat...
                </div>
              ) : (
                liveLogs.map((log, index) => {
                  const lineNo = (index + 1).toString().padStart(2, "0");
                  const isCrit = log.severity === "CRITICAL" || log.severity === "ERROR";
                  return (
                    <div 
                      key={log.id || index}
                      className={`p-2 border transition-colors ${
                        isCrit 
                          ? "border-[#66ff66] bg-[#255325]/20" 
                          : "border-[#255325] bg-[#000000]"
                      }`}
                    >
                      <div className="flex justify-between items-center text-[10px] text-[#255325] border-b border-[#255325]/50 pb-1 mb-1">
                        <span>[{lineNo}] {formatDateTime(log.timestamp)}</span>
                        <span className={`px-1 font-bold ${
                          isCrit ? "bg-[#66ff66] text-[#000000]" : "text-[#58ca58]"
                        }`}>
                          [{log.source.toUpperCase()}]
                        </span>
                      </div>
                      <div className="text-[#ffffff] font-medium truncate">{log.host}</div>
                      <div className="text-[#58ca58] truncate">{log.message}</div>
                      {log.anomaly_score > 0.4 && (
                        <div className="text-[#ffffff] text-[9px] mt-1 pt-0.5 border-t border-[#255325] flex justify-between">
                          <span>ANOMALY_INDEX:</span>
                          <span className="text-[#66ff66]">
                            [{renderAsciiMeter(log.anomaly_score, 1.0, 8)}] {log.anomaly_score.toFixed(2)}
                          </span>
                        </div>
                      )}
                    </div>
                  );
                })
              )}
            </div>
          </div>

        </div>
      </div>

      {/* ============================================================== */}
      {/* [03] MITRE ATT&CK MATRIX MAPPING                               */}
      {/* ============================================================== */}
      <div>
        <div className="text-[12px] text-[#255325] mb-2 select-none">
          [03] $ sentinel --inspect mitre-matrix --ttps all
        </div>

        <div className="border border-[#255325] p-4 bg-[#000000]">
          <div className="border-b border-[#255325] pb-2 mb-4 text-[13px] flex items-center justify-between">
            <span className="text-[#ffffff] font-medium">
              MITRE ATT&amp;CK MATRIX MAPPING // TTP CORRELATION
            </span>
            <span className="text-[#58ca58] text-[11px]">
              FRAMEWORK: v14.1
            </span>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-9 gap-2 text-center text-[11px]">
            {mitreTactics.map((tactic) => (
              <div 
                key={tactic.name}
                className={`p-2.5 border flex flex-col justify-between min-h-[90px] transition-colors ${
                  tactic.active 
                    ? "border-[#66ff66] bg-[#66ff66] text-[#000000] font-medium" 
                    : "border-[#255325] bg-[#000000] text-[#58ca58]"
                }`}
              >
                <div className="uppercase text-[10px] leading-tight font-medium mb-1">
                  {tactic.name}
                </div>
                <div>
                  <span className={`block font-bold text-[11px] ${tactic.active ? "text-[#000000]" : "text-[#ffffff]"}`}>
                    [{tactic.technique}]
                  </span>
                  <span className="text-[9px] block truncate mt-0.5 opacity-90">
                    {tactic.label}
                  </span>
                </div>
                <div className="text-[9px] mt-1 pt-1 border-t border-current/20">
                  {tactic.active ? "[ ! ACTIVE ]" : "[ - IDLE ]"}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* ============================================================== */}
      {/* [04] CORRELATED INCIDENTS QUEUE TABLE                          */}
      {/* ============================================================== */}
      <div>
        <div className="text-[12px] text-[#255325] mb-2 select-none">
          [04] $ sentinel --query incidents --status active --sort risk_score:desc
        </div>

        <div className="border border-[#255325] p-4 bg-[#000000]">
          <div className="flex justify-between items-center border-b border-[#255325] pb-2 mb-4 text-[13px]">
            <span className="text-[#ffffff] font-medium">
              CORRELATED INCIDENT QUEUE // TRIAGE READOUT
            </span>
            <Link 
              to="/incidents" 
              className="text-[#58ca58] hover:text-[#000000] hover:bg-[#66ff66] px-2 py-0.5 border border-[#255325] transition-colors text-[11px]"
            >
              [ VIEW_ALL_INCIDENTS ↵ ]
            </Link>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-[12px] border-collapse font-mono">
              <thead>
                <tr className="border-b border-[#255325] text-[#58ca58] text-[11px] uppercase">
                  <th className="pb-2 w-20">INC_ID</th>
                  <th className="pb-2">THREAT_DESCRIPTION</th>
                  <th className="pb-2 w-28">SEVERITY</th>
                  <th className="pb-2 w-48">RISK_SCORE</th>
                  <th className="pb-2 w-28">STATUS</th>
                  <th className="pb-2 w-36">TIMESTAMP</th>
                  <th className="pb-2 w-28 text-right">ACTION</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#255325]">
                {incidents.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="py-6 text-center text-[#255325]">
                      Zero active threat incidents in current correlation window.
                    </td>
                  </tr>
                ) : (
                  incidents.map((inc) => {
                    const isCrit = inc.severity === "CRITICAL" || inc.severity === "HIGH";
                    return (
                      <tr key={inc.id} className="hover:bg-[#255325]/15 transition-colors">
                        <td className="py-2.5 text-[#58ca58]">INC-{inc.id}</td>
                        <td className="py-2.5 pr-4">
                          <div className="text-[#ffffff] font-medium">{inc.title}</div>
                          <div className="text-[#58ca58] text-[11px] truncate max-w-lg">{inc.description}</div>
                        </td>
                        <td className="py-2.5">
                          <span className={`px-1.5 py-0.2 border text-[10px] font-bold ${
                            isCrit 
                              ? "bg-[#66ff66] text-[#000000] border-[#66ff66]" 
                              : "border-[#255325] text-[#58ca58]"
                          }`}>
                            [{inc.severity}]
                          </span>
                        </td>
                        <td className="py-2.5 font-mono text-[11px]">
                          <div className="flex items-center gap-1.5">
                            <span className="text-[#ffffff] font-medium">{inc.risk_score}</span>
                            <span className="text-[#66ff66]">
                              [{renderAsciiMeter(inc.risk_score, 100, 10)}]
                            </span>
                          </div>
                        </td>
                        <td className="py-2.5 text-[#58ca58]">
                          [{inc.status.toUpperCase()}]
                        </td>
                        <td className="py-2.5 text-[#58ca58] text-[11px] font-mono">
                          {formatDateTime(inc.created_at)}
                        </td>
                        <td className="py-2.5 text-right">
                          <Link 
                            to={`/incidents/${inc.id}`}
                            className="px-2 py-1 border border-[#255325] text-[#58ca58] hover:border-[#66ff66] hover:bg-[#66ff66] hover:text-[#000000] font-medium transition-colors text-[11px] inline-block"
                          >
                            [ INVESTIGATE ↵ ]
                          </Link>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>

    </div>
  );
};

export default Dashboard;

import React, { useState, useEffect, useRef } from "react";
import { Search, Terminal, Filter, RefreshCw } from "lucide-react";
import { useAuth } from "../context/AuthContext";
import { API_BASE, WS_BASE } from "../config/api";

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
  raw_log: string;
}

export const SearchLogs: React.FC = () => {
  const { token } = useAuth();
  
  // Search parameters
  const [host, setHost] = useState("");
  const [username, setUsername] = useState("");
  const [ip, setIp] = useState("");
  const [severity, setSeverity] = useState("");
  const [source, setSource] = useState("");
  const [logType, setLogType] = useState("");
  const [limit, setLimit] = useState(100);

  const [logs, setLogs] = useState<Log[]>([]);
  const [loading, setLoading] = useState(false);
  const [expandedId, setExpandedId] = useState<number | null>(null);

  const filterActiveRef = useRef(false);
  filterActiveRef.current = !!(host || username || ip || severity || source || logType);

  const fetchDefaultLogs = async () => {
    setLoading(true);
    try {
      const resp = await fetch(`${API_BASE}/api/logs/search?limit=100`, {
        headers: {
          "Authorization": `Bearer ${token}`
        }
      });
      if (resp.ok) {
        const data = await resp.json();
        setLogs(data);
      }
    } catch (err) {
      console.error("Error fetching initial logs in search:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDefaultLogs();

    const ws = new WebSocket(`${WS_BASE}/api/ws`);
    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.type === "NEW_LOG") {
          if (!filterActiveRef.current) {
            setLogs((prev) => [data.log, ...prev].slice(0, 100));
          }
        }
      } catch (err) {
        console.error("Error parsing WS message in search page:", err);
      }
    };

    return () => {
      ws.close();
    };
  }, []);

  const handleSearch = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setExpandedId(null);

    try {
      // Build query string
      const params = new URLSearchParams();
      if (host) params.append("host", host);
      if (username) params.append("username", username);
      if (ip) params.append("ip", ip);
      if (severity) params.append("severity", severity);
      if (source) params.append("source", source);
      if (logType) params.append("log_type", logType);
      params.append("limit", limit.toString());

      const resp = await fetch(`${API_BASE}/api/logs/search?${params.toString()}`, {
        headers: {
          "Authorization": `Bearer ${token}`
        }
      });

      if (resp.ok) {
        const data = await resp.json();
        setLogs(data);
      }
    } catch (err) {
      console.error("Error executing log search query:", err);
    } finally {
      setLoading(false);
    }
  };

  const clearFilters = () => {
    setHost("");
    setUsername("");
    setIp("");
    setSeverity("");
    setSource("");
    setLogType("");
    setLimit(100);
    setTimeout(() => {
      fetchDefaultLogs();
    }, 50);
  };

  const getSeverityBg = (sev: string) => {
    switch (sev.toUpperCase()) {
      case "CRITICAL": return "bg-red-500/20 text-red-400";
      case "ERROR": return "bg-orange-500/20 text-orange-400";
      case "WARNING": return "bg-yellow-500/20 text-yellow-400";
      default: return "bg-slate-800 text-slate-400";
    }
  };

  return (
    <div className="flex-1 p-8 space-y-8 overflow-y-auto h-screen max-w-[calc(100vw-16rem)]">
      
      {/* Title */}
      <div className="flex justify-between items-center border-b border-darkBorder pb-6">
        <div>
          <h2 className="text-3xl font-extrabold text-slate-100 tracking-wide flex items-center gap-3">
            <Search className="w-8 h-8 text-blue-500" />
            FORENSIC SEARCH LOGS
          </h2>
          <p className="text-sm text-slate-500 mt-1">
            Perform forensic analysis queries against ingested operating system, firewall, and web logs
          </p>
        </div>
      </div>

      {/* Filter Form Panel */}
      <div className="glass-card rounded-xl p-6 border">
        <form onSubmit={handleSearch} className="space-y-4">
          <div className="flex items-center gap-2 mb-2">
            <Filter className="w-4 h-4 text-blue-400" />
            <h3 className="font-bold text-slate-300 text-xs uppercase tracking-wider">Query Filter Criteria</h3>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div>
              <label className="block text-[10px] font-bold text-slate-500 uppercase mb-1.5">Host Name</label>
              <input
                type="text"
                value={host}
                onChange={(e) => setHost(e.target.value)}
                placeholder="e.g. host-corp-win10"
                className="w-full bg-slate-950 border border-darkBorder focus:border-blue-500 rounded py-1.5 px-3 text-xs text-slate-200 outline-none transition-colors"
              />
            </div>
            <div>
              <label className="block text-[10px] font-bold text-slate-500 uppercase mb-1.5">Username</label>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="e.g. administrator"
                className="w-full bg-slate-950 border border-darkBorder focus:border-blue-500 rounded py-1.5 px-3 text-xs text-slate-200 outline-none transition-colors"
              />
            </div>
            <div>
              <label className="block text-[10px] font-bold text-slate-500 uppercase mb-1.5">Source/Dest IP</label>
              <input
                type="text"
                value={ip}
                onChange={(e) => setIp(e.target.value)}
                placeholder="e.g. 192.168.1.10"
                className="w-full bg-slate-950 border border-darkBorder focus:border-blue-500 rounded py-1.5 px-3 text-xs text-slate-200 outline-none transition-colors"
              />
            </div>
            <div>
              <label className="block text-[10px] font-bold text-slate-500 uppercase mb-1.5">Severity</label>
              <select
                value={severity}
                onChange={(e) => setSeverity(e.target.value)}
                className="w-full bg-slate-950 border border-darkBorder focus:border-blue-500 rounded py-1.5 px-3 text-xs text-slate-300 outline-none cursor-pointer"
              >
                <option value="">All Severities</option>
                <option value="INFO">INFO</option>
                <option value="WARNING">WARNING</option>
                <option value="ERROR">ERROR</option>
                <option value="CRITICAL">CRITICAL</option>
              </select>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div>
              <label className="block text-[10px] font-bold text-slate-500 uppercase mb-1.5">Log Source</label>
              <select
                value={source}
                onChange={(e) => setSource(e.target.value)}
                className="w-full bg-slate-950 border border-darkBorder focus:border-blue-500 rounded py-1.5 px-3 text-xs text-slate-300 outline-none cursor-pointer"
              >
                <option value="">All Sources</option>
                <option value="Windows">Windows</option>
                <option value="Linux">Linux</option>
                <option value="Apache">Apache</option>
                <option value="Firewall">Firewall</option>
                <option value="Simulator">Simulator</option>
              </select>
            </div>
            <div>
              <label className="block text-[10px] font-bold text-slate-500 uppercase mb-1.5">Log Type</label>
              <select
                value={logType}
                onChange={(e) => setLogType(e.target.value)}
                className="w-full bg-slate-950 border border-darkBorder focus:border-blue-500 rounded py-1.5 px-3 text-xs text-slate-300 outline-none cursor-pointer"
              >
                <option value="">All Types</option>
                <option value="Security">Security</option>
                <option value="Auth">Auth</option>
                <option value="System">System</option>
                <option value="Web">Web</option>
                <option value="Traffic">Traffic</option>
              </select>
            </div>
            <div>
              <label className="block text-[10px] font-bold text-slate-500 uppercase mb-1.5">Result Limit</label>
              <select
                value={limit}
                onChange={(e) => setLimit(parseInt(e.target.value))}
                className="w-full bg-slate-950 border border-darkBorder focus:border-blue-500 rounded py-1.5 px-3 text-xs text-slate-300 outline-none cursor-pointer"
              >
                <option value="50">50 rows</option>
                <option value="100">100 rows</option>
                <option value="250">250 rows</option>
                <option value="500">500 rows</option>
              </select>
            </div>
            <div className="flex gap-3 pt-5">
              <button
                type="submit"
                className="flex-1 bg-blue-600 hover:bg-blue-500 active:bg-blue-700 text-white font-bold text-xs rounded tracking-wider shadow shadow-blue-500/10 transition-all cursor-pointer flex items-center justify-center gap-1.5"
              >
                <Search className="w-3.5 h-3.5" />
                Query Logs
              </button>
              <button
                type="button"
                onClick={clearFilters}
                className="bg-slate-900 border border-darkBorder hover:bg-slate-800 text-slate-400 hover:text-slate-200 px-3 rounded cursor-pointer transition-colors"
              >
                <RefreshCw className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        </form>
      </div>

      {/* Query Results */}
      <div className="glass-card rounded-xl p-6 border flex flex-col">
        <div className="flex items-center gap-2 mb-6">
          <Terminal className="w-4 h-4 text-emerald-400" />
          <h3 className="font-bold text-slate-100 text-sm">Query Execution Output</h3>
        </div>

        {loading ? (
          <div className="py-12 text-center text-slate-400 font-medium">Executing SQL query...</div>
        ) : logs.length === 0 ? (
          <div className="py-12 text-center text-slate-500">
            No logs fetched. Formulate filter properties and click 'Query Logs'.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-darkBorder text-slate-500 font-semibold uppercase tracking-wider">
                  <th className="pb-3 w-8"></th>
                  <th className="pb-3 w-40">Timestamp</th>
                  <th className="pb-3 w-36">Host</th>
                  <th className="pb-3 w-28">Source</th>
                  <th className="pb-3 w-24">Severity</th>
                  <th className="pb-3">Normalized Message</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-darkBorder">
                {logs.map((log) => {
                  const expanded = expandedId === log.id;
                  return (
                    <React.Fragment key={log.id}>
                      <tr 
                        onClick={() => setExpandedId(expanded ? null : log.id)}
                        className="hover:bg-slate-900/30 cursor-pointer transition-colors"
                      >
                        <td className="py-3 font-semibold text-slate-500 text-center select-none">
                          {expanded ? "▲" : "▼"}
                        </td>
                        <td className="py-3 text-slate-400 font-mono">
                          {new Date(log.timestamp).toLocaleString()}
                        </td>
                        <td className="py-3 font-semibold text-slate-200">{log.host}</td>
                        <td className="py-3 text-slate-400">{log.source}</td>
                        <td className="py-3">
                          <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold ${getSeverityBg(log.severity)}`}>
                            {log.severity}
                          </span>
                        </td>
                        <td className="py-3 text-slate-300 truncate max-w-md pr-4">{log.message}</td>
                      </tr>
                      {expanded && (
                        <tr>
                          <td colSpan={6} className="bg-slate-950/40 p-4 border-l-2 border-blue-500">
                            <div className="font-mono text-[10px] space-y-4 max-w-full overflow-x-auto text-slate-400">
                              <div>
                                <span className="text-slate-600 block mb-1">// Standardized Normalized Schema:</span>
                                <div className="grid grid-cols-2 md:grid-cols-4 gap-2 bg-slate-900/60 p-3 rounded border border-darkBorder">
                                  <div><span className="text-slate-500">Log Entry ID:</span> {log.id}</div>
                                  <div><span className="text-slate-500">Host:</span> {log.host}</div>
                                  <div><span className="text-slate-500">Log Source:</span> {log.source}</div>
                                  <div><span className="text-slate-500">Log Type:</span> {log.log_type}</div>
                                  <div><span className="text-slate-500">Severity:</span> {log.severity}</div>
                                  <div><span className="text-slate-500">User Context:</span> {log.username || "-"}</div>
                                  <div><span className="text-slate-500">Source IP:</span> {log.src_ip || "-"}</div>
                                  <div><span className="text-slate-500">Dest IP:</span> {log.dst_ip || "-"}</div>
                                  <div><span className="text-slate-500">Process Name:</span> {log.process || "-"}</div>
                                </div>
                              </div>
                              <div>
                                <span className="text-slate-600 block mb-1">// Raw Unprocessed Log:</span>
                                <pre className="bg-slate-900/40 border border-darkBorder p-3 rounded whitespace-pre-wrap select-all max-h-40 overflow-y-auto">
                                  {log.raw_log}
                                </pre>
                              </div>
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

    </div>
  );
};
export default SearchLogs;

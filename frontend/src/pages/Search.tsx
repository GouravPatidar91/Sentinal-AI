import React, { useState, useEffect, useRef } from "react";
import { useAuth } from "../context/AuthContext";
import { API_BASE, WS_BASE } from "../config/api";
import { formatDateTime } from "../utils/time";

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
    const activeToken = token || localStorage.getItem("token");
    try {
      const resp = await fetch(`${API_BASE}/api/logs/search?limit=100`, {
        headers: {
          "Authorization": `Bearer ${activeToken}`
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
  }, [token]);

  const handleSearch = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setExpandedId(null);

    const activeToken = token || localStorage.getItem("token");
    try {
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
          "Authorization": `Bearer ${activeToken}`
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

  const getSeverityBadge = (sev: string) => {
    switch (sev.toUpperCase()) {
      case "CRITICAL":
        return <span className="bg-[#66ff66] text-[#000000] font-bold px-1.5 py-0.5 select-none">[CRITICAL]</span>;
      case "ERROR":
        return <span className="text-[#ffffff] border border-[#66ff66] px-1.5 py-0.5 select-none">[ERROR]</span>;
      case "WARNING":
        return <span className="text-[#66ff66] border border-[#255325] px-1.5 py-0.5 select-none">[WARNING]</span>;
      default:
        return <span className="text-[#58ca58] border border-[#255325] px-1.5 py-0.5 select-none">[INFO]</span>;
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
              <span className="text-[#58ca58]">sentinel@soc:~$</span> sentinel --search logs --pipeline ingested-events --stream
            </span>
          </div>
          <span className="px-2 py-0.5 bg-[#66ff66] text-[#000000] font-medium text-[11px] select-none">
            [ CHANNEL: 03 // SEARCH_LOGS ]
          </span>
        </div>

        <div className="flex flex-col md:flex-row md:items-center justify-between gap-2">
          <div>
            <h1 className="text-[22px] sm:text-[26px] font-medium text-[#ffffff] tracking-tight uppercase">
              Forensic Log Search // SIEM Query Console
            </h1>
            <p className="text-[14px] text-[#58ca58] mt-1">
              Direct telemetry search against normalized Linux SSH auth, Windows EventLog (4624/4625), and Apache access pipelines.
            </p>
          </div>
          <div className="text-[12px] text-[#58ca58] text-right font-mono shrink-0">
            <div>INDEX_STATUS: <span className="text-[#ffffff]">ACTIVE_INDEX</span></div>
            <div>STREAM_SYNC: <span className="text-[#66ff66]">LIVE (TAIL -F)</span></div>
          </div>
        </div>
      </div>

      {/* Query Filter Criteria Form */}
      <div>
        <div className="text-[12px] text-[#255325] mb-2 select-none">
          [01] $ sentinel --query-params --host "{host || '*'}" --user "{username || '*'}" --ip "{ip || '*'}"
        </div>

        <div className="border border-[#255325] p-4 bg-[#000000]">
          <div className="border-b border-[#255325] pb-2 mb-4 text-[12px] flex justify-between items-center">
            <span className="text-[#ffffff] font-medium uppercase tracking-wider">
              QUERY_FILTER_CRITERIA // PARAMETERS
            </span>
            <span className="text-[#58ca58] text-[11px]">
              MODE: SQL_INTERPOLATED
            </span>
          </div>

          <form onSubmit={handleSearch} className="space-y-4">
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              <div>
                <label className="block text-[11px] text-[#58ca58] uppercase mb-1">
                  HOST_NAME:
                </label>
                <input
                  type="text"
                  value={host}
                  onChange={(e) => setHost(e.target.value)}
                  placeholder="e.g. host-corp-win10"
                  className="w-full bg-[#000000] border border-[#255325] focus:border-[#66ff66] p-2 text-[12px] text-[#ffffff] placeholder-[#255325] outline-none font-mono transition-colors"
                />
              </div>

              <div>
                <label className="block text-[11px] text-[#58ca58] uppercase mb-1">
                  USERNAME_CONTEXT:
                </label>
                <input
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="e.g. administrator"
                  className="w-full bg-[#000000] border border-[#255325] focus:border-[#66ff66] p-2 text-[12px] text-[#ffffff] placeholder-[#255325] outline-none font-mono transition-colors"
                />
              </div>

              <div>
                <label className="block text-[11px] text-[#58ca58] uppercase mb-1">
                  SRC_OR_DST_IP:
                </label>
                <input
                  type="text"
                  value={ip}
                  onChange={(e) => setIp(e.target.value)}
                  placeholder="e.g. 192.168.1.10"
                  className="w-full bg-[#000000] border border-[#255325] focus:border-[#66ff66] p-2 text-[12px] text-[#ffffff] placeholder-[#255325] outline-none font-mono transition-colors"
                />
              </div>

              <div>
                <label className="block text-[11px] text-[#58ca58] uppercase mb-1">
                  SEVERITY_LEVEL:
                </label>
                <select
                  value={severity}
                  onChange={(e) => setSeverity(e.target.value)}
                  className="w-full bg-[#000000] border border-[#255325] focus:border-[#66ff66] p-2 text-[12px] text-[#66ff66] outline-none font-mono cursor-pointer transition-colors"
                >
                  <option value="">[ALL_SEVERITIES]</option>
                  <option value="INFO">[INFO]</option>
                  <option value="WARNING">[WARNING]</option>
                  <option value="ERROR">[ERROR]</option>
                  <option value="CRITICAL">[CRITICAL]</option>
                </select>
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              <div>
                <label className="block text-[11px] text-[#58ca58] uppercase mb-1">
                  LOG_SOURCE:
                </label>
                <select
                  value={source}
                  onChange={(e) => setSource(e.target.value)}
                  className="w-full bg-[#000000] border border-[#255325] focus:border-[#66ff66] p-2 text-[12px] text-[#66ff66] outline-none font-mono cursor-pointer transition-colors"
                >
                  <option value="">[ALL_SOURCES]</option>
                  <option value="Windows">[WINDOWS]</option>
                  <option value="Linux">[LINUX]</option>
                  <option value="Apache">[APACHE]</option>
                  <option value="Firewall">[FIREWALL]</option>
                  <option value="Simulator">[SIMULATOR]</option>
                </select>
              </div>

              <div>
                <label className="block text-[11px] text-[#58ca58] uppercase mb-1">
                  LOG_TYPE:
                </label>
                <select
                  value={logType}
                  onChange={(e) => setLogType(e.target.value)}
                  className="w-full bg-[#000000] border border-[#255325] focus:border-[#66ff66] p-2 text-[12px] text-[#66ff66] outline-none font-mono cursor-pointer transition-colors"
                >
                  <option value="">[ALL_TYPES]</option>
                  <option value="Security">[SECURITY]</option>
                  <option value="Auth">[AUTH]</option>
                  <option value="System">[SYSTEM]</option>
                  <option value="Web">[WEB]</option>
                  <option value="Traffic">[TRAFFIC]</option>
                </select>
              </div>

              <div>
                <label className="block text-[11px] text-[#58ca58] uppercase mb-1">
                  ROW_LIMIT:
                </label>
                <select
                  value={limit}
                  onChange={(e) => setLimit(parseInt(e.target.value))}
                  className="w-full bg-[#000000] border border-[#255325] focus:border-[#66ff66] p-2 text-[12px] text-[#66ff66] outline-none font-mono cursor-pointer transition-colors"
                >
                  <option value="50">50 records</option>
                  <option value="100">100 records</option>
                  <option value="250">250 records</option>
                  <option value="500">500 records</option>
                </select>
              </div>

              <div className="flex gap-2 items-end pt-2">
                <button
                  type="submit"
                  className="flex-1 px-4 py-2 bg-[#66ff66] text-[#000000] hover:bg-[#ffffff] font-medium text-[12px] transition-colors cursor-pointer text-center select-none"
                >
                  [ ↵ EXECUTE_QUERY ]
                </button>
                <button
                  type="button"
                  onClick={clearFilters}
                  className="px-3 py-2 border border-[#255325] text-[#58ca58] hover:text-[#ffffff] hover:border-[#66ff66] text-[12px] transition-colors cursor-pointer select-none"
                  title="Reset Filter Criteria"
                >
                  [ ↺ RESET ]
                </button>
              </div>
            </div>
          </form>
        </div>
      </div>

      {/* Query Execution Output Table */}
      <div>
        <div className="text-[12px] text-[#255325] mb-2 select-none">
          [02] $ sentinel --render output --format stream --count {logs.length}
        </div>

        <div className="border border-[#255325] bg-[#000000] p-4">
          <div className="flex justify-between items-center border-b border-[#255325] pb-2 mb-3 text-[12px]">
            <span className="text-[#ffffff] font-medium">
              INGESTED_EVENT_STREAM // RECORDS_LOADED: {logs.length}
            </span>
            <span className="text-[#66ff66] text-[11px]">
              TAIL_STATUS: {filterActiveRef.current ? "[FILTERED]" : "[LIVE_FEED █]"}
            </span>
          </div>

          {loading ? (
            <div className="py-12 text-center text-[#58ca58] font-mono text-[13px]">
              &gt; Querying forensic logs index...
            </div>
          ) : logs.length === 0 ? (
            <div className="py-12 text-center text-[#255325] font-mono text-[13px]">
              [ - ] No logs fetched. Formulate filter properties and click '[ ↵ EXECUTE_QUERY ]'.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-[12px] border-collapse font-mono">
                <thead>
                  <tr className="border-b border-[#255325] text-[#58ca58] text-[11px] uppercase tracking-wider">
                    <th className="pb-2 w-8"></th>
                    <th className="pb-2 w-44">TIMESTAMP</th>
                    <th className="pb-2 w-36">HOST</th>
                    <th className="pb-2 w-28">SOURCE</th>
                    <th className="pb-2 w-28">SEVERITY</th>
                    <th className="pb-2">NORMALIZED_MESSAGE</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#255325]">
                  {logs.map((log) => {
                    const expanded = expandedId === log.id;
                    return (
                      <React.Fragment key={log.id}>
                        <tr 
                          onClick={() => setExpandedId(expanded ? null : log.id)}
                          className="hover:bg-[#255325]/20 cursor-pointer transition-colors"
                        >
                          <td className="py-3 text-center text-[#255325] font-bold select-none text-[10px]">
                            {expanded ? "▼" : "▶"}
                          </td>
                          <td className="py-3 text-[#58ca58] text-[11px] font-mono whitespace-nowrap">
                            {formatDateTime(log.timestamp)}
                          </td>
                          <td className="py-3 text-[#ffffff] font-medium">
                            {log.host}
                          </td>
                          <td className="py-3 text-[#58ca58]">
                            [{log.source.toUpperCase()}]
                          </td>
                          <td className="py-3">
                            {getSeverityBadge(log.severity)}
                          </td>
                          <td className="py-3 text-[#ffffff] truncate max-w-lg pr-4">
                            {log.message}
                          </td>
                        </tr>
                        {expanded && (
                          <tr>
                            <td colSpan={6} className="bg-[#000000] p-4 border-l-2 border-[#66ff66] border-b border-[#255325]">
                              <div className="font-mono text-[11px] space-y-3 max-w-full overflow-x-auto text-[#58ca58]">
                                <div className="text-[#ffffff] font-medium text-[12px] border-b border-[#255325] pb-1">
                                  // STANDARDIZED NORMALIZED RECORD #{log.id}
                                </div>
                                <div className="grid grid-cols-2 md:grid-cols-4 gap-2 bg-[#255325]/10 p-3 border border-[#255325]">
                                  <div><span className="text-[#255325]">RECORD_ID:</span> {log.id}</div>
                                  <div><span className="text-[#255325]">HOST_NAME:</span> <span className="text-[#ffffff]">{log.host}</span></div>
                                  <div><span className="text-[#255325]">LOG_SOURCE:</span> {log.source}</div>
                                  <div><span className="text-[#255325]">LOG_TYPE:</span> {log.log_type}</div>
                                  <div><span className="text-[#255325]">SEVERITY:</span> <span className="text-[#ffffff]">{log.severity}</span></div>
                                  <div><span className="text-[#255325]">USER_CONTEXT:</span> <span className="text-[#ffffff]">{log.username || "N/A"}</span></div>
                                  <div><span className="text-[#255325]">SOURCE_IP:</span> <span className="text-[#ffffff]">{log.src_ip || "N/A"}</span></div>
                                  <div><span className="text-[#255325]">DEST_IP:</span> <span className="text-[#ffffff]">{log.dst_ip || "N/A"}</span></div>
                                  <div><span className="text-[#255325]">PROCESS:</span> <span className="text-[#ffffff]">{log.process || "N/A"}</span></div>
                                </div>
                                <div>
                                  <div className="text-[#255325] text-[10px] uppercase mb-1">
                                    // RAW UNPROCESSED TELEMETRY PAYLOAD:
                                  </div>
                                  <pre className="bg-[#000000] border border-[#255325] p-3 text-[#66ff66] text-[11px] whitespace-pre-wrap select-all max-h-48 overflow-y-auto leading-relaxed">
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

    </div>
  );
};

export default SearchLogs;

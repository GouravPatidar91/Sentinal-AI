import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { API_BASE, WS_BASE } from "../config/api";
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

export const IncidentQueue: React.FC = () => {
  const { token } = useAuth();
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("All");
  const [severityFilter, setSeverityFilter] = useState("All");

  useEffect(() => {
    fetchIncidents();
    
    const ws = new WebSocket(`${WS_BASE}/api/ws`);
    
    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.type === "NEW_LOG" && data.incident) {
          setIncidents((prev) => {
            const filtered = prev.filter(i => i.id !== data.incident.id);
            return [data.incident, ...filtered];
          });
        } else if (data.type === "INCIDENT_UPDATE" && data.incident) {
          setIncidents((prev) => {
            return prev.map(inc => inc.id === data.incident.id ? data.incident : inc);
          });
        }
      } catch (err) {
        console.error("Error parsing WS message in incident queue:", err);
      }
    };
    
    return () => {
      ws.close();
    };
  }, [token]);

  const fetchIncidents = async () => {
    setLoading(true);
    const activeToken = token || localStorage.getItem("token");
    try {
      const resp = await fetch(`${API_BASE}/api/incidents/`, {
        headers: { "Authorization": `Bearer ${activeToken}` }
      });
      if (resp.ok) {
        const data = await resp.json();
        setIncidents(data);
      }
    } catch (err) {
      console.error("Error loading incidents list:", err);
    } finally {
      setLoading(false);
    }
  };

  const renderAsciiMeter = (val: number, max: number, chars = 8) => {
    const filled = Math.min(chars, Math.max(0, Math.round((val / max) * chars)));
    return "█".repeat(filled) + "░".repeat(chars - filled);
  };

  const getSeverityBadge = (sev: string) => {
    switch (sev.toUpperCase()) {
      case "CRITICAL":
        return <span className="bg-[#66ff66] text-[#000000] font-bold px-1.5 py-0.5 select-none">[CRITICAL]</span>;
      case "HIGH":
        return <span className="text-[#ffffff] border border-[#66ff66] px-1.5 py-0.5 select-none">[HIGH]</span>;
      case "MEDIUM":
        return <span className="text-[#66ff66] border border-[#255325] px-1.5 py-0.5 select-none">[MEDIUM]</span>;
      default:
        return <span className="text-[#58ca58] border border-[#255325] px-1.5 py-0.5 select-none">[LOW]</span>;
    }
  };

  const filteredIncidents = incidents.filter((inc) => {
    const matchesSearch = inc.title.toLowerCase().includes(search.toLowerCase()) || 
                          inc.description?.toLowerCase().includes(search.toLowerCase()) ||
                          `INC-${inc.id}`.toLowerCase().includes(search.toLowerCase());
                          
    const matchesStatus = statusFilter === "All" || inc.status === statusFilter;
    const matchesSeverity = severityFilter === "All" || inc.severity === severityFilter;

    return matchesSearch && matchesStatus && matchesSeverity;
  });

  const stats = {
    total: incidents.length,
    new: incidents.filter(i => i.status === "New").length,
    active: incidents.filter(i => ["New", "Investigating"].includes(i.status)).length,
    critical: incidents.filter(i => i.severity === "CRITICAL").length
  };

  return (
    <div className="flex-1 min-w-0 p-6 space-y-6 overflow-y-auto h-screen bg-[#000000] text-[#66ff66] font-mono select-text">
      
      {/* Top Command Session Bar & Title */}
      <div className="border border-[#255325] p-4 bg-[#000000]">
        <div className="flex items-center justify-between text-[13px] border-b border-[#255325] pb-2 mb-3">
          <div className="flex items-center gap-2">
            <span className="text-[#255325] select-none">[00]</span>
            <span className="text-[#66ff66]">
              <span className="text-[#58ca58]">sentinel@soc:~$</span> sentinel --query incidents --status all --sort risk:desc
            </span>
          </div>
          <span className="px-2 py-0.5 bg-[#66ff66] text-[#000000] font-medium text-[11px] select-none">
            [ CHANNEL: 02 // INCIDENTS ]
          </span>
        </div>

        <div className="flex flex-col md:flex-row md:items-center justify-between gap-2">
          <div>
            <h1 className="text-[22px] sm:text-[26px] font-medium text-[#ffffff] tracking-tight uppercase">
              Correlated Incident Queue // Triage Readout
            </h1>
            <p className="text-[14px] text-[#58ca58] mt-1">
              Real-time multi-stage threat correlation, automated risk scoring, and MITRE ATT&amp;CK TTP aggregation.
            </p>
          </div>
          <div className="text-[12px] text-[#58ca58] text-right font-mono shrink-0">
            <div>QUEUE_STATE: <span className="text-[#ffffff]">SYNCHRONIZED</span></div>
            <div>SOCKET: <span className="text-[#66ff66]">ESTABLISHED (1000ms)</span></div>
          </div>
        </div>
      </div>

      {/* Metrics Counters */}
      <div>
        <div className="text-[12px] text-[#255325] mb-2 select-none">
          [01] $ sentinel --stats incidents --summary
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="border border-[#255325] p-4 bg-[#000000] flex flex-col justify-between">
            <div>
              <div className="text-[11px] text-[#58ca58] uppercase">01. TOTAL_RECORDED</div>
              <div className="text-[26px] font-medium text-[#ffffff] mt-1">{stats.total}</div>
            </div>
            <div className="mt-3 pt-2 border-t border-[#255325] text-[11px] text-[#58ca58] flex justify-between">
              <span>LEDGER:</span>
              <span className="text-[#66ff66]">DATABASE_SYNCED</span>
            </div>
          </div>

          <div className="border border-[#255325] p-4 bg-[#000000] flex flex-col justify-between">
            <div>
              <div className="text-[11px] text-[#58ca58] uppercase">02. UNTRIAGED_NEW</div>
              <div className={`text-[26px] font-medium mt-1 ${stats.new > 0 ? "text-[#ffffff]" : "text-[#58ca58]"}`}>
                {stats.new}
              </div>
            </div>
            <div className="mt-3 pt-2 border-t border-[#255325] text-[11px] text-[#58ca58] flex justify-between">
              <span>STATUS:</span>
              <span className={stats.new > 0 ? "text-[#ffffff]" : "text-[#58ca58]"}>
                {stats.new > 0 ? "AWAITING_REVIEW" : "ALL_TRIAGED"}
              </span>
            </div>
          </div>

          <div className="border border-[#255325] p-4 bg-[#000000] flex flex-col justify-between">
            <div>
              <div className="text-[11px] text-[#58ca58] uppercase">03. ACTIVE_INVESTIGATING</div>
              <div className="text-[26px] font-medium text-[#ffffff] mt-1">{stats.active}</div>
            </div>
            <div className="mt-3 pt-2 border-t border-[#255325] text-[11px] text-[#58ca58] flex justify-between">
              <span>WORKFLOW:</span>
              <span className="text-[#66ff66]">PIPELINE_IN_PROGRESS</span>
            </div>
          </div>

          <div className="border border-[#255325] p-4 bg-[#000000] flex flex-col justify-between">
            <div>
              <div className="text-[11px] text-[#58ca58] uppercase">04. SEV_CRITICAL</div>
              <div className={`text-[26px] font-medium mt-1 ${stats.critical > 0 ? "text-[#ffffff]" : "text-[#58ca58]"}`}>
                {stats.critical}
              </div>
            </div>
            <div className="mt-3 pt-2 border-t border-[#255325] text-[11px] text-[#58ca58] flex justify-between">
              <span>ALERT_LEVEL:</span>
              <span className={stats.critical > 0 ? "text-[#ffffff]" : "text-[#58ca58]"}>
                {stats.critical > 0 ? "PRIORITY_ONE" : "ZERO_CRITICAL"}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div>
        <div className="text-[12px] text-[#255325] mb-2 select-none">
          [02] $ sentinel --filter-queue --query "{search || '*'}" --status {statusFilter} --severity {severityFilter}
        </div>
        <div className="border border-[#255325] p-3 bg-[#000000] flex flex-col md:flex-row gap-3 justify-between items-stretch md:items-center">
          
          <div className="flex items-center gap-2 flex-1 max-w-md border border-[#255325] px-3 py-1.5 bg-[#000000]">
            <span className="text-[#58ca58] text-[12px] select-none">&gt;</span>
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="SEARCH_QUERY: title, host, or INC-ID..."
              className="bg-transparent border-none outline-none text-[#ffffff] placeholder-[#255325] text-[12px] w-full font-mono"
            />
            {search && (
              <button 
                onClick={() => setSearch("")} 
                className="text-[#58ca58] hover:text-[#ffffff] text-[11px]"
              >
                [✕]
              </button>
            )}
          </div>

          <div className="flex items-center gap-3">
            <div className="flex items-center gap-1.5 text-[12px]">
              <span className="text-[#58ca58]">STATUS:</span>
              <select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                className="bg-[#000000] border border-[#255325] text-[#66ff66] px-2 py-1 text-[11px] outline-none cursor-pointer hover:border-[#66ff66] transition-colors"
              >
                <option value="All">[ALL_STATUSES]</option>
                <option value="New">[NEW]</option>
                <option value="Investigating">[INVESTIGATING]</option>
                <option value="Contained">[CONTAINED]</option>
                <option value="Resolved">[RESOLVED]</option>
                <option value="Closed">[CLOSED]</option>
              </select>
            </div>

            <div className="flex items-center gap-1.5 text-[12px]">
              <span className="text-[#58ca58]">SEVERITY:</span>
              <select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                className="bg-[#000000] border border-[#255325] text-[#66ff66] px-2 py-1 text-[11px] outline-none cursor-pointer hover:border-[#66ff66] transition-colors"
              >
                <option value="All">[ALL_SEVERITIES]</option>
                <option value="CRITICAL">[CRITICAL]</option>
                <option value="HIGH">[HIGH]</option>
                <option value="MEDIUM">[MEDIUM]</option>
                <option value="LOW">[LOW]</option>
              </select>
            </div>

            {(search || statusFilter !== "All" || severityFilter !== "All") && (
              <button
                onClick={() => { setSearch(""); setStatusFilter("All"); setSeverityFilter("All"); }}
                className="text-[11px] px-2 py-1 border border-[#255325] text-[#58ca58] hover:text-[#ffffff] hover:border-[#66ff66] transition-colors cursor-pointer"
              >
                [ RESET_FILTERS ]
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Main Table */}
      <div>
        <div className="text-[12px] text-[#255325] mb-2 select-none">
          [03] $ sentinel --render table --view triage
        </div>

        <div className="border border-[#255325] bg-[#000000] p-4">
          <div className="border-b border-[#255325] pb-2 mb-3 flex justify-between items-center text-[12px]">
            <span className="text-[#ffffff] font-medium">
              MATCHING_INCIDENTS_TABLE // COUNT: {filteredIncidents.length}
            </span>
            <span className="text-[#58ca58]">
              AUTO_SORT: RISK_SCORE_DESC
            </span>
          </div>

          {loading ? (
            <div className="py-12 text-center text-[#58ca58] font-mono text-[13px]">
              &gt; Loading incident correlation ledger from database...
            </div>
          ) : filteredIncidents.length === 0 ? (
            <div className="py-12 text-center text-[#255325] font-mono text-[13px]">
              [ - ] No security incidents matched the active query filters.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-[12px] border-collapse font-mono">
                <thead>
                  <tr className="border-b border-[#255325] text-[#58ca58] text-[11px] uppercase tracking-wider">
                    <th className="pb-2 w-20"># ID</th>
                    <th className="pb-2">INCIDENT_NAME &amp; DESCRIPTION</th>
                    <th className="pb-2 w-28">SEVERITY</th>
                    <th className="pb-2 w-36">RISK_METER</th>
                    <th className="pb-2 w-28">STATUS</th>
                    <th className="pb-2 w-44">TIMESTAMP</th>
                    <th className="pb-2 w-28 text-right">ACTION</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#255325]">
                  {filteredIncidents.map((inc) => (
                    <tr key={inc.id} className="hover:bg-[#255325]/20 transition-colors">
                      <td className="py-3 font-mono text-[#ffffff] font-medium">
                        INC-{inc.id}
                      </td>
                      <td className="py-3 pr-4">
                        <span className="font-medium text-[#ffffff] block">
                          {inc.title}
                        </span>
                        <span className="text-[#58ca58] text-[11px] block truncate max-w-xl">
                          {inc.description}
                        </span>
                      </td>
                      <td className="py-3">
                        {getSeverityBadge(inc.severity)}
                      </td>
                      <td className="py-3">
                        <div className="flex items-center gap-2">
                          <span className={`text-[11px] ${inc.risk_score >= 70 ? "text-[#ffffff]" : "text-[#66ff66]"}`}>
                            [{renderAsciiMeter(inc.risk_score, 100, 8)}]
                          </span>
                          <span className="text-[#58ca58] text-[11px]">
                            {inc.risk_score}
                          </span>
                        </div>
                      </td>
                      <td className="py-3">
                        <span className={`text-[11px] font-medium ${
                          inc.status === "New" ? "text-[#ffffff]" : 
                          inc.status === "Investigating" ? "text-[#66ff66]" : 
                          inc.status === "Resolved" ? "text-[#58ca58]" : "text-[#255325]"
                        }`}>
                          [{inc.status.toUpperCase()}]
                        </span>
                      </td>
                      <td className="py-3 text-[#58ca58] text-[11px] font-mono">
                        {formatDateTime(inc.created_at)}
                      </td>
                      <td className="py-3 text-right">
                        <Link
                          to={`/incidents/${inc.id}`}
                          className="px-2.5 py-1 border border-[#255325] text-[#58ca58] hover:text-[#000000] hover:bg-[#66ff66] hover:border-[#66ff66] transition-colors text-[11px] font-medium inline-block select-none"
                        >
                          [ INVESTIGATE ↵ ]
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>

    </div>
  );
};

export default IncidentQueue;

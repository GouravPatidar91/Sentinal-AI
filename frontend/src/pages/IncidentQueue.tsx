import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { AlertOctagon, Filter, Search } from "lucide-react";
import { useAuth } from "../context/AuthContext";
import { API_BASE, WS_BASE } from "../config/api";

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
  }, []);

  const fetchIncidents = async () => {
    setLoading(true);
    try {
      const resp = await fetch(`${API_BASE}/api/incidents`, {
        headers: { "Authorization": `Bearer ${token}` }
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

  const getSeverityBg = (sev: string) => {
    switch (sev.toUpperCase()) {
      case "CRITICAL": return "bg-red-500/10 text-red-400 border-red-500/20";
      case "HIGH": return "bg-orange-500/10 text-orange-400 border-orange-500/20";
      case "MEDIUM": return "bg-yellow-500/10 text-yellow-400 border-yellow-500/20";
      default: return "bg-blue-500/10 text-blue-400 border-blue-500/20";
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
    <div className="flex-1 p-8 space-y-8 overflow-y-auto h-screen max-w-[calc(100vw-16rem)]">
      
      {/* Title */}
      <div className="flex justify-between items-center border-b border-darkBorder pb-6">
        <div>
          <h2 className="text-3xl font-extrabold text-slate-100 tracking-wide flex items-center gap-3">
            <AlertOctagon className="w-8 h-8 text-red-500" />
            INCIDENT QUEUE
          </h2>
          <p className="text-sm text-slate-500 mt-1">
            Review, prioritize, and investigate aggregated cybersecurity threat logs
          </p>
        </div>
      </div>

      {/* Stats Counters */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <div className="glass-card rounded-xl p-5 border flex flex-col justify-center">
          <span className="text-[10px] font-bold text-slate-500 tracking-widest uppercase">Total Incidents</span>
          <span className="text-3xl font-bold text-slate-100 mt-1">{stats.total}</span>
        </div>
        <div className="glass-card rounded-xl p-5 border flex flex-col justify-center">
          <span className="text-[10px] font-bold text-slate-500 tracking-widest uppercase">Untriaged (New)</span>
          <span className="text-3xl font-bold text-blue-400 mt-1">{stats.new}</span>
        </div>
        <div className="glass-card rounded-xl p-5 border flex flex-col justify-center">
          <span className="text-[10px] font-bold text-slate-500 tracking-widest uppercase">Active Investigations</span>
          <span className="text-3xl font-bold text-orange-400 mt-1">{stats.active}</span>
        </div>
        <div className="glass-card rounded-xl p-5 border flex flex-col justify-center">
          <span className="text-[10px] font-bold text-slate-500 tracking-widest uppercase">Critical Threats</span>
          <span className="text-3xl font-bold text-red-500 mt-1">{stats.critical}</span>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="glass-card rounded-xl p-4 border flex flex-col md:flex-row gap-4 justify-between items-center">
        
        {/* Search */}
        <div className="relative w-full md:w-80">
          <span className="absolute inset-y-0 left-0 pl-3 flex items-center">
            <Search className="w-4 h-4 text-slate-500" />
          </span>
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search incident title, host or ID..."
            className="w-full bg-slate-950 border border-darkBorder rounded-lg py-2 pl-10 pr-4 text-xs text-slate-200 outline-none focus:border-blue-500 transition-colors"
          />
        </div>

        {/* Filters */}
        <div className="flex flex-wrap gap-4 w-full md:w-auto justify-end">
          <div className="flex items-center gap-2">
            <Filter className="w-3.5 h-3.5 text-slate-500" />
            <span className="text-xs text-slate-400">Status:</span>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="bg-slate-950 border border-darkBorder rounded py-1.5 px-3 text-xs text-slate-300 outline-none cursor-pointer"
            >
              <option value="All">All Statuses</option>
              <option value="New">New</option>
              <option value="Investigating">Investigating</option>
              <option value="Contained">Contained</option>
              <option value="Resolved">Resolved</option>
              <option value="Closed">Closed</option>
            </select>
          </div>

          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-400">Severity:</span>
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="bg-slate-950 border border-darkBorder rounded py-1.5 px-3 text-xs text-slate-300 outline-none cursor-pointer"
            >
              <option value="All">All Severities</option>
              <option value="CRITICAL">CRITICAL</option>
              <option value="HIGH">HIGH</option>
              <option value="WARNING">WARNING</option>
              <option value="INFO">INFO</option>
            </select>
          </div>
        </div>

      </div>

      {/* Main Table */}
      <div className="glass-card rounded-xl p-6 border">
        {loading ? (
          <div className="py-12 text-center text-slate-400 font-medium">Loading threat incidents...</div>
        ) : filteredIncidents.length === 0 ? (
          <div className="py-12 text-center text-slate-500">
            No incidents match the active search/filters.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-darkBorder text-slate-500 font-semibold uppercase tracking-wider">
                  <th className="pb-3 w-20">ID</th>
                  <th className="pb-3">Incident Title</th>
                  <th className="pb-3 w-32">Severity</th>
                  <th className="pb-3 w-32">Risk Score</th>
                  <th className="pb-3 w-32">Status</th>
                  <th className="pb-3 w-40">Created At</th>
                  <th className="pb-3 w-24">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-darkBorder">
                {filteredIncidents.map((inc) => (
                  <tr key={inc.id} className="hover:bg-slate-900/30 transition-colors">
                    <td className="py-4 font-mono text-slate-400">INC-{inc.id}</td>
                    <td className="py-4 pr-4">
                      <span className="font-semibold text-slate-200 block text-sm">{inc.title}</span>
                      <span className="text-slate-500 text-[10px] mt-0.5 block truncate max-w-lg">{inc.description}</span>
                    </td>
                    <td className="py-4">
                      <span className={`px-2 py-0.5 rounded border text-[10px] font-bold tracking-wide ${getSeverityBg(inc.severity)}`}>
                        {inc.severity}
                      </span>
                    </td>
                    <td className="py-4">
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-slate-200">{inc.risk_score}</span>
                        <div className="w-20 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                          <div 
                            className={`h-full ${
                              inc.risk_score > 75 ? "bg-red-500 animate-pulse" :
                              inc.risk_score > 40 ? "bg-orange-500" : "bg-yellow-500"
                            }`}
                            style={{ width: `${inc.risk_score}%` }}
                          />
                        </div>
                      </div>
                    </td>
                    <td className="py-4">
                      <span className={`font-semibold ${
                        inc.status === "New" ? "text-blue-400" : 
                        inc.status === "Investigating" ? "text-orange-400 animate-pulse" : 
                        inc.status === "Resolved" ? "text-emerald-400" : "text-slate-500"
                      }`}>{inc.status}</span>
                    </td>
                    <td className="py-4 text-slate-400 font-mono">
                      {new Date(inc.created_at).toLocaleString()}
                    </td>
                    <td className="py-4">
                      <Link
                        to={`/incidents/${inc.id}`}
                        className="bg-blue-600 hover:bg-blue-500 text-white px-3.5 py-2 rounded font-bold tracking-wide shadow-md shadow-blue-500/10 hover:shadow-blue-500/25 transition-all text-[11px]"
                      >
                        Investigate
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
  );
};
export default IncidentQueue;

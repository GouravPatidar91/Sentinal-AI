import React, { useEffect, useState } from "react";
import { Sliders, AlertTriangle } from "lucide-react";
import { useAuth } from "../context/AuthContext";
import { useNotifications } from "../context/NotificationContext";
import { API_BASE } from "../config/api";

interface Rule {
  id: number;
  name: string;
  description: string;
  severity: string;
  tactic: string;
  technique: string;
  rule_type: string;
  condition_pattern: string;
  is_enabled: boolean;
}

export const RulesManager: React.FC = () => {
  const { token, isAdmin } = useAuth();
  const { triggerNotification } = useNotifications();
  const [rules, setRules] = useState<Rule[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchRules();
  }, []);

  const fetchRules = async () => {
    setLoading(true);
    try {
      const resp = await fetch(`${API_BASE}/api/rules`, {
        headers: {
          "Authorization": `Bearer ${token}`
        }
      });
      if (resp.ok) {
        const data = await resp.json();
        setRules(data);
      }
    } catch (err) {
      console.error("Error loading rules:", err);
    } finally {
      setLoading(false);
    }
  };

  const handleToggleRule = async (ruleId: number, currentStatus: boolean) => {
    if (!isAdmin) {
      triggerNotification(
        "Access Denied",
        "Only Administrators are authorized to enable or disable SIEM rules.",
        "CRITICAL"
      );
      return;
    }

    try {
      const resp = await fetch(`${API_BASE}/api/rules/${ruleId}`, {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`
        },
        body: JSON.stringify({ is_enabled: !currentStatus })
      });

      if (resp.ok) {
        setRules((prev) => 
          prev.map((r) => r.id === ruleId ? { ...r, is_enabled: !currentStatus } : r)
        );
        triggerNotification(
          "Rule State Updated",
          `Rule ID ${ruleId} is now ${!currentStatus ? "ENABLED" : "DISABLED"}`,
          "INFO"
        );
      } else {
        const err = await resp.json();
        throw new Error(err.detail || "Failed to update rule status");
      }
    } catch (err: any) {
      triggerNotification(
        "Update Failed",
        err.message || "Failed to contact backend API",
        "CRITICAL"
      );
    }
  };

  const getSeverityBg = (sev: string) => {
    switch (sev.toUpperCase()) {
      case "CRITICAL": return "text-red-400 bg-red-950/30 border-red-900/50";
      case "HIGH": return "text-orange-400 bg-orange-950/30 border-orange-900/50";
      case "WARNING": return "text-yellow-400 bg-yellow-950/30 border-yellow-900/50";
      default: return "text-blue-400 bg-blue-950/30 border-blue-900/50";
    }
  };

  const ruleTypes = ["Windows", "Linux", "Apache", "Firewall"];

  return (
    <div className="flex-1 p-8 space-y-8 overflow-y-auto h-screen max-w-[calc(100vw-16rem)]">
      
      {/* Title */}
      <div className="flex justify-between items-center border-b border-darkBorder pb-6">
        <div>
          <h2 className="text-3xl font-extrabold text-slate-100 tracking-wide flex items-center gap-3">
            <Sliders className="w-8 h-8 text-blue-500" />
            SIEM RULES ENGINE
          </h2>
          <p className="text-sm text-slate-500 mt-1">
            Enable or disable individual inspection signatures and adjust detection severities
          </p>
        </div>
      </div>

      {/* Permissions Banner */}
      {!isAdmin && (
        <div className="p-4 rounded-xl bg-orange-950/20 border border-orange-900/40 text-orange-200 text-xs flex gap-3 items-center">
          <AlertTriangle className="w-5 h-5 text-orange-400 shrink-0" />
          <span>
            You are logged in with the <strong>Analyst</strong> role. You can review active detection rules, but you are not authorized to toggle them. Switch accounts to Admin to edit settings.
          </span>
        </div>
      )}

      {/* Main Content Grid */}
      {loading ? (
        <div className="py-12 text-center text-slate-400 font-medium">Loading rules database...</div>
      ) : (
        <div className="space-y-12">
          {ruleTypes.map((type) => {
            const filteredRules = rules.filter(r => r.rule_type === type);
            if (filteredRules.length === 0) return null;

            return (
              <div key={type} className="space-y-4">
                <div className="flex items-center gap-2 border-b border-darkBorder pb-2">
                  <h3 className="text-lg font-bold text-slate-200 tracking-wide">{type} Signature Pack</h3>
                  <span className="bg-slate-900 border border-darkBorder text-[10px] text-slate-400 font-bold px-2 py-0.5 rounded-full font-mono">
                    {filteredRules.length} rules
                  </span>
                </div>
                
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  {filteredRules.map((rule) => (
                    <div 
                      key={rule.id}
                      className={`glass-card rounded-xl p-5 border flex flex-col justify-between h-48 transition-all ${
                        rule.is_enabled ? "border-slate-800" : "border-slate-900/60 opacity-60"
                      }`}
                    >
                      <div className="space-y-2">
                        <div className="flex justify-between items-start">
                          <span className="font-mono text-[10px] text-slate-500 font-semibold uppercase">ID: RULE-{rule.id}</span>
                          <span className={`px-2 py-0.5 rounded border text-[9px] font-bold ${getSeverityBg(rule.severity)}`}>
                            {rule.severity}
                          </span>
                        </div>
                        <h4 className="font-bold text-sm text-slate-200">{rule.name}</h4>
                        <p className="text-xs text-slate-400 leading-normal line-clamp-2">{rule.description}</p>
                      </div>

                      <div className="border-t border-darkBorder/60 pt-3 mt-4 flex justify-between items-center text-xs">
                        <div className="flex gap-4 font-mono text-[10px] text-slate-500">
                          <div><span className="text-slate-600">Tactic:</span> {rule.tactic}</div>
                          <div><span className="text-slate-600">ID:</span> {rule.technique}</div>
                        </div>

                        {/* Switch button */}
                        <div className="flex items-center gap-2">
                          <span className={`text-[10px] font-bold uppercase tracking-wider ${rule.is_enabled ? "text-emerald-400" : "text-slate-500"}`}>
                            {rule.is_enabled ? "Active" : "Disabled"}
                          </span>
                          <button
                            onClick={() => handleToggleRule(rule.id, rule.is_enabled)}
                            className={`w-9 h-5 rounded-full p-0.5 transition-colors cursor-pointer relative ${
                              rule.is_enabled ? "bg-emerald-500" : "bg-slate-800"
                            }`}
                          >
                            <div 
                              className={`w-4 h-4 bg-white rounded-full transition-transform transform ${
                                rule.is_enabled ? "translate-x-4" : "translate-x-0"
                              }`}
                            />
                          </button>
                        </div>
                      </div>

                    </div>
                  ))}
                </div>
              </div>
            );
          })}
        </div>
      )}

    </div>
  );
};
export default RulesManager;

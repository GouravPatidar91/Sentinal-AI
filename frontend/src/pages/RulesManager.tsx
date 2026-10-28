import React, { useEffect, useState } from "react";
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
  const [selectedType, setSelectedType] = useState<string>("ALL");

  useEffect(() => {
    fetchRules();
  }, [token]);

  const fetchRules = async () => {
    setLoading(true);
    const activeToken = token || localStorage.getItem("token");
    try {
      const resp = await fetch(`${API_BASE}/api/rules/`, {
        headers: {
          "Authorization": `Bearer ${activeToken}`
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

  const getSeverityBadge = (sev: string) => {
    switch (sev.toUpperCase()) {
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

  const ruleTypes = ["Windows", "Linux", "Apache", "Firewall"];
  const filteredRules = selectedType === "ALL" ? rules : rules.filter(r => r.rule_type === selectedType);

  return (
    <div className="flex-1 min-w-0 p-6 space-y-6 overflow-y-auto h-screen bg-[#000000] text-[#66ff66] font-mono select-text">
      
      {/* Top Command Session Bar & Title */}
      <div className="border border-[#255325] p-4 bg-[#000000]">
        <div className="flex items-center justify-between text-[13px] border-b border-[#255325] pb-2 mb-3">
          <div className="flex items-center gap-2">
            <span className="text-[#255325] select-none">[00]</span>
            <span className="text-[#66ff66]">
              <span className="text-[#58ca58]">sentinel@soc:~$</span> sentinel --engine rules --inspect active-heuristics --policy strict
            </span>
          </div>
          <span className="px-2 py-0.5 bg-[#66ff66] text-[#000000] font-medium text-[11px] select-none">
            [ CHANNEL: 04 // RULES_ENGINE ]
          </span>
        </div>

        <div className="flex flex-col md:flex-row md:items-center justify-between gap-2">
          <div>
            <h1 className="text-[22px] sm:text-[26px] font-medium text-[#ffffff] tracking-tight uppercase">
              Detection Rules Engine // SIEM &amp; MITRE Matrix
            </h1>
            <p className="text-[14px] text-[#58ca58] mt-1">
              Deterministic threshold policies, regular expression patterns, and behavioral correlation triggers across all assets.
            </p>
          </div>
          <div className="text-[12px] text-[#58ca58] text-right font-mono shrink-0">
            <div>LOADED_RULES: <span className="text-[#ffffff]">{rules.length} ACTIVE_DEFINITIONS</span></div>
            <div>STATUS: <span className="text-[#66ff66]">HOT_RELOAD_ENABLED</span></div>
          </div>
        </div>
      </div>

      {/* Permissions Callout (If Analyst) */}
      {!isAdmin && (
        <div className="border border-[#255325] p-3 bg-[#255325]/10 text-[12px] text-[#58ca58] flex items-center justify-between">
          <div>
            <span className="text-[#ffffff] font-medium">[ ! ] PERMISSION_RESTRICTION:</span> Authenticated as <strong>Analyst</strong> (Read-Only). Root administrative privilege is required to toggle SIEM rules.
          </div>
          <span className="text-[#255325] select-none">[EACCES]</span>
        </div>
      )}

      {/* Filter Category Tabs */}
      <div>
        <div className="text-[12px] text-[#255325] mb-2 select-none">
          [01] $ sentinel --rules-filter --category "{selectedType.toLowerCase()}"
        </div>

        <div className="border border-[#255325] p-2 bg-[#000000] flex flex-wrap gap-2 text-[12px]">
          <button
            onClick={() => setSelectedType("ALL")}
            className={`px-3 py-1 border transition-colors select-none ${
              selectedType === "ALL"
                ? "bg-[#66ff66] text-[#000000] border-[#66ff66] font-medium"
                : "border-[#255325] text-[#58ca58] hover:text-[#ffffff] hover:border-[#66ff66]"
            }`}
          >
            [ ALL ({rules.length}) ]
          </button>
          {ruleTypes.map((type) => {
            const count = rules.filter(r => r.rule_type === type).length;
            const isSelected = selectedType === type;
            return (
              <button
                key={type}
                onClick={() => setSelectedType(type)}
                className={`px-3 py-1 border transition-colors select-none ${
                  isSelected
                    ? "bg-[#66ff66] text-[#000000] border-[#66ff66] font-medium"
                    : "border-[#255325] text-[#58ca58] hover:text-[#ffffff] hover:border-[#66ff66]"
                }`}
              >
                [ {type.toUpperCase()} ({count}) ]
              </button>
            );
          })}
        </div>
      </div>

      {/* Rules Grid */}
      <div>
        <div className="text-[12px] text-[#255325] mb-2 select-none">
          [02] $ sentinel --render rules-catalog --count {filteredRules.length}
        </div>

        {loading ? (
          <div className="border border-[#255325] p-12 text-center text-[#58ca58] font-mono text-[13px] bg-[#000000]">
            &gt; Querying detection rules database...
          </div>
        ) : filteredRules.length === 0 ? (
          <div className="border border-[#255325] p-12 text-center text-[#255325] font-mono text-[13px] bg-[#000000]">
            [ - ] No rules registered under this category.
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {filteredRules.map((rule) => (
              <div
                key={rule.id}
                className={`border p-4 bg-[#000000] flex flex-col justify-between transition-colors ${
                  rule.is_enabled 
                    ? "border-[#255325] hover:border-[#66ff66]" 
                    : "border-[#255325]/50 opacity-60"
                }`}
              >
                <div className="space-y-3">
                  <div className="flex justify-between items-start border-b border-[#255325] pb-2 text-[11px]">
                    <span className="text-[#255325] font-mono font-medium">
                      RULE #{rule.id} // [{rule.rule_type.toUpperCase()}]
                    </span>
                    {getSeverityBadge(rule.severity)}
                  </div>

                  <div>
                    <h3 className="font-medium text-[#ffffff] text-[14px]">
                      {rule.name}
                    </h3>
                    <p className="text-[12px] text-[#58ca58] mt-1 leading-relaxed">
                      {rule.description}
                    </p>
                  </div>

                  {rule.condition_pattern && (
                    <div className="bg-[#255325]/10 border border-[#255325] p-2 text-[10px] text-[#66ff66] font-mono truncate">
                      <span className="text-[#255325]">REGEX: </span>
                      {rule.condition_pattern}
                    </div>
                  )}
                </div>

                <div className="border-t border-[#255325] pt-3 mt-4 flex justify-between items-center text-[11px]">
                  <div className="flex gap-3 text-[#58ca58]">
                    <span>TACTIC: <strong className="text-[#ffffff]">{rule.tactic}</strong></span>
                    <span>TECHNIQUE: <strong className="text-[#66ff66]">{rule.technique}</strong></span>
                  </div>

                  <button
                    onClick={() => handleToggleRule(rule.id, rule.is_enabled)}
                    disabled={!isAdmin}
                    className={`px-2.5 py-1 text-[11px] font-medium border transition-colors select-none ${
                      !isAdmin 
                        ? "border-[#255325] text-[#255325] cursor-not-allowed"
                        : rule.is_enabled
                          ? "bg-[#66ff66] text-[#000000] border-[#66ff66] hover:bg-[#ffffff] cursor-pointer"
                          : "border-[#255325] text-[#58ca58] hover:text-[#66ff66] hover:border-[#66ff66] cursor-pointer"
                    }`}
                  >
                    {rule.is_enabled ? "[ ◉ ACTIVE ]" : "[ ○ DISABLED ]"}
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

    </div>
  );
};

export default RulesManager;

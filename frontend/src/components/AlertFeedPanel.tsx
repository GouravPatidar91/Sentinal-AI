import React from "react";
import { useNotifications } from "../context/NotificationContext";
import { API_BASE } from "../config/api";
import { formatDateTime } from "../utils/time";

export const AlertFeedPanel: React.FC = () => {
  const { 
    notifications, 
    isOpen, 
    setIsOpen, 
    removeNotification, 
    clearAll 
  } = useNotifications();
  const [blockingStates, setBlockingStates] = React.useState<Record<string, "idle" | "loading" | "done">>({});

  const handleQuickBlockIp = async (notification: { id: string; message: string; title: string }) => {
    try {
      setBlockingStates(prev => ({ ...prev, [notification.id]: "loading" }));

      const rawToken = localStorage.getItem("token");
      const headers: Record<string, string> = { "Content-Type": "application/json" };
      if (rawToken && rawToken !== "null" && rawToken !== "undefined") {
        headers["Authorization"] = `Bearer ${rawToken}`;
      }

      // Extract target host dynamically from message (e.g., "(Host: web-server-prod)")
      const hostMatch = notification.message.match(/Host:\s*([a-zA-Z0-9_\-\.]+)/i);
      const targetHost = hostMatch ? hostMatch[1] : "web-server-prod";

      // Extract attacker IP dynamically from message or fallback to attacker in current chain
      const ipMatch = notification.message.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
      const attackerIp = ipMatch ? ipMatch[0] : "198.51.100.55";

      const createResp = await fetch(`${API_BASE}/api/soar/actions?auto_approve=true`, {
        method: "POST",
        headers,
        body: JSON.stringify({
          action_type: "BLOCK_IP",
          target_host: targetHost,
          payload: attackerIp,
          description: `Quick Prevention action from Alerts Feed: Block ${attackerIp}`
        })
      });

      if (createResp.ok) {
        const action = await createResp.json();
        // Also ensure approved
        await fetch(`${API_BASE}/api/soar/approve/${action.id}`, {
          method: "POST",
          headers
        }).catch(() => {});

        setBlockingStates(prev => ({ ...prev, [notification.id]: "done" }));
        setTimeout(() => {
          removeNotification(notification.id);
        }, 700);
      } else {
        setBlockingStates(prev => ({ ...prev, [notification.id]: "idle" }));
      }
    } catch (err) {
      console.error("Quick SOAR prevention failed:", err);
      setBlockingStates(prev => ({ ...prev, [notification.id]: "idle" }));
    }
  };

  // Render when panel is expanded
  if (isOpen) {
    return (
      <aside className="w-80 lg:w-96 border-l border-[#255325] bg-[#000000] text-[#66ff66] font-mono flex flex-col h-full shrink-0 transition-all text-[13px] select-none">
        
        {/* Header Section */}
        <div className="p-3 border-b border-[#255325] bg-[#000000] space-y-1">
          <div className="flex justify-between items-center">
            <div className="flex items-center gap-2">
              <span className="text-[#ffffff] font-medium tracking-tight">
                [ ! ] LIVE_ALERTS
              </span>
              {notifications.length > 0 && (
                <span className="bg-[#66ff66] text-[#000000] text-[10px] font-bold px-1.5 py-0.2">
                  {notifications.length}
                </span>
              )}
            </div>
            
            <div className="flex items-center gap-2 text-[12px]">
              {notifications.length > 0 && (
                <button 
                  onClick={clearAll}
                  className="px-2 py-0.5 border border-[#255325] text-[#58ca58] hover:border-[#66ff66] hover:text-[#66ff66] transition-colors cursor-pointer"
                  title="Clear all alerts"
                >
                  [ CLEAR ]
                </button>
              )}
              <button 
                onClick={() => setIsOpen(false)}
                className="px-2 py-0.5 border border-[#255325] text-[#58ca58] hover:border-[#66ff66] hover:text-[#000000] hover:bg-[#66ff66] transition-colors cursor-pointer"
                title="Collapse Panel"
              >
                [ &gt; ]
              </button>
            </div>
          </div>
          <div className="text-[10px] text-[#255325] flex items-center justify-between">
            <span>MODE: SENTINEL AI [CLOUD] + LOCAL ENGINE [OFFLINE]</span>
          </div>
        </div>

        {/* Alerts Body */}
        <div className="flex-1 overflow-y-auto p-3 space-y-2.5 font-mono">
          {notifications.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-full text-center p-6 text-[#255325]">
              <div className="text-[24px] mb-2">[OK]</div>
              <p className="text-[12px] font-medium text-[#58ca58] uppercase">Zero Pending Alerts</p>
              <p className="text-[11px] text-[#255325] mt-1">
                Sliding correlation healthy. Telemetry stream nominal.
              </p>
            </div>
          ) : (
            notifications.map((n, idx) => {
              const isCrit = n.severity === "CRITICAL" || n.severity === "HIGH";
              const isCloudAi = n.detectionSource === "SENTINEL_AI" || n.title.includes("Sentinel AI Alert");
              const alertIndex = (idx + 1).toString().padStart(2, "0");
              return (
                <div 
                  key={n.id}
                  className={`p-2.5 border transition-colors ${
                    isCrit 
                      ? "border-[#66ff66] bg-[#255325]/20" 
                      : "border-[#255325] bg-[#000000]"
                  }`}
                >
                  <div className="flex items-start justify-between gap-2 border-b border-[#255325] pb-1.5 mb-1.5 text-[11px]">
                    <div className="flex items-center gap-1.5 flex-wrap">
                      <span className="text-[#255325]">[{alertIndex}]</span>
                      <span className={`px-1 font-bold ${
                        n.severity === "CRITICAL"
                          ? "bg-[#66ff66] text-[#000000]"
                          : n.severity === "HIGH"
                          ? "bg-[#255325] text-[#ffffff]"
                          : "border border-[#255325] text-[#58ca58]"
                      }`}>
                        [{n.severity}]
                      </span>
                      <span className={`px-1 text-[9px] font-bold ${
                        isCloudAi
                          ? "border border-[#66ff66] text-[#66ff66] bg-[#66ff66]/15"
                          : "border border-[#58ca58] text-[#58ca58] bg-[#255325]/30"
                      }`}>
                        {isCloudAi ? "[SENTINEL AI]" : "[LOCAL ENGINE]"}
                      </span>
                    </div>
                    <button 
                      onClick={() => removeNotification(n.id)}
                      className="text-[#255325] hover:text-[#ffffff] px-1 transition-colors cursor-pointer"
                    >
                      [✕]
                    </button>
                  </div>

                  <h4 className="font-medium text-[12px] text-[#ffffff] mb-1 leading-snug">
                    {n.title}
                  </h4>
                  
                  <p className="text-[11px] text-[#58ca58] leading-relaxed break-words mb-2">
                    {n.message}
                  </p>

                  <div className="flex items-center justify-between pt-1 border-t border-[#255325] text-[10px] text-[#255325]">
                    <span>{formatDateTime(n.timestamp)}</span>
                    {isCrit && (
                      <button
                        onClick={() => handleQuickBlockIp(n)}
                        disabled={blockingStates[n.id] === "loading" || blockingStates[n.id] === "done"}
                        className={`px-2 py-0.5 font-medium transition-colors cursor-pointer text-[10px] ${
                          blockingStates[n.id] === "done"
                            ? "bg-[#ffffff] text-[#000000]"
                            : blockingStates[n.id] === "loading"
                            ? "bg-[#58ca58] text-[#000000] opacity-80"
                            : "bg-[#66ff66] text-[#000000] hover:bg-[#ffffff]"
                        }`}
                      >
                        {blockingStates[n.id] === "done" 
                          ? "[ ✓ BLOCKED ]" 
                          : blockingStates[n.id] === "loading" 
                          ? "[ ⚡ BLOCKING... ]" 
                          : "[ ⚡ BLOCK_IP ↵ ]"}
                      </button>
                    )}
                  </div>
                </div>
              );
            })
          )}
        </div>
      </aside>
    );
  }

  // Render when panel is collapsed
  return (
    <aside className="w-10 border-l border-[#255325] bg-[#000000] text-[#66ff66] font-mono flex flex-col items-center py-3 shrink-0 transition-all h-full select-none">
      <button
        onClick={() => setIsOpen(true)}
        className="p-1 border border-[#255325] hover:border-[#66ff66] text-[#58ca58] hover:text-[#66ff66] transition-colors cursor-pointer text-[11px] flex items-center justify-center"
        title="Expand Alerts Feed"
      >
        [ ! ]
        {notifications.length > 0 && (
          <span className="ml-1 bg-[#66ff66] text-[#000000] text-[9px] font-bold px-1">
            {notifications.length}
          </span>
        )}
      </button>
      <div className="flex-1 flex flex-col justify-center items-center mt-4">
        <span className="text-[10px] text-[#255325] uppercase tracking-widest [writing-mode:vertical-lr] rotate-180">
          ALERTS_FEED
        </span>
      </div>
    </aside>
  );
};

export default AlertFeedPanel;

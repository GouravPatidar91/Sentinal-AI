import React from "react";
import { useNotifications } from "../context/NotificationContext";
import { 
  Bell, 
  ChevronRight, 
  ChevronLeft, 
  Trash2, 
  ShieldCheck, 
  AlertTriangle,
  AlertOctagon,
  Info
} from "lucide-react";

export const AlertFeedPanel: React.FC = () => {
  const { 
    notifications, 
    isOpen, 
    setIsOpen, 
    removeNotification, 
    clearAll 
  } = useNotifications();

  // Color mapping based on alert severity
  const severityStyles = {
    CRITICAL: {
      border: "border-l-4 border-red-500",
      bg: "bg-red-950/30",
      text: "text-red-200",
      icon: <AlertOctagon className="w-4 h-4 text-red-500 shrink-0 mt-0.5" />
    },
    HIGH: {
      border: "border-l-4 border-orange-500",
      bg: "bg-orange-950/30",
      text: "text-orange-200",
      icon: <AlertTriangle className="w-4 h-4 text-orange-500 shrink-0 mt-0.5" />
    },
    WARNING: {
      border: "border-l-4 border-yellow-500",
      bg: "bg-yellow-950/30",
      text: "text-yellow-200",
      icon: <AlertTriangle className="w-4 h-4 text-yellow-500 shrink-0 mt-0.5" />
    },
    INFO: {
      border: "border-l-4 border-blue-500",
      bg: "bg-blue-950/30",
      text: "text-blue-200",
      icon: <Info className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />
    }
  };

  // Render when panel is expanded
  if (isOpen) {
    return (
      <div className="w-80 lg:w-96 border-l border-darkBorder bg-slate-950/90 backdrop-blur-md flex flex-col h-full shrink-0 transition-all duration-300">
        
        {/* Header Section */}
        <div className="p-4 border-b border-darkBorder flex justify-between items-center bg-slate-950">
          <div className="flex items-center gap-2">
            <div className="relative">
              <Bell className="w-5 h-5 text-slate-300" />
              {notifications.length > 0 && (
                <span className="absolute -top-1.5 -right-1.5 bg-red-600 text-slate-100 text-[10px] font-bold px-1.5 py-0.25 rounded-full animate-pulse">
                  {notifications.length}
                </span>
              )}
            </div>
            <h3 className="font-extrabold text-sm text-slate-200 tracking-wider">LIVE ALERTS FEED</h3>
          </div>
          
          <div className="flex items-center gap-3">
            {notifications.length > 0 && (
              <button 
                onClick={clearAll}
                className="text-[10px] text-slate-500 hover:text-red-400 flex items-center gap-1 transition-colors font-bold uppercase cursor-pointer"
                title="Clear all alerts"
              >
                <Trash2 className="w-3 h-3" />
                Clear
              </button>
            )}
            <button 
              onClick={() => setIsOpen(false)}
              className="p-1 rounded bg-slate-900 border border-darkBorder hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition-colors cursor-pointer"
              title="Collapse Panel"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Alerts Body */}
        <div className="flex-1 overflow-y-auto p-4 space-y-3">
          {notifications.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-full text-center p-6 text-slate-500">
              <div className="p-3 rounded-full bg-slate-900 border border-darkBorder mb-3">
                <ShieldCheck className="w-8 h-8 text-emerald-500" />
              </div>
              <p className="text-xs font-semibold uppercase text-slate-400">System Secure</p>
              <p className="text-[11px] text-slate-600 mt-1 leading-normal">
                No active threats detected. Real-time log streaming is healthy.
              </p>
            </div>
          ) : (
            notifications.map((n) => {
              const styles = severityStyles[n.severity] || severityStyles.INFO;
              return (
                <div 
                  key={n.id}
                  className={`p-3 rounded-lg border border-darkBorder/60 flex flex-col justify-between transition-all duration-300 hover:border-darkBorder ${styles.bg} ${styles.border}`}
                >
                  <div className="flex gap-2 items-start justify-between">
                    <div className="flex gap-2 items-start">
                      {styles.icon}
                      <div className="flex flex-col">
                        <span className="text-[10px] font-mono text-slate-500 uppercase font-bold tracking-wide">
                          {n.severity} ALERT
                        </span>
                        <h4 className={`font-bold text-xs ${styles.text} mt-0.5 leading-snug`}>
                          {n.title}
                        </h4>
                      </div>
                    </div>
                    <button 
                      onClick={() => removeNotification(n.id)}
                      className="text-slate-500 hover:text-slate-200 text-xs font-semibold p-0.5 hover:bg-slate-900/60 rounded cursor-pointer"
                    >
                      ✕
                    </button>
                  </div>
                  <p className="text-[11px] text-slate-300 mt-2 pl-6 leading-relaxed break-words">
                    {n.message}
                  </p>
                  <span className="text-[9px] text-slate-500 mt-3 self-end pl-6">
                    {n.timestamp.toLocaleTimeString()}
                  </span>
                </div>
              );
            })
          )}
        </div>
      </div>
    );
  }

  // Render when panel is collapsed
  return (
    <div className="w-12 border-l border-darkBorder bg-slate-950 flex flex-col items-center py-4 shrink-0 transition-all duration-300 h-full">
      <button
        onClick={() => setIsOpen(true)}
        className="relative p-2 rounded-lg bg-slate-900 hover:bg-slate-800 border border-darkBorder text-slate-400 hover:text-slate-200 transition-colors flex items-center justify-center cursor-pointer"
        title="Expand Alerts Feed"
      >
        <Bell className="w-4 h-4" />
        {notifications.length > 0 && (
          <span className="absolute -top-1 -right-1 bg-red-600 text-slate-100 text-[8px] font-bold w-4 h-4 rounded-full flex items-center justify-center animate-pulse">
            {notifications.length}
          </span>
        )}
      </button>
      <div className="flex-1 flex flex-col justify-center items-center gap-2 mt-4 select-none">
        <ChevronLeft className="w-3 h-3 text-slate-600 animate-pulse" />
        <span className="text-[9px] text-slate-600 font-bold uppercase tracking-widest [writing-mode:vertical-lr] rotate-180">
          ALERTS FEED
        </span>
      </div>
    </div>
  );
};

export default AlertFeedPanel;

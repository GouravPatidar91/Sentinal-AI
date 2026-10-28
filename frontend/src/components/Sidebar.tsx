import React from "react";
import { Link, useLocation } from "react-router-dom";
import { useAuth } from "../context/AuthContext";

export const Sidebar: React.FC = () => {
  const location = useLocation();
  const { user, logout } = useAuth();
  
  const navItems = [
    { name: "Dashboard", path: "/dashboard", code: "01" },
    { name: "Incidents", path: "/incidents", code: "02" },
    { name: "Search Logs", path: "/search", code: "03" },
    { name: "Rules Engine", path: "/rules", code: "04" },
    { name: "Attack Sim", path: "/simulator", code: "05" }
  ];

  const isActive = (path: string) => {
    return location.pathname === path || (path !== "/dashboard" && location.pathname.startsWith(path));
  };

  return (
    <aside className="w-64 bg-[#000000] border-r border-[#255325] flex flex-col h-screen sticky top-0 font-mono text-[13px] select-none shrink-0">
      
      {/* Brand Session Bar */}
      <Link 
        to="/" 
        className="p-4 border-b border-[#255325] bg-[#000000] flex items-center justify-between group transition-colors hover:bg-[#255325]/20" 
        title="Return to SentinelAI Manual"
      >
        <div>
          <div className="font-bold text-[#ffffff] text-[15px] tracking-tight">
            SENTINEL_AI
          </div>
          <div className="text-[11px] text-[#58ca58]">/ SYS_SOC_CONSOLE</div>
        </div>
        <span className="text-[10px] px-1.5 py-0.5 border border-[#66ff66] text-[#000000] bg-[#66ff66] font-medium">
          [OK]
        </span>
      </Link>
      
      {/* Navigation Channels */}
      <div className="flex-1 px-3 py-4 flex flex-col gap-1 overflow-y-auto overflow-x-hidden">
        <div className="text-[11px] text-[#255325] px-2 pb-2 tracking-wider">
          # TELEMETRY CHANNELS
        </div>
        {navItems.map((item) => {
          const active = isActive(item.path);
          return (
            <Link
              key={item.name}
              to={item.path}
              className={`flex items-center justify-between px-3 py-2 text-[13px] border transition-colors w-full select-none ${
                active 
                  ? "bg-[#66ff66] text-[#000000] border-[#66ff66] font-medium" 
                  : "text-[#58ca58] hover:text-[#000000] hover:bg-[#66ff66] border-transparent"
              }`}
            >
              <span className="flex items-center gap-2 truncate">
                <span className={active ? "text-[#000000] font-bold" : "text-[#255325]"}>
                  [{item.code}]
                </span>
                <span className="truncate">{item.name.toUpperCase()}</span>
              </span>
              <span className="text-[11px] font-bold shrink-0">
                {active ? "▶" : "·"}
              </span>
            </Link>
          );
        })}
      </div>

      {/* User Information & Session Termination Footer */}
      <div className="p-3 border-t border-[#255325] flex flex-col gap-2.5 bg-[#000000]">
        {user && (
          <div className="border border-[#255325] p-2 flex flex-col gap-0.5 text-[11px]">
            <div className="text-[10px] text-[#255325] uppercase tracking-wider">
              AUTHENTICATED_ANALYST
            </div>
            <div className="text-[#ffffff] font-medium truncate">
              {user.username}
            </div>
            <div className="text-[#58ca58] text-[10px]">
              ROLE: {user.role.toUpperCase()}
            </div>
          </div>
        )}
        <button
          onClick={logout}
          className="px-3 py-1.5 border border-[#255325] text-[#58ca58] hover:border-[#66ff66] hover:text-[#000000] hover:bg-[#66ff66] text-center font-medium transition-colors cursor-pointer text-[12px]"
        >
          [ ⏻ TERMINATE_SESSION ]
        </button>
      </div>
    </aside>
  );
};

export default Sidebar;

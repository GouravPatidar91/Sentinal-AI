import React from "react";
import { Link, useLocation } from "react-router-dom";
import { 
  ShieldAlert, 
  LayoutDashboard, 
  AlertOctagon, 
  ListRestart, 
  Search, 
  Sliders, 
  LogOut, 
  User 
} from "lucide-react";
import { useAuth } from "../context/AuthContext";

export const Sidebar: React.FC = () => {
  const location = useLocation();
  const { user, logout } = useAuth();
  
  const navItems = [
    { name: "Dashboard", path: "/", icon: LayoutDashboard },
    { name: "Incidents", path: "/incidents", icon: AlertOctagon },
    { name: "Search Logs", path: "/search", icon: Search },
    { name: "Rules Engine", path: "/rules", icon: Sliders },
    { name: "Attack Simulator", path: "/simulator", icon: ListRestart }
  ];

  const isActive = (path: string) => {
    if (path === "/") {
      return location.pathname === "/";
    }
    return location.pathname.startsWith(path);
  };

  return (
    <aside className="w-64 glass-card border-r border-darkBorder flex flex-col h-screen sticky top-0">
      {/* Brand Logo Header */}
      <div className="p-6 border-b border-darkBorder flex items-center gap-3">
        <ShieldAlert className="w-8 h-8 text-red-500 animate-pulse" />
        <div>
          <h1 className="font-bold text-lg leading-none tracking-wider text-slate-100">SENTINELAI</h1>
          <span className="text-[10px] text-slate-500 font-semibold tracking-widest uppercase">AI AUTONOMOUS SOC</span>
        </div>
      </div>
      
      {/* Navigation Links */}
      <nav className="flex-1 px-4 py-6 space-y-1">
        {navItems.map((item) => {
          const Icon = item.icon;
          const active = isActive(item.path);
          return (
            <Link
              key={item.name}
              to={item.path}
              className={`flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-medium transition-all duration-200 ${
                active 
                  ? "bg-blue-600/15 text-blue-400 border border-blue-500/30" 
                  : "text-slate-400 hover:text-slate-100 hover:bg-slate-800/40 border border-transparent"
              }`}
            >
              <Icon className={`w-5 h-5 ${active ? "text-blue-400" : "text-slate-400"}`} />
              {item.name}
            </Link>
          );
        })}
      </nav>

      {/* User Information & Log out footer */}
      <div className="p-4 border-t border-darkBorder flex flex-col gap-3">
        {user && (
          <div className="flex items-center gap-3 px-2 py-1">
            <div className="w-8 h-8 rounded-full bg-slate-800 flex items-center justify-center border border-slate-700">
              <User className="w-4 h-4 text-slate-300" />
            </div>
            <div className="flex flex-col">
              <span className="text-xs font-semibold text-slate-300">{user.username}</span>
              <span className="text-[10px] text-slate-500 capitalize">{user.role}</span>
            </div>
          </div>
        )}
        <button
          onClick={logout}
          className="flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-medium text-red-400 hover:text-red-300 hover:bg-red-950/20 border border-transparent hover:border-red-900/30 transition-all duration-200 w-full"
        >
          <LogOut className="w-5 h-5 text-red-400" />
          Disconnect
        </button>
      </div>
    </aside>
  );
};
export default Sidebar;

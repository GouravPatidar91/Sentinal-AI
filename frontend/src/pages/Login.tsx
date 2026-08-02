import React, { useState } from "react";
import { useAuth } from "../context/AuthContext";
import { ShieldAlert, Lock, User, AlertCircle } from "lucide-react";
import { API_BASE } from "../config/api";

export const Login: React.FC = () => {
  const { login } = useAuth();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      const formData = new URLSearchParams();
      formData.append("username", username);
      formData.append("password", password);

      const resp = await fetch(`${API_BASE}/api/auth/login`, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: formData,
      });

      if (!resp.ok) {
        const errData = await resp.json();
        throw new Error(errData.detail || "Authentication failed");
      }

      const data = await resp.json();
      login(data.access_token, data.username, data.role);
    } catch (err: any) {
      setError(err.message || "Failed to connect to backend server");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen w-screen flex items-center justify-center bg-darkBg cyber-grid p-4 relative overflow-hidden">
      {/* Background glow graphics */}
      <div className="absolute top-1/4 left-1/3 w-96 h-96 bg-blue-600/10 rounded-full blur-3xl" />
      <div className="absolute bottom-1/4 right-1/3 w-96 h-96 bg-red-600/5 rounded-full blur-3xl" />

      {/* Login Card */}
      <div className="w-full max-w-md glass-card rounded-2xl p-8 relative z-10 border border-slate-800 shadow-2xl">
        
        {/* Brand */}
        <div className="flex flex-col items-center mb-8">
          <div className="w-14 h-14 rounded-xl bg-red-600/10 border border-red-500/30 flex items-center justify-center mb-3">
            <ShieldAlert className="w-8 h-8 text-red-500 animate-pulse" />
          </div>
          <h2 className="text-2xl font-bold text-slate-100 tracking-wider">SENTINELAI</h2>
          <span className="text-xs text-slate-500 uppercase tracking-widest font-semibold mt-1">
            Autonomous SOC & Investigation Platform
          </span>
        </div>

        {/* Error Alert */}
        {error && (
          <div className="mb-6 p-4 rounded-lg bg-red-950/40 border border-red-900/50 text-red-200 text-sm flex gap-3 items-start">
            <AlertCircle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
            <span>{error}</span>
          </div>
        )}

        {/* Form */}
        <form onSubmit={handleSubmit} className="space-y-6">
          <div>
            <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
              Analyst Username
            </label>
            <div className="relative">
              <span className="absolute inset-y-0 left-0 flex items-center pl-3">
                <User className="w-4 h-4 text-slate-500" />
              </span>
              <input
                type="text"
                required
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="e.g. admin or analyst"
                className="w-full bg-slate-900/60 border border-slate-800 focus:border-blue-500 rounded-lg py-2.5 pl-10 pr-4 text-sm text-slate-100 placeholder-slate-600 outline-none transition-colors"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
              Security Credentials
            </label>
            <div className="relative">
              <span className="absolute inset-y-0 left-0 flex items-center pl-3">
                <Lock className="w-4 h-4 text-slate-500" />
              </span>
              <input
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
                className="w-full bg-slate-900/60 border border-slate-800 focus:border-blue-500 rounded-lg py-2.5 pl-10 pr-4 text-sm text-slate-100 placeholder-slate-600 outline-none transition-colors"
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full bg-blue-600 hover:bg-blue-500 active:bg-blue-700 disabled:opacity-50 text-white rounded-lg py-2.5 text-sm font-semibold tracking-wide shadow-lg shadow-blue-500/20 transition-all cursor-pointer"
          >
            {loading ? "Authenticating..." : "Establish Secure Session"}
          </button>
        </form>

        {/* Demo Credentials Info */}
        <div className="mt-8 pt-6 border-t border-slate-900 text-center">
          <span className="text-[10px] text-slate-500 font-semibold tracking-widest uppercase block mb-3">
            Default Credentials (seeding)
          </span>
          <div className="bg-slate-950/50 border border-slate-900 rounded-lg p-3 text-[11px] font-mono text-slate-400 flex flex-col gap-1.5 align-middle justify-center">
            <div>
              <span className="text-blue-400">Admin:</span> admin <span className="opacity-40">/</span> admin123
            </div>
            <div>
              <span className="text-teal-400">Analyst:</span> analyst <span className="opacity-40">/</span> analyst123
            </div>
          </div>
        </div>

      </div>
    </div>
  );
};
export default Login;

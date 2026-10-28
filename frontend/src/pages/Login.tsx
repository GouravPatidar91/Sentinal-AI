import React, { useState } from "react";
import { Link } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
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
        throw new Error(errData.detail || "Authentication verification failed");
      }

      const data = await resp.json();
      login(data.access_token, data.username, data.role);
    } catch (err: any) {
      setError(err.message || "Failed to connect to backend authentication service");
    } finally {
      setLoading(false);
    }
  };

  const handleAutofill = (u: string, p: string) => {
    setUsername(u);
    setPassword(p);
  };

  return (
    <div className="min-h-screen w-screen flex flex-col items-center justify-center bg-[#000000] text-[#66ff66] font-mono p-4 select-text">
      
      {/* Return Link to Landing Page */}
      <div className="w-full max-w-lg mb-3 flex justify-between items-center text-[12px]">
        <Link 
          to="/" 
          className="text-[#58ca58] hover:text-[#000000] hover:bg-[#66ff66] px-2 py-0.5 border border-[#255325] transition-colors select-none"
        >
          [ ← RETURN_TO_MANUAL ]
        </Link>
        <span className="text-[#255325]">
          SESSION_PORT: 5173 // TLS_1.3
        </span>
      </div>

      {/* Main Terminal Login Dossier */}
      <div className="w-full max-w-lg border border-[#255325] bg-[#000000] p-6 sm:p-8 space-y-6">
        
        {/* Command Callout Header */}
        <div className="border-b border-[#255325] pb-4">
          <div className="flex items-center justify-between text-[12px] pb-2 mb-2 border-b border-[#255325]/50">
            <div className="flex items-center gap-2">
              <span className="text-[#255325] select-none">[00]</span>
              <span className="text-[#66ff66]">
                <span className="text-[#58ca58]">auth@soc:~$</span> sentinel --authenticate --token bearer
              </span>
            </div>
            <span className="px-1.5 py-0.2 bg-[#66ff66] text-[#000000] font-medium text-[10px] select-none">
              [LOCKED]
            </span>
          </div>

          <h1 className="text-[20px] font-bold text-[#ffffff] tracking-tight uppercase">
            SENTINEL_AI // SYS_AUTH_CONSOLE
          </h1>
          <p className="text-[12px] text-[#58ca58] mt-1 leading-relaxed">
            Autonomous Cyber Threat Defense System. Please provide authorized operator credentials to establish encrypted telemetry channel.
          </p>
        </div>

        {/* Error Alert Box */}
        {error && (
          <div className="p-3 border border-[#66ff66] bg-[#255325]/20 text-[12px] text-[#ffffff] space-y-1">
            <div className="font-bold text-[#66ff66] text-[11px]">
              [ ! ] AUTHENTICATION_REJECTED:
            </div>
            <div className="text-[#ffffff] leading-relaxed">
              {error}
            </div>
          </div>
        )}

        {/* Credentials Form */}
        <form onSubmit={handleSubmit} className="space-y-5">
          <div>
            <div className="flex justify-between items-center text-[11px] mb-1.5">
              <label className="text-[#58ca58] uppercase">
                [01] $ enter --username &lt;analyst_id&gt;
              </label>
              <span className="text-[#255325]">REQUIRED</span>
            </div>
            <div className="relative flex items-center border border-[#255325] focus-within:border-[#66ff66] transition-colors bg-[#000000]">
              <span className="text-[#58ca58] text-[12px] pl-3 select-none">&gt;</span>
              <input
                type="text"
                required
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="e.g. admin or analyst"
                className="w-full bg-transparent py-2 px-3 text-[13px] text-[#ffffff] placeholder-[#255325] outline-none font-mono"
              />
            </div>
          </div>

          <div>
            <div className="flex justify-between items-center text-[11px] mb-1.5">
              <label className="text-[#58ca58] uppercase">
                [02] $ enter --password &lt;secret_key&gt;
              </label>
              <span className="text-[#255325]">REQUIRED</span>
            </div>
            <div className="relative flex items-center border border-[#255325] focus-within:border-[#66ff66] transition-colors bg-[#000000]">
              <span className="text-[#58ca58] text-[12px] pl-3 select-none">&gt;</span>
              <input
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
                className="w-full bg-transparent py-2 px-3 text-[13px] text-[#ffffff] placeholder-[#255325] outline-none font-mono"
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full py-2.5 px-4 bg-[#66ff66] text-[#000000] hover:bg-[#ffffff] font-medium text-[13px] transition-colors cursor-pointer select-none text-center block disabled:opacity-50"
          >
            {loading ? "[ AUTHENTICATING_CREDENTIALS... █ ]" : "[ ↵ ESTABLISH_SECURE_SESSION ]"}
          </button>
        </form>

        {/* Seed Identities Diagnostic Box */}
        <div className="border-t border-[#255325] pt-4 space-y-3">
          <div className="flex justify-between items-center text-[10px] text-[#255325]">
            <span>[03] $ cat /etc/sentinel/seed_identities.conf</span>
            <span>DEV_SEEDS</span>
          </div>

          <div className="border border-[#255325] p-3 bg-[#000000] space-y-2 text-[11px]">
            <div className="flex justify-between items-center border-b border-[#255325]/40 pb-1.5">
              <div>
                <span className="text-[#ffffff] font-medium">ROLE [ADMIN]:</span>
                <span className="text-[#58ca58] ml-2">admin / admin123</span>
              </div>
              <button
                type="button"
                onClick={() => handleAutofill("admin", "admin123")}
                className="text-[10px] border border-[#255325] text-[#58ca58] hover:text-[#000000] hover:bg-[#66ff66] px-1.5 py-0.5 cursor-pointer transition-colors"
              >
                [ AUTOFILL ]
              </button>
            </div>

            <div className="flex justify-between items-center pt-0.5">
              <div>
                <span className="text-[#ffffff] font-medium">ROLE [ANALYST]:</span>
                <span className="text-[#58ca58] ml-2">analyst / analyst123</span>
              </div>
              <button
                type="button"
                onClick={() => handleAutofill("analyst", "analyst123")}
                className="text-[10px] border border-[#255325] text-[#58ca58] hover:text-[#000000] hover:bg-[#66ff66] px-1.5 py-0.5 cursor-pointer transition-colors"
              >
                [ AUTOFILL ]
              </button>
            </div>
          </div>
        </div>

      </div>

      {/* Terminal System Footer Note */}
      <div className="mt-4 text-[11px] text-[#255325] text-center">
        SENTINEL_AI CORE v2.4 // AUTHORIZED ACCESS ONLY // INCIDENTS MONITORED
      </div>
    </div>
  );
};

export default Login;

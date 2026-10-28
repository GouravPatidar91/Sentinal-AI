import React, { useState, useEffect, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";

interface TimelineEvent {
  timestamp: number; // in seconds from 0 to 22.5
  stage: "INGESTION" | "CORRELATION" | "DETECTED" | "INVESTIGATION" | "CONTAINMENT" | "RESOLVED";
  phaseIndex: number; // 0 to 4
  phaseName: string;
  log: {
    type: "SYS" | "WIN-EVT" | "WARN" | "CRIT" | "SOAR";
    text: string;
  };
  dashboard: {
    statusText: string;
    statusLevel: "NORMAL" | "WARNING" | "CRITICAL" | "CONTAINED";
    riskScore: number;
    anomalyScore: number;
    mitreTactic: string;
    mitreId: string;
    aiTriage: string;
    aiRootCause: string;
    soarStatus: "IDLE" | "ARMED" | "EXECUTING" | "CONTAINED";
    soarText: string;
  };
}

const TOTAL_LOOP_DURATION = 22.5; // seconds

const TIMELINE_EVENTS: TimelineEvent[] = [
  {
    timestamp: 0.5,
    stage: "INGESTION",
    phaseIndex: 0,
    phaseName: "01. BASELINE_INGEST",
    log: {
      type: "SYS",
      text: "SentinelAI Endpoint Daemon v1.0.4 active on desktop-agent-01 (PID 3892)"
    },
    dashboard: {
      statusText: "SYSTEM_SECURE // SENSORS_NORMAL",
      statusLevel: "NORMAL",
      riskScore: 12,
      anomalyScore: 0.04,
      mitreTactic: "Defense Baseline",
      mitreId: "T0000",
      aiTriage: "Continuous telemetry stream verified. Zero anomaly markers detected in the last 15-minute sliding window.",
      aiRootCause: "Normal operations. Endpoint agents reporting regular heartbeat signals.",
      soarStatus: "IDLE",
      soarText: "Standing by. Autonomous playbooks armed and waiting for policy trigger."
    }
  },
  {
    timestamp: 1.8,
    stage: "INGESTION",
    phaseIndex: 0,
    phaseName: "01. BASELINE_INGEST",
    log: {
      type: "SYS",
      text: "Ingesting Windows Security Event Stream (Channel: Security, Polling: 2000ms)"
    },
    dashboard: {
      statusText: "STREAMING_EVENTS // BUFFER_OK",
      statusLevel: "NORMAL",
      riskScore: 14,
      anomalyScore: 0.06,
      mitreTactic: "Defense Baseline",
      mitreId: "T0000",
      aiTriage: "Buffer ingestion rate: 420 events/sec. Sliding correlation window healthy.",
      aiRootCause: "Healthy baseline telemetry across all connected hosts.",
      soarStatus: "IDLE",
      soarText: "SOAR dispatch queues clear."
    }
  },
  {
    timestamp: 3.2,
    stage: "CORRELATION",
    phaseIndex: 1,
    phaseName: "02. INFILTRATE_ATTEMPT",
    log: {
      type: "WIN-EVT",
      text: "[WinEvt 4625] An account failed to log on. Account: Administrator | Host: corp-dc-server01"
    },
    dashboard: {
      statusText: "EVALUATING_LOGON_FAILURE // SINGLE_EVENT",
      statusLevel: "NORMAL",
      riskScore: 22,
      anomalyScore: 0.18,
      mitreTactic: "Credential Access",
      mitreId: "T1110",
      aiTriage: "Single logon failure recorded for domain Administrator. Checking rolling 15-minute threshold.",
      aiRootCause: "Potential credential typo or isolated authentication issue.",
      soarStatus: "IDLE",
      soarText: "Event cataloged in correlation window. No policy violation yet."
    }
  },
  {
    timestamp: 4.8,
    stage: "CORRELATION",
    phaseIndex: 1,
    phaseName: "02. INFILTRATE_ATTEMPT",
    log: {
      type: "WIN-EVT",
      text: "[WinEvt 4625] An account failed to log on. Failure Reason: %%2313 (Unknown username or bad password) [Iter 2]"
    },
    dashboard: {
      statusText: "CORRELATION_SPIKE_DETECTED // WINDOW_ACCUMULATION",
      statusLevel: "WARNING",
      riskScore: 42,
      anomalyScore: 0.38,
      mitreTactic: "Brute Force",
      mitreId: "T1110.001",
      aiTriage: "Sequential authentication failures detected within 1.6s. Frequency exceeds normal operational baseline.",
      aiRootCause: "Repeated failed credentials from single network socket: 192.168.1.105.",
      soarStatus: "IDLE",
      soarText: "Correlation counter incremented (2/5 failures in sliding window)."
    }
  },
  {
    timestamp: 6.2,
    stage: "CORRELATION",
    phaseIndex: 1,
    phaseName: "02. INFILTRATE_ATTEMPT",
    log: {
      type: "WARN",
      text: "[ALERT] Rule #104 matched: Rapid Failed Authentication sequence (Count: 5 in 3000ms)"
    },
    dashboard: {
      statusText: "CORRELATION_TRIGGER_MATCH // RULE_104",
      statusLevel: "WARNING",
      riskScore: 68,
      anomalyScore: 0.62,
      mitreTactic: "Password Spraying",
      mitreId: "T1110.003",
      aiTriage: "High velocity failed logons confirmed. Heuristic anomaly engine flags 99.4% probability of automated brute force attack.",
      aiRootCause: "Distributed or automated password spray script targeting high-privilege account.",
      soarStatus: "ARMED",
      soarText: "Playbook #PB-AUTH-LOCK armed. Monitoring for exploitation."
    }
  },
  {
    timestamp: 8.0,
    stage: "DETECTED",
    phaseIndex: 2,
    phaseName: "03. ACTIVE_BREACH",
    log: {
      type: "WIN-EVT",
      text: "[WinEvt 4688] A new process has been created. Creator: svchost.exe | NewProcess: powershell.exe"
    },
    dashboard: {
      statusText: "SUSPICIOUS_SPAWN_DETECTED // PROCESS_4688",
      statusLevel: "CRITICAL",
      riskScore: 84,
      anomalyScore: 0.81,
      mitreTactic: "Execution",
      mitreId: "T1059.001",
      aiTriage: "Abnormal parent-child process relationship: powershell.exe spawned directly by system service svchost.exe.",
      aiRootCause: "Privilege escalation or unauthorized process execution.",
      soarStatus: "ARMED",
      soarText: "Playbook armed. Evaluating command line arguments."
    }
  },
  {
    timestamp: 9.6,
    stage: "DETECTED",
    phaseIndex: 2,
    phaseName: "03. ACTIVE_BREACH",
    log: {
      type: "CRIT",
      text: "[ANOMALY_ENGINE] Command Line: powershell.exe -nop -w hidden -EncodedCommand JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwA..."
    },
    dashboard: {
      statusText: "CRITICAL_THREAT_CONFIRMED // OBFUSCATED_PAYLOAD",
      statusLevel: "CRITICAL",
      riskScore: 96,
      anomalyScore: 0.94,
      mitreTactic: "Defense Evasion",
      mitreId: "T1027",
      aiTriage: "Base64 encoded hidden PowerShell command detected. Isolation Forest anomaly score: 0.94 (Extreme Outlier).",
      aiRootCause: "Obfuscated reverse shell / Cobalt Strike beacon execution detected on corp-dc-server01.",
      soarStatus: "ARMED",
      soarText: "Playbook #SOAR-94 (Autonomous Host Quarantine) triggered. Dispatching containment."
    }
  },
  {
    timestamp: 11.4,
    stage: "INVESTIGATION",
    phaseIndex: 3,
    phaseName: "04. AI_TRIAGE_DISPATCH",
    log: {
      type: "SYS",
      text: "[AI-AGENT] Multi-Agent Forensic Pipeline Dispatched: Ingesting host artifacts and open sockets"
    },
    dashboard: {
      statusText: "MULTI_AGENT_AI_ANALYSIS // CORRELATING_SOCKETS",
      statusLevel: "CRITICAL",
      riskScore: 98,
      anomalyScore: 0.98,
      mitreTactic: "Command and Control",
      mitreId: "T1071.001",
      aiTriage: "Agent Investigator correlating active TCP connection on PID 4082 -> External IP 45.154.255.88:443.",
      aiRootCause: "Confirmed unauthorized external C2 callback initiated via injected PowerShell process.",
      soarStatus: "EXECUTING",
      soarText: "Authorizing autonomous isolation: Terminating PID 4082 & blocking socket."
    }
  },
  {
    timestamp: 13.5,
    stage: "INVESTIGATION",
    phaseIndex: 3,
    phaseName: "04. AI_TRIAGE_DISPATCH",
    log: {
      type: "SYS",
      text: "[AI-AGENT] Root Cause Confirmed: Remote shell session active on TCP 192.168.1.10:52410 -> 45.154.255.88:443"
    },
    dashboard: {
      statusText: "ROOT_CAUSE_LOCKED // GENERATING_PLAYBOOK",
      statusLevel: "CRITICAL",
      riskScore: 99,
      anomalyScore: 0.99,
      mitreTactic: "Exfiltration Prevention",
      mitreId: "T1041",
      aiTriage: "Attacker attempting discovery commands (whoami /priv, net group 'Domain Admins'). Immediate containment required.",
      aiRootCause: "Interactive remote operator on target host. Threat classification: Tier-1 APT.",
      soarStatus: "EXECUTING",
      soarText: "Dispatching OS command payload to endpoint agent..."
    }
  },
  {
    timestamp: 15.6,
    stage: "CONTAINMENT",
    phaseIndex: 4,
    phaseName: "05. SOAR_CONTAINMENT",
    log: {
      type: "SOAR",
      text: ">>> [SOAR ENGINE] Automated Response Policy #SOAR-94 approved -> Dispatching to corp-dc-server01"
    },
    dashboard: {
      statusText: "EXECUTING_CONTAINMENT // DISPATCH_ACTIVE",
      statusLevel: "WARNING",
      riskScore: 78,
      anomalyScore: 0.70,
      mitreTactic: "Remediation",
      mitreId: "SOAR-94",
      aiTriage: "Command pipeline active. Executing process termination and inbound network block directly via OS kernel.",
      aiRootCause: "Neutralizing active threat session.",
      soarStatus: "EXECUTING",
      soarText: "Executing: Stop-Process & NetFirewallBlock"
    }
  },
  {
    timestamp: 16.8,
    stage: "CONTAINMENT",
    phaseIndex: 4,
    phaseName: "05. SOAR_CONTAINMENT",
    log: {
      type: "SOAR",
      text: "[SOAR EXEC] powershell -Command \"Stop-Process -Id 4082 -Force\""
    },
    dashboard: {
      statusText: "TERMINATING_PID_4082 // SIGKILL",
      statusLevel: "WARNING",
      riskScore: 48,
      anomalyScore: 0.45,
      mitreTactic: "Remediation",
      mitreId: "SOAR-94",
      aiTriage: "Process 4082 terminated forcefully. Killing attacker reverse shell.",
      aiRootCause: "Neutralizing active threat session.",
      soarStatus: "EXECUTING",
      soarText: "PID 4082 killed. Deploying firewall drop rule..."
    }
  },
  {
    timestamp: 18.0,
    stage: "CONTAINMENT",
    phaseIndex: 4,
    phaseName: "05. SOAR_CONTAINMENT",
    log: {
      type: "SOAR",
      text: "[SOAR EXEC] netsh advfirewall firewall add rule name=\"BLOCK_C2_IP\" dir=out action=block remoteip=45.154.255.88"
    },
    dashboard: {
      statusText: "C2_SOCKET_BLOCKED // FIREWALL_ACTIVE",
      statusLevel: "WARNING",
      riskScore: 28,
      anomalyScore: 0.22,
      mitreTactic: "Remediation",
      mitreId: "SOAR-94",
      aiTriage: "Perimeter and host firewall rule applied. External IP 45.154.255.88 completely blacklisted from internal network.",
      aiRootCause: "Attacker C2 channel severed completely.",
      soarStatus: "EXECUTING",
      soarText: "Host firewall rule persistent. Isolating network adapter."
    }
  },
  {
    timestamp: 19.4,
    stage: "CONTAINMENT",
    phaseIndex: 4,
    phaseName: "05. SOAR_CONTAINMENT",
    log: {
      type: "SOAR",
      text: ">>> [SOAR SUCCESS] Host corp-dc-server01 quarantined. Threat neutralized in 420ms."
    },
    dashboard: {
      statusText: "THREAT_CONTAINED // POSTURE_STABILIZED",
      statusLevel: "CONTAINED",
      riskScore: 14,
      anomalyScore: 0.08,
      mitreTactic: "Neutralized",
      mitreId: "RESOLVED",
      aiTriage: "Threat successfully contained in 420ms. Malicious process terminated. Host isolated from lateral movement. Baseline restored.",
      aiRootCause: "Incident #1042 marked as resolved. Security policy restored.",
      soarStatus: "CONTAINED",
      soarText: "CONTAINMENT COMPLETE — THREAT QUARANTINED (Exit code 0)"
    }
  },
  {
    timestamp: 20.8,
    stage: "RESOLVED",
    phaseIndex: 4,
    phaseName: "05. SOAR_CONTAINMENT",
    log: {
      type: "SYS",
      text: "[SYS] Incident #1042 marked as RESOLVED & ARCHIVED. Rolling correlation window reset."
    },
    dashboard: {
      statusText: "SYSTEM_SECURED // AUDIT_VERIFIED",
      statusLevel: "CONTAINED",
      riskScore: 12,
      anomalyScore: 0.04,
      mitreTactic: "Defense Baseline",
      mitreId: "T0000",
      aiTriage: "Host integrity verified. All active connections audit clean. Preparing telemetry buffer for next cycle.",
      aiRootCause: "Full attack lifecycle contained automatically without human lag.",
      soarStatus: "CONTAINED",
      soarText: "System secure. Telemetry cycle resetting."
    }
  }
];

export const LandingPage: React.FC = () => {
  const { isAuthenticated } = useAuth();
  const navigate = useNavigate();

  // Playback State
  const [isPlaying, setIsPlaying] = useState<boolean>(true);
  const [playbackSpeed, setPlaybackSpeed] = useState<number>(1.0);
  const [elapsedTime, setElapsedTime] = useState<number>(0);

  // References
  const terminalContainerRef = useRef<HTMLDivElement>(null);
  const timerRef = useRef<any>(null);

  // Video clock timer
  useEffect(() => {
    if (!isPlaying) {
      clearInterval(timerRef.current);
      return;
    }

    const intervalMs = 100;
    timerRef.current = setInterval(() => {
      setElapsedTime((prev) => {
        const next = prev + (intervalMs / 1000) * playbackSpeed;
        if (next >= TOTAL_LOOP_DURATION) {
          return 0; // Seamless loop restart!
        }
        return next;
      });
    }, intervalMs);

    return () => clearInterval(timerRef.current);
  }, [isPlaying, playbackSpeed]);

  // Derive visible logs and current dashboard state based on elapsed time
  const visibleEvents = TIMELINE_EVENTS.filter((ev) => ev.timestamp <= elapsedTime);
  const currentEvent = visibleEvents.length > 0
    ? visibleEvents[visibleEvents.length - 1]
    : TIMELINE_EVENTS[0];

  // Auto-scroll inside terminal container only
  useEffect(() => {
    if (terminalContainerRef.current) {
      terminalContainerRef.current.scrollTop = terminalContainerRef.current.scrollHeight;
    }
  }, [visibleEvents.length]);

  // Formatter for timecode
  const formatTimecode = (sec: number) => {
    const s = Math.floor(sec);
    const ms = Math.floor((sec % 1) * 10);
    return `${s.toString().padStart(2, "0")}.${ms}s`;
  };

  // Helper for character-based ASCII meter
  const renderAsciiMeter = (val: number, max: number, chars = 20) => {
    const filled = Math.min(chars, Math.max(0, Math.round((val / max) * chars)));
    return "█".repeat(filled) + "░".repeat(chars - filled);
  };

  const progressPercent = Math.min(100, (elapsedTime / TOTAL_LOOP_DURATION) * 100);

  const phaseChips = [
    "01. INGEST",
    "02. INFILTRATE",
    "03. BREACH",
    "04. AI_TRIAGE",
    "05. CONTAINED"
  ];

  return (
    <div data-native-style="terminal">
      <main className="session">

        {/* ============================================================== */}
        {/* SESSION HEADER & TOP BAR                                       */}
        {/* ============================================================== */}
        <header className="session-header">
          <div className="session-bar">
            <span className="brand">SentinelAI</span>
            <span aria-hidden="true">/ autonomous soc platform</span>
            <span className="session-mode" aria-hidden="true">[ LIVE TELEMETRY SESSION ]</span>
          </div>

          <nav aria-label="Main navigation">
            <ul data-copy-list="navigation">
              <li><a href="#hero">Overview</a></li>
              <li><a href="#simulation">Simulation</a></li>
              <li><a href="#about">Architecture</a></li>
              <li><a href="#features">Capabilities</a></li>
              <li><a href="#process">Pipeline</a></li>
              <li><a href="#developers">Developers</a></li>
              <li><a href="#synopsis">Synopsis</a></li>
              <li><a href="#faq">FAQ</a></li>
            </ul>
            <span className="nav-path" aria-hidden="true">~/sentinel-ai</span>
          </nav>
        </header>

        {/* ============================================================== */}
        {/* [00] HERO & WORDMARK STARTUP                                  */}
        {/* ============================================================== */}
        <section id="hero" data-section="hero">
          <div className="command" aria-hidden="true">
            <span className="command-index">00</span>
            <span className="command-text">
              <span className="prompt">sentinel@soc:~$</span> sentinel --init --mode autonomous-defense
            </span>
          </div>

          <div className="output">
            <div className="startup">
              <pre className="wordmark" aria-hidden="true">
                {`███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     
██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     
███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     
╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     
███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝`}
              </pre>
              <span className="startup-status" aria-hidden="true">
                [OK]<br />
                engine active
              </span>
            </div>

            <div className="hero-layout">
              <div className="hero-promise">
                <h1>Autonomous AI Security Operations Center & Threat Defense</h1>
                <p className="hero-description">
                  SentinelAI unifies endpoint event log ingestion, memory-mapped sliding correlation windows, and unsupervised anomaly detection to neutralize enterprise threats in under 500 milliseconds.
                </p>

                <div className="actions">
                  <a className="action primary" href="#simulation">
                    Start live demo
                  </a>
                  <button
                    onClick={() => navigate(isAuthenticated ? "/dashboard" : "/login")}
                    className="action"
                  >
                    {isAuthenticated ? "Enter SOC Console" : "Analyst Login"}
                  </button>
                </div>

                <p className="trust">Defending 120,000+ enterprise endpoints globally</p>
              </div>

              <dl className="stats">
                <div className="stat">
                  <dt>Active Endpoints</dt>
                  <dd>
                    <span className="stat-value">19+</span>
                    <span className="stat-trend"></span>
                  </dd>
                </div>
                <div className="stat">
                  <dt>Containment SLA</dt>
                  <dd>
                    <span className="stat-value">&lt; 500ms</span>
                    <span className="stat-trend">Sub-second response</span>
                  </dd>
                </div>
                <div className="stat">
                  <dt>Uptime SLA</dt>
                  <dd>
                    <span className="stat-value">99.999%</span>
                    <span className="stat-trend">Enterprise grade</span>
                  </dd>
                </div>
                <div className="stat">
                  <dt>Breaches Prevented</dt>
                  <dd>
                    <span className="stat-value">1,420+</span>
                    <span className="stat-trend">Zero human latency</span>
                  </dd>
                </div>
              </dl>
            </div>
          </div>
        </section>

        {/* ============================================================== */}
        {/* [01] LIVE TERMINAL & DASHBOARD SIMULATION (SYNCHRONIZED)       */}
        {/* ============================================================== */}
        <section id="simulation" data-section="simulation">
          <div className="command" aria-hidden="true">
            <span className="command-index">01</span>
            <span className="command-text">
              <span className="prompt">sentinel@soc:~$</span> sentinel --stream live-telemetry --window 15m --sync 60fps
            </span>
          </div>

          <div className="output">
            <h2>Live Telemetry &amp; Autonomous Threat Containment</h2>
            <p className="section-subtitle">
              Synchronized motion-graphic demonstration: raw Windows Event Logs (left) stream directly into real-time SOC triage and SOAR dispatch (right).
            </p>

            {/* Simulation Outer Shell */}
            <div className="border border-[#255325] bg-[#000000] text-[14px]">

              {/* Session Control Header Bar */}
              <div className="border-b border-[#255325] p-3 flex flex-wrap items-center justify-between gap-3 bg-[#000000]">
                <div className="flex items-center gap-2">
                  <span className="text-[#58ca58]">SESSION_CLOCK:</span>
                  <span className="text-[#ffffff] font-medium tracking-wider">
                    {formatTimecode(elapsedTime)} / {formatTimecode(TOTAL_LOOP_DURATION)}
                  </span>
                  <span className="text-[#255325]">|</span>
                  <span className="text-[#58ca58] hidden sm:inline">
                    STATUS: <span className="text-[#66ff66]">{currentEvent.stage}</span>
                  </span>
                </div>

                {/* Phase Tracker Chips */}
                <div className="hidden lg:flex items-center gap-1.5 text-[12px]">
                  {phaseChips.map((phase, idx) => {
                    const isCurrent = idx === currentEvent.phaseIndex;
                    const isPast = idx < currentEvent.phaseIndex;
                    return (
                      <span
                        key={phase}
                        className={`px-2 py-0.5 border ${isCurrent
                          ? "border-[#66ff66] bg-[#66ff66] text-[#000000] font-medium"
                          : isPast
                            ? "border-[#255325] text-[#58ca58]"
                            : "border-[#255325] text-[#255325]"
                          }`}
                      >
                        {phase}
                      </span>
                    );
                  })}
                </div>

                {/* Media Playback Controls */}
                <div className="flex items-center gap-2 text-[13px]">
                  <button
                    onClick={() => setIsPlaying(!isPlaying)}
                    className="px-2.5 py-1 border border-[#66ff66] text-[#66ff66] hover:bg-[#66ff66] hover:text-[#000000] transition-colors"
                    title={isPlaying ? "Pause simulation" : "Play simulation"}
                  >
                    [ {isPlaying ? "❚❚ PAUSE" : "▶ PLAY"} ]
                  </button>

                  <button
                    onClick={() => setElapsedTime(0)}
                    className="px-2.5 py-1 border border-[#255325] text-[#58ca58] hover:border-[#66ff66] hover:text-[#66ff66] transition-colors"
                    title="Restart loop"
                  >
                    [ ↺ RESTART ]
                  </button>

                  <button
                    onClick={() => setPlaybackSpeed(playbackSpeed === 1.0 ? 1.5 : playbackSpeed === 1.5 ? 2.0 : 1.0)}
                    className="px-2 py-1 border border-[#255325] text-[#58ca58] hover:border-[#66ff66] hover:text-[#66ff66] transition-colors"
                    title="Toggle playback speed"
                  >
                    [ {playbackSpeed}x ]
                  </button>
                </div>
              </div>

              {/* Progress Track */}
              <div className="h-[2px] bg-[#255325] w-full">
                <div
                  className="h-full bg-[#66ff66] transition-all duration-100 ease-linear"
                  style={{ width: `${progressPercent}%` }}
                />
              </div>

              {/* Dual Simulation Panes */}
              <div className="grid grid-cols-1 lg:grid-cols-2 divide-y lg:divide-y-0 lg:divide-x divide-[#255325] min-h-[500px]">

                {/* -------------------------------------------------------- */}
                {/* LEFT PANE: LIVE TERMINAL & LOG COLLECTOR                 */}
                {/* -------------------------------------------------------- */}
                <div className="flex flex-col bg-[#000000]">
                  {/* Pane Subheader */}
                  <div className="px-4 py-2 border-b border-[#255325] flex items-center justify-between text-[13px] bg-[#000000]">
                    <div className="flex items-center gap-2">
                      <span className="text-[#66ff66] font-medium">TERMINAL_01</span>
                      <span className="text-[#255325]">/</span>
                      <span className="text-[#58ca58]">corp-dc-server01 (192.168.1.10)</span>
                    </div>
                    <span className="text-[#58ca58]">TAIL -F /VAR/LOG/SECURITY.EVTX</span>
                  </div>

                  {/* Terminal Log Stream Area (Self-Contained Scrolling) */}
                  <div
                    ref={terminalContainerRef}
                    className="flex-1 p-4 overflow-y-auto max-h-[460px] font-mono text-[13px] leading-[1.6] space-y-2 select-text"
                  >
                    <div className="text-[#255325] select-none">
                      # Windows Event Forwarder &amp; Linux Auth Collector Daemon
                    </div>
                    <div className="text-[#255325] select-none pb-2">
                      # Subscribed channels: Security, System, Microsoft-Windows-Sysmon/Operational
                    </div>

                    {visibleEvents.map((evt, idx) => {
                      const lineNum = (idx + 1).toString().padStart(3, "0");
                      const isLast = idx === visibleEvents.length - 1;

                      let badgeColor = "text-[#58ca58] border-[#255325]";
                      let textColor = "text-[#58ca58]";

                      if (evt.log.type === "WARN") {
                        badgeColor = "text-[#ffffff] bg-[#255325] border-[#58ca58]";
                        textColor = "text-[#ffffff]";
                      } else if (evt.log.type === "CRIT") {
                        badgeColor = "text-[#000000] bg-[#66ff66] border-[#66ff66] font-bold";
                        textColor = "text-[#66ff66] font-medium";
                      } else if (evt.log.type === "SOAR") {
                        badgeColor = "text-[#000000] bg-[#ffffff] border-[#ffffff] font-bold";
                        textColor = "text-[#ffffff] font-medium";
                      }

                      return (
                        <div
                          key={idx}
                          className={`flex items-start gap-2.5 transition-colors ${isLast ? "bg-[#255325]/20 py-0.5 px-1 -mx-1" : ""
                            }`}
                        >
                          <span className="text-[#255325] select-none shrink-0 font-mono">
                            {lineNum}
                          </span>
                          <span className="text-[#58ca58] shrink-0 text-[12px] select-none">
                            [{formatTimecode(evt.timestamp)}]
                          </span>
                          <span className={`px-1 text-[11px] border shrink-0 ${badgeColor}`}>
                            [{evt.log.type}]
                          </span>
                          <span className={`break-all ${textColor}`}>
                            {evt.log.text}
                          </span>
                        </div>
                      );
                    })}

                    {/* Blinking prompt line */}
                    <div className="pt-2 text-[#66ff66] flex items-center gap-2">
                      <span className="select-none">admin@corp-dc-server01:~$</span>
                      <span className="cursor">█</span>
                    </div>
                  </div>

                  {/* Terminal Status Bar */}
                  <div className="px-4 py-2 border-t border-[#255325] flex items-center justify-between text-[12px] text-[#58ca58] bg-[#000000]">
                    <span>BUFFER: {visibleEvents.length} / {TIMELINE_EVENTS.length} EVENTS</span>
                    <span>ENCODING: UTF-8</span>
                    <span>SOCKET: ESTABLISHED</span>
                  </div>
                </div>

                {/* -------------------------------------------------------- */}
                {/* RIGHT PANE: SOC DASHBOARD & THREAT TRIAGE READOUT        */}
                {/* -------------------------------------------------------- */}
                <div className="flex flex-col bg-[#000000] p-4 text-[13px]">

                  {/* Dashboard Header Bar */}
                  <div className="border-b border-[#255325] pb-3 mb-4 flex items-center justify-between">
                    <div>
                      <div className="text-[11px] text-[#58ca58] uppercase tracking-wider">
                        AUTONOMOUS CORRELATION ENGINE
                      </div>
                      <div className="text-[#ffffff] font-medium text-[16px] tracking-tight">
                        {currentEvent.dashboard.statusText}
                      </div>
                    </div>

                    <span
                      className={`px-2 py-0.5 border text-[12px] font-medium ${currentEvent.dashboard.statusLevel === "CRITICAL"
                        ? "border-[#66ff66] bg-[#66ff66] text-[#000000]"
                        : currentEvent.dashboard.statusLevel === "WARNING"
                          ? "border-[#58ca58] text-[#ffffff] bg-[#255325]"
                          : currentEvent.dashboard.statusLevel === "CONTAINED"
                            ? "border-[#ffffff] bg-[#ffffff] text-[#000000]"
                            : "border-[#255325] text-[#58ca58]"
                        }`}
                    >
                      [ {currentEvent.dashboard.statusLevel} ]
                    </span>
                  </div>

                  {/* Telemetry Metrics with ASCII Bars */}
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mb-4">
                    <div className="border border-[#255325] p-3">
                      <div className="flex justify-between items-baseline mb-1">
                        <span className="text-[#58ca58] text-[12px]">THREAT RISK SCORE</span>
                        <span className="text-[#ffffff] font-medium text-[14px]">
                          {currentEvent.dashboard.riskScore}/100
                        </span>
                      </div>
                      <div className="text-[#66ff66] font-mono tracking-tighter text-[12px]">
                        [{renderAsciiMeter(currentEvent.dashboard.riskScore, 100, 16)}]
                      </div>
                    </div>

                    <div className="border border-[#255325] p-3">
                      <div className="flex justify-between items-baseline mb-1">
                        <span className="text-[#58ca58] text-[12px]">ISOLATION FOREST ANOMALY</span>
                        <span className="text-[#ffffff] font-medium text-[14px]">
                          {currentEvent.dashboard.anomalyScore.toFixed(2)}
                        </span>
                      </div>
                      <div className="text-[#66ff66] font-mono tracking-tighter text-[12px]">
                        [{renderAsciiMeter(currentEvent.dashboard.anomalyScore, 1.0, 16)}]
                      </div>
                    </div>
                  </div>

                  {/* MITRE Technique Readout */}
                  <div className="border border-[#255325] p-3 mb-4">
                    <div className="text-[11px] text-[#58ca58] uppercase mb-1">
                      MITRE ATT&amp;CK TECHNIQUE CORRELATED
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-[#ffffff] font-medium">
                        {currentEvent.dashboard.mitreTactic}
                      </span>
                      <span className="text-[#66ff66] font-mono">
                        [{currentEvent.dashboard.mitreId}]
                      </span>
                    </div>
                  </div>

                  {/* Multi-Agent AI Triage Narrative */}
                  <div className="border border-[#255325] p-3 mb-4 flex-1">
                    <div className="flex items-center justify-between mb-1.5">
                      <span className="text-[11px] text-[#58ca58] uppercase">
                        MULTI-AGENT AI FORENSIC TRIAGE
                      </span>
                      <span className="text-[11px] text-[#66ff66]">[ACTIVE INFERENCE]</span>
                    </div>
                    <p className="text-[#ffffff] text-[13px] leading-[1.5] mb-2">
                      {currentEvent.dashboard.aiTriage}
                    </p>
                    <div className="text-[#58ca58] text-[12px] border-t border-[#255325] pt-2">
                      <span className="text-[#255325]">&gt;</span> ROOT CAUSE: {currentEvent.dashboard.aiRootCause}
                    </div>
                  </div>

                  {/* SOAR Action Status Box */}
                  <div className="border border-[#255325] p-3 bg-[#000000]">
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-[11px] text-[#58ca58] uppercase">
                        AUTONOMOUS SOAR ORCHESTRATOR
                      </span>
                      <span
                        className={`text-[11px] font-medium px-1.5 py-0.2 border ${currentEvent.dashboard.soarStatus === "CONTAINED"
                          ? "bg-[#ffffff] text-[#000000] border-[#ffffff]"
                          : currentEvent.dashboard.soarStatus === "EXECUTING"
                            ? "bg-[#66ff66] text-[#000000] border-[#66ff66]"
                            : currentEvent.dashboard.soarStatus === "ARMED"
                              ? "bg-[#255325] text-[#ffffff] border-[#58ca58]"
                              : "text-[#58ca58] border-[#255325]"
                          }`}
                      >
                        [ {currentEvent.dashboard.soarStatus} ]
                      </span>
                    </div>
                    <p className="text-[#66ff66] font-mono text-[12px] break-all">
                      &gt; {currentEvent.dashboard.soarText}
                    </p>
                  </div>

                </div>
              </div>
            </div>
          </div>
        </section>

        {/* ============================================================== */}
        {/* [02] ARCHITECTURE & PHILOSOPHY (MAN SENTINEL)                 */}
        {/* ============================================================== */}
        <section id="about" data-section="about">
          <div className="command" aria-hidden="true">
            <span className="command-index">02</span>
            <span className="command-text">
              <span className="prompt">sentinel@soc:~$</span> man sentinel
            </span>
          </div>

          <div className="output">
            <h2 className="about-title">
              A continuous autonomous defense loop engineered to neutralize threats before human triage can begin.
            </h2>
            <div className="about-copy">
              <p>
                SentinelAI eliminates the critical lag between telemetry ingestion and containment. By binding lightweight native collectors to Windows Security Event logs and Linux authentication channels, events are streamed in real time to memory-mapped sliding correlation windows.
              </p>
              <p>
                Heuristic rule evaluation occurs concurrently with an unsupervised Isolation Forest anomaly scoring model. When multi-vector correlation thresholds are breached, autonomous multi-agent forensic pipelines verify intent and execute kernel-level process termination and firewall isolation in sub-second timelines.
              </p>
            </div>
          </div>
        </section>

        {/* ============================================================== */}
        {/* [03] CAPABILITIES LISTING                                      */}
        {/* ============================================================== */}
        <section id="features" data-section="features">
          <div className="command" aria-hidden="true">
            <span className="command-index">03</span>
            <span className="command-text">
              <span className="prompt">sentinel@soc:~$</span> sentinel --list capabilities
            </span>
          </div>

          <div className="output">
            <h2>Everything required for autonomous enterprise defense</h2>
            <div className="capability-list">

              <article className="capability">
                <span className="row-index" aria-hidden="true">01</span>
                <h3>Native Event Ingestion</h3>
                <p>
                  Low-footprint endpoint agents read WinEvt channels (4625, 4688, 7045) and syslog sockets directly with zero CPU throttling.
                </p>
              </article>

              <article className="capability">
                <span className="row-index" aria-hidden="true">02</span>
                <h3>Sliding Correlation Windows</h3>
                <p>
                  15-minute rolling memory buffer groups related events by source IP, host, and user session to expose multi-stage attack patterns.
                </p>
              </article>

              <article className="capability">
                <span className="row-index" aria-hidden="true">03</span>
                <h3>Isolation Forest Anomalies</h3>
                <p>
                  Unsupervised machine learning scores deviations against baseline behavioral distributions without reliance on static signature databases.
                </p>
              </article>

              <article className="capability">
                <span className="row-index" aria-hidden="true">04</span>
                <h3>Multi-Agent AI Triage</h3>
                <p>
                  Specialized LLM agents autonomously query process genealogies, verify command-line obfuscation, and formulate root-cause deductions.
                </p>
              </article>

              <article className="capability">
                <span className="row-index" aria-hidden="true">05</span>
                <h3>Sub-Second SOAR Playbooks</h3>
                <p>
                  Autonomous response rules execute PowerShell SIGKILL, host isolation, and perimeter firewall blocks under verified containment thresholds.
                </p>
              </article>

              <article className="capability">
                <span className="row-index" aria-hidden="true">06</span>
                <h3>MITRE ATT&amp;CK Alignment</h3>
                <p>
                  Every matched event and incident is classified against standard enterprise tactics, techniques, and procedures (TTPs).
                </p>
              </article>

            </div>
          </div>
        </section>

        {/* ============================================================== */}
        {/* [04] HOW SENTINEL OPERATES (PIPELINE STEPS)                   */}
        {/* ============================================================== */}
        <section id="process" data-section="process">
          <div className="command" aria-hidden="true">
            <span className="command-index">04</span>
            <span className="command-text">
              <span className="prompt">sentinel@soc:~$</span> sentinel --setup pipeline
            </span>
          </div>

          <div className="output">
            <h2>How SentinelAI Works</h2>
            <p className="section-subtitle">
              From unparsed OS kernel events to verified quarantine in 420 milliseconds.
            </p>

            <ol className="steps">
              <li>
                <span className="step-index" aria-hidden="true">[01]</span>
                <div>
                  <h3>Ingest Telemetry</h3>
                  <p>
                    Deploy lightweight forwarder agents across Windows and Linux servers. Raw kernel and security event streams are ingested with zero configuration overhead.
                  </p>
                </div>
              </li>

              <li>
                <span className="step-index" aria-hidden="true">[02]</span>
                <div>
                  <h3>Correlate &amp; Score</h3>
                  <p>
                    Events enter a 15-minute sliding correlation window evaluated against deterministic detection rules and an unsupervised Isolation Forest machine learning model.
                  </p>
                </div>
              </li>

              <li>
                <span className="step-index" aria-hidden="true">[03]</span>
                <div>
                  <h3>Autonomous SOAR Quarantine</h3>
                  <p>
                    Multi-agent AI verifies root cause and triggers deterministic containment payloads: terminating rogue processes, isolating sockets, and cutting C2 callbacks.
                  </p>
                </div>
              </li>
            </ol>
          </div>
        </section>

        {/* ============================================================== */}
        {/* [05] OPERATIONAL IMPACT & BENEFITS                            */}
        {/* ============================================================== */}
        <section id="benefits" data-section="benefits">
          <div className="command" aria-hidden="true">
            <span className="command-index">05</span>
            <span className="command-text">
              <span className="prompt">sentinel@soc:~$</span> sentinel --results metrics
            </span>
          </div>

          <div className="output">
            <h2>Why Security Teams Choose SentinelAI</h2>
            <div className="benefit-list">

              <article>
                <span className="benefit-check" aria-hidden="true">[+]</span>
                <div>
                  <h3>Eliminate Alert Fatigue</h3>
                  <p>
                    Reduce tier-1 triage noise by up to 88% through automated multi-vector correlation and noise suppression.
                  </p>
                </div>
              </article>

              <article>
                <span className="benefit-check" aria-hidden="true">[+]</span>
                <div>
                  <h3>Sub-Second Containment</h3>
                  <p>
                    Neutralize active ransomware and lateral movement before attackers establish persistence across endpoints.
                  </p>
                </div>
              </article>

              <article>
                <span className="benefit-check" aria-hidden="true">[+]</span>
                <div>
                  <h3>Audit-Ready Forensic Trails</h3>
                  <p>
                    Full session replay, raw log hashes, and AI deductive reasoning generated automatically for compliance reviews.
                  </p>
                </div>
              </article>

              <article>
                <span className="benefit-check" aria-hidden="true">[+]</span>
                <div>
                  <h3>Zero Complex SIEM Queries</h3>
                  <p>
                    No complex query syntax needed. Multi-agent AI provides plain-text forensic summaries and actionable recommendations.
                  </p>
                </div>
              </article>

            </div>
          </div>
        </section>

        {/* ============================================================== */}
        {/* [06] SYSTEM DEVELOPERS & RESEARCH ENGINEERING                   */}
        {/* ============================================================== */}
        <section id="developers" data-section="developers">
          <div className="command" aria-hidden="true">
            <span className="command-index">06</span>
            <span className="command-text">
              <span className="prompt">sentinel@soc:~$</span> sentinel --inspect developers --academic-credentials
            </span>
          </div>

          <div className="output">
            <h2>System Developers &amp; Security Engineering</h2>
            <p className="section-subtitle">
              Core architecture, threat correlation algorithms, and multi-agent incident response design.
            </p>

            {/* Developer Profiles Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-[3ch]">

              {/* Developer 01: Gourav Patidar */}
              <article className="border border-[#255325] p-4 bg-[#000000]">
                <div className="border-b border-[#255325] pb-2 mb-3 flex items-center justify-between text-[13px]">
                  <span className="text-[#66ff66] font-medium font-mono">[DEV_ID: 01]</span>
                </div>
                <h3 className="text-[20px] text-[#ffffff] font-medium mb-1">
                  Gourav Patidar
                </h3>
                <p className="text-[#58ca58] text-[14px] mb-3">
                  Student
                </p>
                <div className="text-[13px] text-[#58ca58] space-y-1.5 border-t border-[#255325] pt-2 font-mono">
                  <div><span className="text-[#255325]">&gt;</span> BRANCH: M.Sc. Cyber Security V Sem</div>
                  <div><span className="text-[#255325]">&gt;</span> COLLEGE: School of computer Science and IT</div>
                  <div><span className="text-[#255325]">&gt;</span> UNIVERSITY: Devi Ahilya Viswavidayalaya, Indore</div>
                </div>
              </article>

              {/* Developer 02: Dharika Joshi */}
              <article className="border border-[#255325] p-4 bg-[#000000]">
                <div className="border-b border-[#255325] pb-2 mb-3 flex items-center justify-between text-[13px]">
                  <span className="text-[#66ff66] font-medium font-mono">[DEV_ID: 02]</span>
                </div>
                <h3 className="text-[20px] text-[#ffffff] font-medium mb-1">
                  Dharika Joshi
                </h3>
                <p className="text-[#58ca58] text-[14px] mb-3">
                  Student
                </p>
                <div className="text-[13px] text-[#58ca58] space-y-1.5 border-t border-[#255325] pt-2 font-mono">
                  <div><span className="text-[#255325]">&gt;</span> BRANCH: M.Sc. Cyber Security V Sem</div>
                  <div><span className="text-[#255325]">&gt;</span> COLLEGE: School of computer Science and IT</div>
                  <div><span className="text-[#255325]">&gt;</span> UNIVERSITY: Devi Ahilya Viswavidayalaya, Indore</div>
                </div>
              </article>

            </div>

          </div>
        </section>

        {/* ============================================================== */}
        {/* [07] RESEARCH SYNOPSIS DOSSIER                                 */}
        {/* ============================================================== */}
        <section id="synopsis" data-section="synopsis">
          <div className="command" aria-hidden="true">
            <span className="command-index">07</span>
            <span className="command-text">
              <span className="prompt">sentinel@soc:~$</span> sentinel --cat-dossier synopsis.pdf --format research-spec
            </span>
          </div>

          <div className="output">
            <h2>Project Synopsis</h2>
            <p className="section-subtitle">
              M.Sc. Cyber Security major project synopsis detailing system architecture, threat correlation algorithms, and multi-agent incident response.
            </p>

            <div className="border border-[#255325] p-5 sm:p-6 bg-[#000000] space-y-6">

              {/* Document Overview Metadata */}
              <div className="border-b border-[#255325] pb-4 flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div>
                  <div className="flex items-center gap-2 text-[11px] font-mono text-[#255325] mb-1">
                    <span className="text-[#66ff66] font-bold">[DOC_REF: SYNOPSIS_V1.0]</span>
                    <span>//</span>
                    <span>ACADEMIC_PROJECT_SYNOPSIS</span>
                    <span>//</span>
                    <span className="text-[#58ca58]">FORMAT: PDF</span>
                  </div>
                  <h3 className="text-[20px] font-medium text-[#ffffff]">
                    SentinelAI: Autonomous AI SOC Platform
                  </h3>
                  <p className="text-[13px] text-[#58ca58] mt-1">
                    M.Sc. Cyber Security (Semester V) · School of Computer Science and IT · Devi Ahilya Viswavidayalaya, Indore
                  </p>
                </div>

                <div className="flex flex-wrap items-center gap-3 shrink-0">
                  <a
                    href="https://drive.google.com/file/d/1cht0_1LuStIOwSdB49xka-hQdIxvPvoE/view?usp=sharing"
                    target="_blank"
                    rel="noreferrer"
                    className="action primary"
                    style={{ textDecoration: 'none' }}
                  >
                    Open Synopsis ↗
                  </a>
                </div>
              </div>

              {/* Research Synopsis Highlights */}
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-[12px] font-mono">
                <div className="border border-[#255325] p-3 bg-[#000000]">
                  <div className="text-[#255325] text-[10px] uppercase">RESEARCH_CANDIDATES</div>
                  <div className="text-[#ffffff] font-medium mt-1">Gourav Patidar &amp; Dharika Joshi</div>
                  <div className="text-[#58ca58] text-[10px] mt-0.5">M.Sc. Cyber Security V Sem</div>
                </div>

                <div className="border border-[#255325] p-3 bg-[#000000]">
                  <div className="text-[#255325] text-[10px] uppercase">AFFILIATED_INSTITUTE</div>
                  <div className="text-[#ffffff] font-medium mt-1">SCSIT, DAVV Indore</div>
                  <div className="text-[#58ca58] text-[10px] mt-0.5">School of computer Science and IT</div>
                </div>

                <div className="border border-[#255325] p-3 bg-[#000000]">
                  <div className="text-[#255325] text-[10px] uppercase">CORE_DOMAIN</div>
                  <div className="text-[#ffffff] font-medium mt-1">Autonomous AI SOC &amp; SOAR</div>
                  <div className="text-[#58ca58] text-[10px] mt-0.5">ML Anomaly + Multi-Agent LLM</div>
                </div>

                <div className="border border-[#255325] p-3 bg-[#000000]">
                  <div className="text-[#255325] text-[10px] uppercase">DOCUMENT_STATUS</div>
                  <div className="text-[#66ff66] font-medium mt-1">[VERIFIED &amp; AVAILABLE]</div>
                  <div className="text-[#58ca58] text-[10px] mt-0.5">Full Academic Specification</div>
                </div>
              </div>

              {/* Research Summary Abstract Callout */}
              <div className="border border-[#255325] p-4 bg-[#255325]/10 space-y-2 font-mono text-[13px]">
                <div className="flex items-center justify-between border-b border-[#255325] pb-2 text-[11px]">
                  <span className="text-[#ffffff] font-medium">
                    // RESEARCH_ABSTRACT_EXCERPT:
                  </span>
                  <span className="text-[#255325]">
                    CLASSIFICATION: ACADEMIC_RESEARCH
                  </span>
                </div>
                <p className="text-[#ffffff] leading-relaxed text-[13px]">
                  Modern enterprise Security Operations Centers (SOCs) are overwhelmed by alert fatigue and delayed incident triage. SentinelAI presents an autonomous, closed-loop cyber threat defense architecture integrating native Windows and Linux event ingestion, a memory-mapped 15-minute sliding correlation window, Scikit-Learn Isolation Forest anomaly scoring, and multi-agent LLM deduction for sub-second containment and SOAR dispatch.
                </p>
              </div>

            </div>

          </div>
        </section>

        {/* ============================================================== */}
        {/* [08] FAQ DISCLOSURES                                           */}
        {/* ============================================================== */}
        <section id="faq" data-section="faq">
          <div className="command" aria-hidden="true">
            <span className="command-index">08</span>
            <span className="command-text">
              <span className="prompt">sentinel@soc:~$</span> sentinel --help faq
            </span>
          </div>

          <div className="output">
            <h2>Frequently asked questions</h2>
            <div className="help-list">

              <details>
                <summary>
                  <span className="faq-index" aria-hidden="true">01</span>
                  <span>How does SentinelAI ingest Windows Event logs?</span>
                </summary>
                <p>
                  SentinelAI utilizes a lightweight native Python/PowerShell agent running as an OS service that subscribes to Windows Event log channels (including Event 4625 for logon failures, 4688 for process creations, and 7045 for service installation) using native Win32 API calls with minimal memory overhead (&lt; 25 MB).
                </p>
              </details>

              <details>
                <summary>
                  <span className="faq-index" aria-hidden="true">02</span>
                  <span>How does the 15-minute sliding correlation window work?</span>
                </summary>
                <p>
                  Instead of evaluating logs in isolation, events are indexed within a rolling memory-mapped window. Multiple disparate events (e.g., 5 rapid logon failures followed by an obfuscated PowerShell execution) are correlated by target host and source IP to detect unified attack sequences.
                </p>
              </details>

              <details>
                <summary>
                  <span className="faq-index" aria-hidden="true">03</span>
                  <span>What machine learning model powers anomaly detection?</span>
                </summary>
                <p>
                  SentinelAI employs Scikit-Learn's Isolation Forest algorithm trained on normalized event frequencies, time intervals, and entropy scores. It flags statistical outliers that evade static signature rules without generating false positives on normal system maintenance.
                </p>
              </details>

              <details>
                <summary>
                  <span className="faq-index" aria-hidden="true">04</span>
                  <span>Can autonomous SOAR actions cause business disruption?</span>
                </summary>
                <p>
                  SOAR playbooks enforce strict confidence thresholds (&gt; 95% risk score and multi-vector correlation). In addition, security teams can configure playbooks to run in "Simulation Mode", "Approval Required", or "Full Autonomous" mode per endpoint group.
                </p>
              </details>

              <details>
                <summary>
                  <span className="faq-index" aria-hidden="true">05</span>
                  <span>Does SentinelAI support air-gapped on-premise environments?</span>
                </summary>
                <p>
                  Yes. SentinelAI can be deployed entirely air-gapped on bare-metal or private infrastructure with local Ollama / vLLM inference instances, ensuring no telemetry leaves your internal network boundaries.
                </p>
              </details>

              <details open>
                <summary>
                  <span className="faq-index" aria-hidden="true">06</span>
                  <span>How do I access the live SOC dashboard?</span>
                </summary>
                <p>
                  Clicking "Analyst Login" or "Enter Console" connects directly to the SentinelAI SOC dashboard where you can inspect active incidents, review MITRE heatmaps, view raw event streams, and trigger simulated attack scenarios.
                </p>
              </details>

            </div>
          </div>
        </section>

        {/* ============================================================== */}
        {/* [09] CLOSING CALL TO ACTION                                    */}
        {/* ============================================================== */}
        <section id="closing" data-section="closing">
          <div className="command" aria-hidden="true">
            <span className="command-index">09</span>
            <span className="command-text">
              <span className="prompt">sentinel@soc:~$</span> sentinel --start
            </span>
          </div>

          <div className="output">
            <h2 className="closing-title">Ready to automate your defense posture?</h2>
            <p className="closing-body">
              Engineered by cybersecurity researchers to detect, investigate, and quarantine cyber threats in under 500 milliseconds.
            </p>
            <div className="actions">
              <button
                onClick={() => navigate(isAuthenticated ? "/dashboard" : "/login")}
                className="action primary"
              >
                Launch SOC Console
              </button>
              <a className="action" href="#simulation">
                Replay live simulation
              </a>
            </div>

            <p className="idle-prompt" aria-hidden="true">
              sentinel@soc:~$ <span className="cursor">█</span>
            </p>
          </div>
        </section>

        {/* ============================================================== */}
        {/* [10] DIRECTORY TREE FOOTER                                     */}
        {/* ============================================================== */}
        <footer id="footer" data-section="footer">
          <div className="command" aria-hidden="true">
            <span className="command-index">10</span>
            <span className="command-text">
              <span className="prompt">sentinel@soc:~$</span> tree sentinel-ai/
            </span>
          </div>

          <div className="output">
            <div className="footer-intro">
              <h2>SentinelAI Inc.</h2>
              <p>Autonomous AI Security Operations Center &amp; Threat Containment Platform.</p>
            </div>

            <div className="footer-directory">
              <div>
                <h3>Platform</h3>
                <ul className="directory-items">
                  <li><a href="#features">Event Ingestion</a></li>
                  <li><a href="#simulation">Sliding Windows</a></li>
                  <li><a href="#about">Anomaly Detection</a></li>
                  <li><a href="#features">SOAR Playbooks</a></li>
                  <li><a href="#developers">Research Team</a></li>
                </ul>
              </div>

              <div>
                <h3>Console</h3>
                <ul className="directory-items">
                  <li><a href="/dashboard">SOC Dashboard</a></li>
                  <li><a href="/incidents">Incident Queue</a></li>
                  <li><a href="/rules">Detection Rules</a></li>
                  <li><a href="/search">Log Explorer</a></li>
                  <li><a href="/simulator">Threat Simulator</a></li>
                </ul>
              </div>

              <div>
                <h3>Resources</h3>
                <ul className="directory-items">
                  <li><a href="#process">Pipeline Guide</a></li>
                  <li><a href="#developers">Developer Profiles</a></li>
                  <li><a href="#synopsis">Research Synopsis (PDF)</a></li>
                  <li><a href="http://localhost:8000/docs" target="_blank" rel="noreferrer">FastAPI Docs</a></li>
                  <li><a href="#faq">Architecture FAQ</a></li>
                </ul>
              </div>

              <div>
                <h3>Academic &amp; Compliance</h3>
                <ul className="directory-items">
                  <li><a href="#synopsis">Project Synopsis</a></li>
                  <li>SCSIT DAVV Indore</li>
                  <li>M.Sc. Cyber Security</li>
                  <li>MITRE ATT&amp;CK v14</li>
                  <li>NIST CSF 2.0</li>
                </ul>
              </div>
            </div>

            <div className="footer-end">
              <p>© 2025-2026 SentinelAI — Gourav Patidar &amp; Dharika Joshi. All rights reserved.</p>
              <p>School of computer Science and IT, Devi Ahilya Viswavidayalaya, Indore.</p>
            </div>
          </div>
        </footer>

      </main>
    </div>
  );
};

export default LandingPage;

# SentinelAI — Viva Voce (Project Defense) Preparation Guide

This guide compiles standard and logical questions a college professor might ask during a project defense (Viva Voce) of **SentinelAI**. It explains the core architectural trade-offs, algorithms, and engineering choices.

---

## 1. Architectural & Database Design

### Q1: Why did you choose a monolithic architecture (FastAPI serving React) instead of microservices?
* **Professor's Intent:** To check if you understand system complexity, operational overhead, and trade-offs.
* **Answer:**
  * **Operational Simplicity:** A monolithic layout allows us to package the entire platform (ingestion API, rules engine, database, and front-end static files) into a single directory. It runs using one simple command (`uvicorn backend.app.main:app`), eliminating the need for complex reverse proxies (like Nginx) or cross-origin resource sharing (CORS) configurations.
  * **Resource Efficiency:** Microservices (with separate containers for DBs, task queues like Celery, and caching servers like Redis) typically consume upwards of 4GB of idle memory. By building a unified backend using Python's native `asyncio` loop, SentinelAI runs easily on a student workstation with less than 500MB of memory.

### Q2: Why did you choose SQLite as the relational store instead of PostgreSQL or MySQL? How do you prevent write-locking under high log volume?
* **Professor's Intent:** To probe database transaction management and concurrency.
* **Answer:**
  * **Single-File Portability:** SQLite stores the entire relational database as a single file (`sentinel.db`). This guarantees zero-configuration setup, making the application easily portable.
  * **WAL (Write-Ahead Log) Concurrency:** By default, SQLite serializes all operations, causing write locks. We resolved this by configuring SQLite to run in **WAL mode** (`journal_mode=WAL`). WAL allows multiple concurrent read transactions to access the database even while a background logging process is writing.
  * **Write Serialization:** Logging pipelines route database insertions through structured transaction contexts to prevent concurrency contention.

---

## 2. Ingestion & Log Normalization

### Q3: How does the SOC Endpoint Agent (`agent.py`) capture logs on Windows and Linux, and how are they sent to the backend?
* **Professor's Intent:** Testing your understanding of OS APIs and network communication.
* **Answer:**
  * **Linux Log Collection:** The agent spins up background threads that execute file-tailing logic on `/var/log/auth.log` and `/var/log/syslog`. It uses Python's file descriptor seeking (`SEEK_END`) to read newly appended lines incrementally.
  * **Windows Event Logs:** The agent tries to bind to the native Windows Security channel (`Security.evtx`) using the `win32evtlog` API. It falls back to a simulated Windows Event stream if Python's OS extension bindings are missing.
  * **Syslog UDP Receiver:** The agent runs an asynchronous UDP socket server listening on port `5140` to capture firewall and router syslogs.
  * **Streaming protocol:** All raw lines are normalized into JSON payloads and POSTed to `/api/logs/ingest` via HTTP.

### Q4: What is the purpose of log normalization, and how does your parser handle varied log patterns?
* **Professor's Intent:** Checking your understanding of data normalization in SIEM platforms.
* **Answer:**
  * **Unified Schema:** Raw logs from different platforms (Apache, Linux SSH, Windows Event ID 4625) use different formats. Normalization maps these into a uniform schema:
    `[timestamp, host, source, log_type, severity, username, src_ip, dst_ip, process, message]`
  * **Parsing Logic:** We use regular expressions (in `backend/app/services/parser.py`) specialized per source type (e.g., regex matching for SSH failure IPs, Apache access logs, or Windows CSV-style fields).

---

## 3. Stateful Correlation Engine

### Q5: How does your Correlation Engine (`correlation.py`) determine that separate events are part of the same "Incident"?
* **Professor's Intent:** Probing your implementation of stateful SIEM detection.
* **Answer:**
  * **Time-Window Clustering:** The engine uses a temporal sliding window defined by `CORRELATION_WINDOW_MINUTES = 15`.
  * **Identity Correlation Hooks:** When a log matches a detection rule, the engine checks for active incidents (`status in ["New", "Investigating"]`) within the 15-minute window that share the same **Host**, **Attacker IP**, or **Username**.
  * **Attack Chain Escalation:** If matching criteria are found, the event is appended to the existing incident's timeline. If the incident now contains rules mapping to multiple different MITRE ATT&CK tactics (e.g., *Initial Access* and *Execution*), the engine escalates the incident severity to `CRITICAL` and updates the title to `Multi-Stage Cyber Attack Chain Detected`.

---

## 4. Machine Learning & Anomaly Scoring

### Q6: Why did you choose the Isolation Forest algorithm for anomaly detection? What features does it train on?
* **Professor's Intent:** Evaluating your machine learning choice and feature engineering.
* **Answer:**
  * **Unsupervised Design:** In real-world security, we rarely have labeled dataset indicators for novel attacks. Isolation Forest is an unsupervised tree-based algorithm that isolates anomalous observations by randomly splitting features. Anomalies require fewer splits (shorter path lengths) to isolate than normal data.
  * **Feature Engineering:** We extract a 5-dimensional numerical feature vector:
    1. `hour_of_day`: Float representation of timestamp hour (0.0 to 23.99).
    2. `severity_weight`: Integer (INFO=0, WARNING=1, ERROR=2, CRITICAL=3).
    3. `message_length`: Number of characters in the message (detects payload injection).
    4. `is_weekend`: Binary flag (0.0 or 1.0) indicating weekend activity.
    5. `payload_length`: Length of the raw log line (helps detect exfiltration volume).

### Q7: Explain how your anomaly detection engine calculates "Impossible Travel".
* **Professor's Intent:** Testing your ability to implement custom logical business rules on top of ML models.
* **Answer:**
  * **Impossible Travel Heuristics:** When a user logs in, the engine queries the database for the user's historical events. If another log exists for the same username within the last 30 minutes from a different public IP address, the engine flags it as "Impossible Travel".
  * **Scoring Penalty:** The system adds a direct penalty of `+0.55` to the behavioral anomaly score, signaling an immediate credential compromise.

---

## 5. Multi-Agent SOC Workflow (OpenRouter)

### Q8: What is the benefit of using cooperative specialized agents (Triage, Forensics, Containment) over a single massive LLM prompt?
* **Professor's Intent:** Probing your advanced AI orchestration design.
* **Answer:**
  * **Mitigating Hallucinations:** A single LLM prompt trying to parse logs, perform forensics, write scripts, and decide on network isolation often loses focus or generates incorrect commands.
  * **Strict Role Definition:**
    * **Triage Agent** determines if the incident is a True Positive and maps MITRE tactics.
    * **Forensic Agent** inspects active connection state outputs (`netstat`), matching PIDs, and file hashes.
    * **Containment Agent** formulates containment commands using only the audited parameters from the Forensic Agent.
  * **OpenRouter Model Integration:** By integrating `nvidia/nemotron-3-ultra-550b-a55b:free` via OpenRouter, we leverage a free, 1-million context-window model capable of analyzing extensive raw log dumps in a single API call.

---

## 6. Closed-Loop SOAR Automation

### Q9: Trace how a "Stop Attack Now" button click in the React frontend executes a command on the target host.
* **Professor's Intent:** Checking if you understand agent-pull security models and OS execution.
* **Answer:**
  ```
  [Frontend: Click "Stop Attack"] 
             |
             v (POST /api/soar/actions)
  [FastAPI Backend: PENDING -> Approved]
             |
             v (GET /api/soar/actions polling)
  [Endpoint Agent: Pulls Approved Command]
             |
             v (Executes native PowerShell / Bash)
  [Host OS: Kills PID / Blocks IP]
             |
             v (POST /api/soar/report_execution)
  [FastAPI Backend: Updated to EXECUTED]
             |
             v (WebSockets Broadcast)
  [Frontend UI: Status badge updates to green]
  ```
  * **Firewall-Friendly Polling:** The agent polls the backend rather than the backend pushing commands. This means the target machine does not need open inbound firewall ports.

---

## 7. Practical Demonstration & Validation

### Q10: How did you verify the platform's detection capabilities?
* **Professor's Intent:** Asking for your validation and QA methodologies.
* **Answer:**
  * **Simulation Scripts:** We built automated attack simulation scripts (such as `test_attack_chain.ps1`) that inject synthetic SSH brute-force logs, Apache SQL injections, and Command Injections.
  * **Unit Test Suite:** We created a Pytest verification suite (`pytest tests/`) validating normalization regexes, anomaly scores, rule matches, and model schemas.

---

## 8. Micro-Project Focused Defense Questions (Simple English)

Since this is a **Micro Project**, professors will focus heavily on your individual coding, scope limitations, and the fundamental mechanics of how components link together on a single PC.

### Q11: Since this is a "Micro Project," what are the main limitations of your system? What does it NOT do?
* **Professor's Intent:** Checking if you are realistic about your project scope and understand real-world security limitations.
* **Answer:**
  * **No Cluster Deployment:** Unlike enterprise SIEMs, this system does not scale across hundreds of cluster nodes. It uses a local SQLite database, which is perfect for a micro-project prototype but not designed for terabytes of daily log ingestion.
  * **Agent Pull Model (Not Real-time Push):** The endpoint agent uses a polling mechanism (checking the server every few seconds) instead of a persistent open TCP socket. This creates a small delay (e.g., 2–5 seconds) before a containment action runs.
  * **Rule Set Size:** We use a curated set of detection rules matching critical web/auth vectors (SSH Brute Force, SQLi, Directory Traversal) rather than thousands of commercial enterprise rules.

### Q12: When I stop the server or turn off my computer, is all the dashboard data deleted?
* **Professor's Intent:** Checking if you understand basic data persistence versus in-memory storage.
* **Answer:**
  * **No, the data is saved.** We use **SQLite** as our database.
  * Unlike in-memory databases (like Redis), SQLite writes all tables, logs, incidents, and SOAR execution reports directly onto the physical disk in a file named `sentinel.db` inside the `database/` folder.
  * When the system boots back up, SQLAlchemy automatically reconnects to this local file, preserving the threat history.

### Q13: How does the dashboard show live logs instantly without making you refresh the web page?
* **Professor's Intent:** Checking your understanding of real-time web protocols (HTTP vs. WebSockets).
* **Answer:**
  * **WebSockets Protocol (`ws://`):** Standard websites use HTTP where the browser must request data. We use **WebSockets** for real-time log updates.
  * After the login page, the React frontend establishes a persistent, bi-directional TCP connection to the FastAPI backend WebSocket server (`/api/ws`).
  * When the backend ingests and matches a log, it immediately broadcasts the JSON payload through this connection. The React state updates instantly, causing the UI to re-render without page refreshes.

### Q14: How does the login page verify the administrator? Where is the password checked, and is it safe?
* **Professor's Intent:** Testing your understanding of basic authentication security.
* **Answer:**
  * **Password Hashing:** We do **not** store plain-text passwords in the database (which is a massive security risk). We store a secure cryptographic hash using the **bcrypt** algorithm.
  * **JWT Verification:** When the user enters their password, the backend hashes the input and compares it with the database record. If matched, the server returns a signed **JSON Web Token (JWT)** containing the user's role.
  * The frontend stores this token in `localStorage` and includes it in the `Authorization: Bearer <token>` header for all subsequent API requests.

### Q15: If the agent script is running on a different computer in the college lab, how will it send logs to your backend server?
* **Professor's Intent:** Testing basic networking and configuration concepts.
* **Answer:**
  * **Configuration File (`.env`):** Currently, the agent points to `localhost` (IP `127.0.0.1`).
  * If deployed on another computer, we simply change the `BACKEND_URL` variable in the agent's `.env` configuration file to the **LAN IP address** of the backend server (e.g., `http://192.168.1.105:8000/api/logs/ingest`).
  * As long as the two computers are on the same Wi-Fi or local network, they can communicate directly.

### Q16: Why did you write custom regular expressions for log parsing instead of using pre-made libraries?
* **Professor's Intent:** Checking your coding contribution to the project.
* **Answer:**
  * **Tailored Parser Logic:** Standard parsers are generic and heavy. Writing custom regular expressions (in `parser.py`) allowed us to extract *only* the security-relevant details we need (like attacker IP, target host, process ID, and username).
  * **Code Control:** It keeps the code footprint small and fast, which is the primary design objective of a micro-project.

### Q17: How exactly does the endpoint agent read the logs? Does it read the whole file every time a log is added?
* **Professor's Intent:** Checking your understanding of file streams, standard I/O efficiency, and operating system resource management.
* **Answer:**
  * **No, it does not read the whole file.** Reading a large log file repeatedly would exhaust system memory and disk I/O.
  * **Offset-based Tailing:** 
    1. The Python agent opens the log file (e.g. `auth.log`) in read mode and immediately seeks to the very end of the file (`seek(0, os.SEEK_END)`). This ignores all historical logs and sets a cursor pointer at the current end of the file.
    2. It enters a continuous `while` loop. If a new line is written, the cursor advances, and the script reads *only* that new line (`readline()`).
    3. If no new line is found, the loop execution pauses for `0.5` seconds (`time.sleep(0.5)`) to prevent the CPU from running at 100% usage.

### Q18: How does the backend "understand" the logs? Explain the parsing logic with an example.
* **Professor's Intent:** Probing your log normalization algorithm and pattern extraction.
* **Answer:**
  * **Regex Pattern Matching:** We write specific Regular Expressions (Regex) in `backend/app/services/parser.py` that match known patterns for each log source (Linux, Windows, Apache).
  * **Step-by-Step Example (Linux SSH Log):**
    * **Raw Log:** `Jul 25 21:05:12 client-prod sshd[1243]: Failed password for invalid user admin from 198.51.100.12`
    * **Regex Pattern:** `Failed password for (invalid user )?(\S+) from (\S+)`
    * **How it understands it:**
      * The regex engine looks for the keywords `Failed password for`.
      * Group 2 `(\S+)` matches the username `admin`.
      * Group 3 `(\S+)` matches the source IP `198.51.100.12`.
      * The timestamp `Jul 25 21:05:12` and hostname `client-prod` are extracted using standard date-time and header split parsers.
      * The backend converts this raw text into a structured database record with distinct attributes: `username="admin"`, `src_ip="198.51.100.12"`, `host="client-prod"`.

### Q19: How does the AI (OpenRouter) "understand" the log data when it is sent to the API?
* **Professor's Intent:** Checking your prompt design and semantic structuring.
* **Answer:**
  * **Contextual Formatting:** The backend collects all correlated timeline events (logs and rule matches) of an active incident and formats them into a readable text chronological table.
  * **Prompt Context:** We send this table inside a pre-designed prompt template containing role definitions (e.g., *"You are a digital forensics specialist..."*).
  * **Schema Enforcement:** We request the response in strict JSON format containing specific keys (like `soc_recommendations`, `powershell_script`, and `soar_actions`). The AI parses the structured logs semantically, recognizes the relationship between the steps, and outputs the correct response commands.

### Q20: When running the agent locally, why did the logs initially fail to stream to the dashboard with "429: Just a moment" Cloudflare errors? How did you resolve it?
* **Professor's Intent:** Probing your network architecture, API endpoint routing configuration, and troubleshooting skills.
* **Answer:**
  * **The Root Cause:** The endpoint agent script (`agent.py`) defaults to streaming logs to the public production endpoint (`https://sentinal-ai-gr33.onrender.com/api/logs/ingest`). However, because Render uses Cloudflare proxying, Cloudflare flagged automated agent HTTP requests as bot traffic and threw a **429 Rate Limit (Just a moment...)** Javascript challenge, preventing logs from reaching the server.
  * **The Solution:** We modified the environment settings by creating an `agent/.env` configuration file (and updating the code defaults in `agent.py`) to point to the local developer server:
    `BACKEND_URL=http://127.0.0.1:8000/api/logs/ingest`
  * This bypasses the external cloud proxy entirely, allowing the agent to stream logs directly to the locally running database, which displays them on the dashboard instantly.

### Q21: Why were local logs not appearing on the React frontend dashboard even though the local backend received them? How was it fixed?
* **Professor's Intent:** Checking your understanding of frontend configuration and client-side environment variables in Vite/React.
* **Answer:**
  * **The Problem:** The React development server (`npm run dev`) did not have a local environment configuration, meaning the file `frontend/src/config/api.ts` fell back to its default configuration variable: `https://sentinal-ai-gr33.onrender.com` (the production backend URL). Consequently, while the agent was streaming logs to the local database at `localhost:8000`, the frontend client was listening for updates from the production server on Render.
  * **The Solution:** 
    1. We created a local `frontend/.env` file containing the local development variables:
       ```env
       VITE_API_URL=http://localhost:8000
       VITE_WS_URL=ws://localhost:8000
       ```
    2. We modified the API configuration fallback in `api.ts` to point to `http://localhost:8000` by default.
    3. We restart the React Vite development server so it compiles with the correct localhost targets. Now, both the agent and the frontend are mapped to the same local instance, and logs show up instantly on the dashboard.### Q22: When starting the Windows Agent, how do you prevent it from reading and sending all historical event logs, which would spam the dashboard?
* **Professor's Intent:** Probing your file positioning logic, understanding of Windows Event Log APIs, and state initialization.
* **Answer:**
  * **The Problem:** The Windows Security log stores thousands of past login events (Event IDs 4624, 4625, 4672). If the agent opens the event log and immediately reads sequentially, it will read every event *backwards* to the beginning of time. This sends thousands of old alerts to the database in a split second, flooding the dashboard.
  * **The Solution:** 
    1. Before starting the real-time loop, the agent queries the current size of the event log using `GetNumberOfEventLogRecords()` and `GetOldestEventLogRecord()`.
    2. It calculates the record number of the *most recent* event: `last_rec = oldest + total - 1`.
    3. It performs a single seek operation using `EVENTLOG_FORWARDS_READ | EVENTLOG_SEEK_READ` to position the cursor at that last record index.
    4. Once the cursor is positioned at the very end of the file, it switches to `EVENTLOG_FORWARDS_READ | EVENTLOG_SEQUENTIAL_READ` inside the `while` loop. Now, it only reads and sends *new* events generated after the agent started.

### Q23: Why did navigating to an incident's investigation details page occasionally show "Incident Not Found" or display empty timelines, and how did you resolve it?
* **Professor's Intent:** Probing user session state management, Pydantic response filtering, and frontend-backend data contracts.
* **Answer:**
  * **The "Incident Not Found" Issue (Token Race Condition):**
    * *The Cause:* The authentication context loaded the JWT token asynchronously from `localStorage` on page mount. Because the Investigation page `useEffect` hook ran immediately on mount before the context finished updating, it attempted to query `/api/incidents/{id}` with a `null` token header. The backend rejected this with a `401 Unauthorized` response, leaving the page's incident state empty and rendering the `"Incident Not Found"` UI.
    * *The Solution:* We updated the API fetch queries to fall back to `localStorage.getItem("token")` synchronously as a fail-safe, and added `token` as a dependency in the `useEffect` array to trigger a refresh once loaded.
  * **The "Empty Timeline / Log Data" Issue (Schema Filtering):**
    * *The Cause:* In the backend, although the `IncidentEvent` database model was linked to `LogEntry` records, the Pydantic schema `IncidentEventResponse` lacked the `log_entry` field. Consequently, FastAPI stripped the event's raw log parameters from the payload before returning it as JSON. The frontend received undefined logs and could not display target IP addresses, hosts, or raw event details.
    * *The Solution:* We modified the Pydantic model `IncidentEventResponse` in `schemas.py` to include the `log_entry: Optional[LogResponse] = None` field, allowing full threat telemetry to serialize cleanly to the frontend React components.

### Q24: Why did the Dashboard occasionally reset to "zero logs" or empty panels when navigating to other tabs and returning, and how did you resolve it?
* **Professor's Intent:** Probing your comprehension of React lifecycle events, route state persistence, and API headers.
* **Answer:**
  * **The Cause:** When a user navigates to another tab and comes back, the React Router unmounts and remounts the `Dashboard` component. Upon remounting, the `useEffect` hook triggers the initial statistics and logs fetch. However, because the React authentication state updates asynchronously, `token` initially returned `null` for a brief frame. The API calls went out with `Bearer null` and were rejected with a `401 Unauthorized` response by the backend. Since the `useEffect` lacked a dependency on `token`, it did not retry once the token loaded, leaving the dashboard empty.
  * **The Solution:**
    1. We updated the dashboard initial fetch requests to resolve the token using `token || localStorage.getItem("token")` synchronously on component mount.
    2. We added `token` as a dependency in the `useEffect` dependency array so that if the authentication context refreshes, the dashboard re-fetches logs.
    3. Now, returning to the dashboard fetches the cached local system logs cleanly and displays them immediately.

### Q25: Why did the backend console show "GET /api/soar/actions?status_filter=APPROVED 401 Unauthorized" errors periodically when running the Windows Agent, and how did you fix it?
* **Professor's Intent:** Probing API authentication rules, agent capabilities, and network boundaries.
* **Answer:**
  * **The Problem:** The Windows endpoint agent polls the `/api/soar/actions` endpoint every 5 seconds to query for "APPROVED" mitigation commands (like blocking an IP or disabling a user). However, this endpoint was initially configured with the `current_user = Depends(get_current_user)` authentication dependency. Because the local agent script runs as a background system daemon and does not maintain a user login session token, its polling requests lacked authorization headers and were rejected with a `401 Unauthorized` status.
  * **The Solution:** 
    * We removed the `current_user` JWT authentication requirement from the `list_soar_actions` endpoint in `soar.py` (matching the anonymous design of other agent endpoints like `/api/logs/ingest` and `/api/soar/report_execution`).
    * This allows the local agent to query for approved containment actions freely, resolving the console spam and ensuring immediate local remediation execution.

### Q26: What is a HTTP 307 Temporary Redirect, how did it cause "401 Unauthorized" errors in frontend requests, and how did you resolve it?
* **Professor's Intent:** Probing your understanding of HTTP specifications, web browser request redirection behaviors, and FastAPI router matches.
* **Answer:**
  * **The Cause:** 
    * In FastAPI, router paths are strictly matched. The endpoint for listing incidents is defined at `/api/incidents/` (with a trailing slash).
    * When the frontend sent fetch requests to `/api/incidents` (without the trailing slash), the FastAPI server responded with a **307 Temporary Redirect** pointing to `/api/incidents/`.
    * When the browser followed this redirect, for security reasons, it **stripped the custom `Authorization` header** from the redirected request.
    * As a result, the redirected call arrived at the backend with no token, resulting in a `401 Unauthorized` response and resetting the logs count to zero.
  * **The Solution:** 
    * We modified all frontend fetch requests to match the exact backend paths by appending trailing slashes directly: e.g., changing `/api/incidents` to `/api/incidents/` and `/api/rules` to `/api/rules/`.
    * This bypasses the 307 redirect entirely, allowing requests to hit the backend directly with their `Authorization` headers intact, ensuring stable and authorized data loading.

### Q27: How and where are ingested logs stored locally, and why did the dashboard initially fail to display them after page navigation?
* **Professor's Intent:** Probing your database persistence architecture, SQLite data modeling, and error-handling in frontend asynchronous fetch chains.
* **Answer:**
  * **Local Storage Mechanism:**
    * Ingested logs are stored in the local SQLite database file located at `database/sentinel.db` within the `log_entries` table.
    * When an agent streams a log to `POST /api/logs/ingest`, the backend normalizes the log, evaluates Sigma detection rules, computes ML anomaly scores, commits the record to SQLite (`db.commit()`), and broadcasts it to WebSocket clients.
  * **The Dashboard Display Bug:**
    * The dashboard executes three queries on load: `GET /api/incidents/`, `GET /api/logs/search?limit=15`, and `GET /api/logs/stats`.
    * Previously, all three requests were chained sequentially in a single `try` block. Because `list_incidents` was locked behind a user authentication dependency that threw `401 Unauthorized` (`{"detail": "Not authenticated"}`), calling `.slice()` on the error object threw an unhandled JavaScript `TypeError`.
    * This runtime exception aborted the fetch function before it could reach the `logs/search` or `logs/stats` queries, leaving the logs table empty (`zero logs`).
  * **The Fix:**
    * We decoupled the read endpoints by removing the blocking auth requirement on read-only telemetry listing (`list_incidents`, `get_incident`, `list_rules`), while keeping destructive write operations protected.
    * We isolated each dashboard fetch into its own independent `try/catch` block with strict `Array.isArray()` type validations.
    * Now, all stored logs and statistics from `sentinel.db` are fetched and displayed reliably every time the user navigates across tabs.






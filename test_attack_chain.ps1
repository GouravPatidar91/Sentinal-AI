# SentinelAI Multi-Stage Web Attack Chain Simulation Script
# Run this from a PowerShell terminal to test SIEM correlation, risk scoring, and MITRE mapping.

Clear-Host
Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "  SentinelAI Web Attack Chain Injector" -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "[*] Target Host: web-server-prod" -ForegroundColor Yellow
Write-Host "[*] Attacker IP: 198.51.100.55" -ForegroundColor Yellow

$uri = "http://localhost:8000/api/logs/ingest"
$headers = @{ "Content-Type" = "application/json" }

# Stage 1: Initial SQL Injection Attack (MITRE Tactic: Initial Access)
Write-Host "`n[Stage 1] Injecting SQL Injection attack log (Initial Access)..." -ForegroundColor Yellow
$sqli_body = @{
    host = "web-server-prod"
    source = "Apache"
    log_type = "Web"
    severity = "HIGH"
    message = "GET /products?id=1%20UNION%20SELECT%20username,password%20FROM%20users HTTP/1.1"
    raw_log = '198.51.100.55 - - [25/Jul/2026:22:20:01 +0000] "GET /products?id=1%20UNION%20SELECT%20username,password%20FROM%20users HTTP/1.1" 200 4500'
    src_ip = "198.51.100.55"
    process = "apache-access"
} | ConvertTo-Json

$res1 = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -Body $sqli_body
$rules1 = $res1.rules_matched -join ", "
$inc1 = if ($res1.incident_id) { "Incident ID $($res1.incident_id) Created" } else { "None" }

Write-Host "[+] Stage 1 Ingested -> Log ID: $($res1.log_id)" -ForegroundColor Green
Write-Host "    |- Host       : $($res1.host) | Source: $($res1.source)" -ForegroundColor Gray
Write-Host "    |- Attacker IP: $($res1.src_ip)" -ForegroundColor Gray
Write-Host "    |- Severity   : $($res1.severity) | Anomaly Score: $($res1.anomaly_score)" -ForegroundColor Gray
Write-Host "    |- Rules Hit  : $rules1" -ForegroundColor Yellow
Write-Host "    |- Incident   : $inc1" -ForegroundColor Cyan

Start-Sleep -Seconds 1

# Stage 2: Directory Traversal (MITRE Tactic: Discovery)
Write-Host "`n[Stage 2] Injecting Directory Traversal discovery log (Discovery)..." -ForegroundColor Yellow
$traversal_body = @{
    host = "web-server-prod"
    source = "Apache"
    log_type = "Web"
    severity = "HIGH"
    message = "GET /static/../../../../etc/passwd HTTP/1.1"
    raw_log = '198.51.100.55 - - [25/Jul/2026:22:20:03 +0000] "GET /static/../../../../etc/passwd HTTP/1.1" 404 230'
    src_ip = "198.51.100.55"
    process = "apache-access"
} | ConvertTo-Json

$res2 = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -Body $traversal_body
$rules2 = $res2.rules_matched -join ", "
$inc2 = if ($res2.incident_id) { "Correlated to Incident ID $($res2.incident_id)" } else { "None" }

Write-Host "[+] Stage 2 Ingested -> Log ID: $($res2.log_id)" -ForegroundColor Green
Write-Host "    |- Host       : $($res2.host) | Source: $($res2.source)" -ForegroundColor Gray
Write-Host "    |- Attacker IP: $($res2.src_ip)" -ForegroundColor Gray
Write-Host "    |- Severity   : $($res2.severity) | Anomaly Score: $($res2.anomaly_score)" -ForegroundColor Gray
Write-Host "    |- Rules Hit  : $rules2" -ForegroundColor Yellow
Write-Host "    |- Incident   : $inc2" -ForegroundColor Cyan

Start-Sleep -Seconds 1

# Stage 3: OS Command Injection (MITRE Tactic: Execution)
Write-Host "`n[Stage 3] Injecting Command Injection execution log (Execution)..." -ForegroundColor Yellow
$cmd_body = @{
    host = "web-server-prod"
    source = "Apache"
    log_type = "Web"
    severity = "CRITICAL"
    message = "GET /cgi-bin/admin.sh?cmd=whoami;%20id;%20uname HTTP/1.1"
    raw_log = '198.51.100.55 - - [25/Jul/2026:22:20:05 +0000] "GET /cgi-bin/admin.sh?cmd=whoami;%20id;%20uname HTTP/1.1" 200 120'
    src_ip = "198.51.100.55"
    process = "apache-access"
} | ConvertTo-Json

$res3 = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -Body $cmd_body
$rules3 = $res3.rules_matched -join ", "
$inc3 = if ($res3.incident_id) { "Escalated to CRITICAL in Incident ID $($res3.incident_id)" } else { "None" }

Write-Host "[+] Stage 3 Ingested -> Log ID: $($res3.log_id)" -ForegroundColor Green
Write-Host "    |- Host       : $($res3.host) | Source: $($res3.source)" -ForegroundColor Gray
Write-Host "    |- Attacker IP: $($res3.src_ip)" -ForegroundColor Gray
Write-Host "    |- Severity   : $($res3.severity) | Anomaly Score: $($res3.anomaly_score)" -ForegroundColor Gray
Write-Host "    |- Rules Hit  : $rules3" -ForegroundColor Yellow
Write-Host "    |- Incident   : $inc3" -ForegroundColor Cyan

Write-Host "`n====================================================" -ForegroundColor Cyan
Write-Host "[+] Multi-stage attack chain injected successfully!" -ForegroundColor Green
Write-Host "[+] Check the dashboard for a new CRITICAL incident on 'WEB-SERVER-PROD'." -ForegroundColor Green
Write-Host "[+] The incident will show Attacker IP: 198.51.100.55." -ForegroundColor Green
Write-Host "====================================================" -ForegroundColor Cyan

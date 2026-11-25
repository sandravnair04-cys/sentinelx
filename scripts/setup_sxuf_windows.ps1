<#
.SYNOPSIS
Registers this Windows host as a SXUF agent and writes a local forwarder config.

.DESCRIPTION
Run from anywhere on the SentinelX server host. The agent key is stored in
forwarder/agent.key with a restrictive ACL and is never written to config.yaml.
#>
param(
    [string]$ServerUrl = 'http://localhost:8000',
    [string]$Username = 'admin',
    [string]$Password = 'Admin@123!'
)

$ErrorActionPreference = 'Stop'
$projectDir = Split-Path -Parent $PSScriptRoot
$forwarderDir = Join-Path $projectDir 'forwarder'
if (-not (Test-Path $forwarderDir)) { throw "Forwarder directory not found: $forwarderDir" }

$hostname = $env:COMPUTERNAME
$safeName = ($hostname -replace '[^A-Za-z0-9._-]', '').ToLower()
$agentId = "sxuf-win-$safeName"

$login = Invoke-RestMethod -Uri "$ServerUrl/api/auth/login" -Method Post `
    -ContentType 'application/json' `
    -Body (@{ username = $Username; password = $Password } | ConvertTo-Json)
$headers = @{ Authorization = "Bearer $($login.access_token)" }

try {
    $registration = Invoke-RestMethod -Uri "$ServerUrl/api/agents/register" -Method Post `
        -Headers $headers -ContentType 'application/json' `
        -Body (@{ agent_id = $agentId; hostname = $hostname } | ConvertTo-Json)
} catch {
    if ($_.Exception.Response.StatusCode.value__ -eq 409) {
        # Agent already exists: rotate to a fresh one-time key.
        $registration = Invoke-RestMethod -Uri "$ServerUrl/api/agents/$agentId/rotate" -Method Post -Headers $headers
    } else { throw }
}

$keyPath = Join-Path $forwarderDir 'agent.key'
[System.IO.File]::WriteAllText($keyPath, $registration.agent_key, [System.Text.UTF8Encoding]::new($false))
try {
    $principal = if ($env:USERDOMAIN) { "$env:USERDOMAIN\$env:USERNAME" } else { $env:USERNAME }
    & icacls $keyPath /inheritance:r /grant:r "${principal}:(F)" | Out-Null
} catch {
    Write-Warning "Could not tighten ACL on agent.key - restrict it manually."
}

$configPath = Join-Path $forwarderDir 'config.yaml'
$config = @"
agent:
  id: "$agentId"
  key_file: "agent.key"

server:
  url: "$ServerUrl"
  tls_verify: true
  timeout_seconds: 15

endpoint:
  hostname: "$hostname"
  os_type: "windows"

runtime:
  batch_size: 100
  heartbeat_seconds: 60
  flush_seconds: 5
  max_buffer_events: 50000
  max_retries: 5
  state_dir: "state"

sources:
  - kind: windows_event
    name: windows-security
    channel: Security
    event_ids: [4624, 4625, 4672, 4688, 4720, 4732, 1102]
    batch_size: 64
  - kind: windows_event
    name: windows-system
    channel: System
    event_ids: [7045, 7034, 6005, 6006]
    batch_size: 64
  - kind: windows_event
    name: windows-application
    channel: Application
    event_ids: [1000, 1001]
    batch_size: 64
"@
[System.IO.File]::WriteAllText($configPath, $config, [System.Text.UTF8Encoding]::new($false))

Write-Host "Agent registered : $agentId"
Write-Host "Hostname         : $hostname"
Write-Host "Config           : $configPath"
Write-Host "Key file         : $keyPath (restricted ACL)"
Write-Host ""
Write-Host "Next steps:"
Write-Host "  cd '$forwarderDir'"
Write-Host "  python sxuf.py verify-config"
Write-Host "  python sxuf.py once"

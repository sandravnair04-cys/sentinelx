<#
.SYNOPSIS
Initialises, checks, commits and pushes SENTINELX to GitHub.

.EXAMPLE
powershell -ExecutionPolicy Bypass -File .\scripts\publish_github.ps1 -RepoUrl "https://github.com/<username>/sentinelx.git"
#>
param(
    [Parameter(Mandatory = $true)]
    [string]$RepoUrl,
    [string]$CommitMessage = "feat: SENTINELX agentic AI SOC platform",
    [string]$GitPath = ""
)

$ErrorActionPreference = 'Stop'
$projectDir = Split-Path -Parent $PSScriptRoot
Set-Location $projectDir

if ($GitPath) {
    if (-not (Test-Path $GitPath)) { throw "GitPath not found: $GitPath" }
    $env:PATH = (Split-Path $GitPath) + ";" + $env:PATH
}
if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    throw "git was not found in PATH. Install Git for Windows, reopen PowerShell, or pass -GitPath."
}

Write-Host "Project : $projectDir"
Write-Host "Git     : $((Get-Command git).Source)"

git init -b main
git add .

$staged = @(git diff --cached --name-only)
$patterns = @(
    '(^|/)\.env$',
    '(^|/)agent\.key$',
    '(^|/)config\.yaml$',
    '\.db$',
    '\.db-wal$',
    '\.db-shm$',
    '(^|/)node_modules/',
    '(^|/)dist/',
    '\.bak$',
    '^data/reports/',
    '(^|/)state/'
)
$forbidden = @($staged | Where-Object { $p = $_; $patterns | Where-Object { $p -match $_ } })
if ($forbidden.Count -gt 0) {
    Write-Host ""
    Write-Host "ABORT: forbidden files would be committed:" -ForegroundColor Red
    $forbidden | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
    Write-Host "Check .gitignore before retrying."
    exit 1
}

Write-Host ""
Write-Host "Files to be committed: $($staged.Count)"
git status --short

$answer = Read-Host "Commit and push to $RepoUrl ? (y/N)"
if ($answer -ne 'y' -and $answer -ne 'Y') {
    Write-Host "Aborted by user; nothing committed."
    exit 0
}

git commit -m $CommitMessage
if (git remote get-url origin 2>$null) {
    git remote set-url origin $RepoUrl
} else {
    git remote add origin $RepoUrl
}
git push -u origin main

Write-Host ""
Write-Host "Done. Verify at $RepoUrl" -ForegroundColor Green

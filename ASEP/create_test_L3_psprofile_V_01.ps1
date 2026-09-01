# ***************************************************************************
# *  Script      : create_test_L3_psprofile_V_01.ps1
# *  Version     : V_01
# *  Last Update : 2026-07-31 07:34 EST
# *  Purpose     : Level 3 synthetic check for Get-PowerShellProfileEntries.
# *                Creates the current user's CurrentHost profile (if absent)
# *                with a single comment line. If the profile already exists
# *                this script APPENDS a clearly-labeled comment and removes
# *                only that line on -Remove. Nothing executes on profile load.
# *  Admin       : NOT required (user profile path).
# *  Logging     : Appends to create_test_L3_psprofile_V_01.log beside script.
# *  Options     : (default) Create  |  -Remove  |  -WhatIf
# * Copyright (c) 2026, Don Murdoch, Blue Team Handbook
# ***************************************************************************
[CmdletBinding(SupportsShouldProcess=$true)]
param([switch]$Remove)

$ProfilePath  = $PROFILE.CurrentUserCurrentHost
$SyntheticLine= "# ASEP_Synthetic_L3_PSProfile - synthetic check marker (safe to delete)"
$LogFile      = if ($PSCommandPath) { $PSCommandPath -replace '\.ps1$','.log' } else { "create_test_L3_psprofile_V_01.log" }
$CreatedFile  = $false   # track whether WE created the file (vs. it pre-existed)

function Write-Log { param([string]$M)
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'; $tz = [TimeZoneInfo]::Local.StandardName
    Add-Content -LiteralPath $LogFile -Value "$ts | $tz | $M" -ErrorAction SilentlyContinue }

if ($Remove) {
    Write-Host "[*] Removing L3 PSProfile synthetic check..." -ForegroundColor Yellow
    if (-not (Test-Path -LiteralPath $ProfilePath)) {
        Write-Host "  [-] Profile not present" -ForegroundColor Gray; return }
    $lines = Get-Content -LiteralPath $ProfilePath
    if ($lines -contains $SyntheticLine) {
        if ($PSCmdlet.ShouldProcess($ProfilePath,"Remove synthetic comment line")) {
            $filtered = $lines | Where-Object { $_ -ne $SyntheticLine }
            if ($filtered) { $filtered | Set-Content -LiteralPath $ProfilePath }
            else { Remove-Item -LiteralPath $ProfilePath -Force }
            Write-Host "  [+] Removed synthetic marker from $ProfilePath" -ForegroundColor Green
            Write-Log "REMOVED | L3 PowerShellProfiles | marker removed from $ProfilePath"
        }
    } else { Write-Host "  [-] Synthetic marker not found in profile" -ForegroundColor Gray }
    return
}

Write-Host "[*] Creating L3 PSProfile synthetic check..." -ForegroundColor Yellow
if (-not [string]::IsNullOrEmpty($ProfilePath)) {
    $dir = Split-Path $ProfilePath -Parent
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
}
if (Test-Path -LiteralPath $ProfilePath) {
    $existing = Get-Content -LiteralPath $ProfilePath
    if ($existing -contains $SyntheticLine) { Write-Warning "Marker already present. Run -Remove first."; return }
}
if ($PSCmdlet.ShouldProcess($ProfilePath,"Append synthetic marker comment")) {
    Add-Content -LiteralPath $ProfilePath -Value $SyntheticLine
    Write-Host "  [+] Appended marker to $ProfilePath" -ForegroundColor Green
    Write-Log "ENABLED | L3 PowerShellProfiles | appended marker to $ProfilePath"
}
Write-Host "[+] Run analyzer at -Level 3; look for the profile in PowerShell Profiles." -ForegroundColor Cyan
Write-Host "    Remove: .\create_test_L3_psprofile_V_01.ps1 -Remove" -ForegroundColor DarkGray

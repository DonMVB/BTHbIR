# ***************************************************************************
# *  Script      : create_test_L1_runkeys_V_01.ps1
# *  Version     : V_01
# *  Last Update : 2026-07-31 07:34 EST
# *  Purpose     : Level 1 synthetic check for Get-RunKeys.
# *                Seeds HKCU\...\Run\ASEP_Synthetic_L1_RunKeys = notepad.exe
# *                so the analyzer reports at least one Run Key entry.
# *  Admin       : NOT required (HKCU only).
# *  Logging     : Appends to create_test_L1_runkeys_V_01.log beside this script.
# *  Options     : (default) Create  |  -Remove  |  -WhatIf
# * Copyright (c) 2026, Don Murdoch, Blue Team Handbook
# ***************************************************************************
[CmdletBinding(SupportsShouldProcess=$true)]
param([switch]$Remove)

$RunKey    = "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
$RunReg    = "Registry::$RunKey"
$ValueName = "ASEP_Synthetic_L1_RunKeys"
$Target    = Join-Path $env:SystemRoot 'System32\notepad.exe'
$LogFile   = if ($PSCommandPath) { $PSCommandPath -replace '\.ps1$','.log' } else { "create_test_L1_runkeys_V_01.log" }

function Write-Log { param([string]$M)
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'; $tz = [TimeZoneInfo]::Local.StandardName
    Add-Content -LiteralPath $LogFile -Value "$ts | $tz | $M" -ErrorAction SilentlyContinue }

if ($Remove) {
    Write-Host "[*] Removing L1 RunKeys synthetic check..." -ForegroundColor Yellow
    if ((Test-Path -LiteralPath $RunReg) -and (Get-Item -LiteralPath $RunReg).Property -contains $ValueName) {
        if ($PSCmdlet.ShouldProcess("$RunKey :: $ValueName","Remove")) {
            Remove-ItemProperty -LiteralPath $RunReg -Name $ValueName -Force
            Write-Host "  [+] Removed $ValueName" -ForegroundColor Green
            Write-Log "REMOVED | L1 RunKeys | $RunKey\$ValueName"
        }
    } else { Write-Host "  [-] Not present" -ForegroundColor Gray }
    return
}

Write-Host "[*] Creating L1 RunKeys synthetic check..." -ForegroundColor Yellow
if (-not (Test-Path -LiteralPath $RunReg)) { New-Item -Path $RunReg -Force | Out-Null }
if ((Get-Item -LiteralPath $RunReg).Property -contains $ValueName) {
    Write-Warning "Already present. Run -Remove first."; return }
if ($PSCmdlet.ShouldProcess("$RunKey :: $ValueName","Add")) {
    New-ItemProperty -LiteralPath $RunReg -Name $ValueName -Value $Target -PropertyType String -Force | Out-Null
    Write-Host "  [+] $ValueName = $Target" -ForegroundColor Green
    Write-Log "ENABLED | L1 RunKeys | $RunKey\$ValueName -> $Target"
}
Write-Host "[+] Run analyzer at -Level 1; look for '$ValueName' in Run Keys." -ForegroundColor Cyan
Write-Host "    Remove: .\create_test_L1_runkeys_V_01.ps1 -Remove" -ForegroundColor DarkGray

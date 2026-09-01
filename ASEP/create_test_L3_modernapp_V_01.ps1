# ***************************************************************************
# *  Script      : create_test_L3_modernapp_V_01.ps1
# *  Version     : V_01
# *  Last Update : 2026-07-31 07:34 EST
# *  Purpose     : Level 3 synthetic check for Get-ModernAppEntries.
# *                Creates a fake AppModel startup-task state key under HKCU.
# *                No real package is registered; nothing can launch. The
# *                analyzer finds the State=2 (Enabled) entry in the
# *                SystemAppData tree.
# *  Admin       : NOT required (HKCU only).
# *  Logging     : Appends to create_test_L3_modernapp_V_01.log beside script.
# *  Options     : (default) Create  |  -Remove  |  -WhatIf
# * Copyright (c) 2026, Don Murdoch, Blue Team Handbook
# ***************************************************************************
[CmdletBinding(SupportsShouldProcess=$true)]
param([switch]$Remove)

$Base      = "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData"
$PkgFamily = "ASEP.SyntheticCheck_L3Modern_0000000000000"
$TaskId    = "ASEP_Synthetic_L3_StartupTask"
$PkgKey    = "$Base\$PkgFamily"
$TaskKey   = "$PkgKey\$TaskId"
$TaskReg   = "Registry::$TaskKey"
$PkgReg    = "Registry::$PkgKey"
$LogFile   = if ($PSCommandPath) { $PSCommandPath -replace '\.ps1$','.log' } else { "create_test_L3_modernapp_V_01.log" }

function Write-Log { param([string]$M)
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'; $tz = [TimeZoneInfo]::Local.StandardName
    Add-Content -LiteralPath $LogFile -Value "$ts | $tz | $M" -ErrorAction SilentlyContinue }

if ($Remove) {
    Write-Host "[*] Removing L3 ModernApp synthetic check..." -ForegroundColor Yellow
    if (Test-Path -LiteralPath $PkgReg) {
        if ($PSCmdlet.ShouldProcess($PkgKey,"Remove synthetic package key")) {
            Remove-Item -LiteralPath $PkgReg -Recurse -Force
            Write-Host "  [+] Removed $PkgKey" -ForegroundColor Green
            Write-Log "REMOVED | L3 ModernAppEntries | $PkgKey"
        }
    } else { Write-Host "  [-] Not present" -ForegroundColor Gray }
    return
}

Write-Host "[*] Creating L3 ModernApp synthetic check..." -ForegroundColor Yellow
if (Test-Path -LiteralPath $TaskReg) { Write-Warning "Already present. Run -Remove first."; return }
if (-not $PSCmdlet.ShouldProcess($TaskKey,"Create AppModel startup-task State=2")) { return }
New-Item -Path $TaskReg -Force | Out-Null
New-ItemProperty -LiteralPath $TaskReg -Name "State" -Value 2 -PropertyType DWord -Force | Out-Null
Write-Host "  [+] Created $TaskKey (State=2 / Enabled)" -ForegroundColor Green
Write-Log "ENABLED | L3 ModernAppEntries | $TaskKey State=2 (Enabled, no real package behind it)"
Write-Host "[+] Run analyzer at -Level 3; look for package '$PkgFamily' in Modern Apps." -ForegroundColor Cyan
Write-Host "    Remove: .\create_test_L3_modernapp_V_01.ps1 -Remove" -ForegroundColor DarkGray

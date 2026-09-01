#Requires -RunAsAdministrator
# ***************************************************************************
# *  Script      : create_test_L3_bho_V_01.ps1
# *  Version     : V_01
# *  Last Update : 2026-07-31 07:34 EST
# *  Purpose     : Level 3 synthetic check for Get-BrowserHelperObjects.
# *                Plants a synthetic CLSID under the IE BHO registry key.
# *                IE is largely deprecated; nothing loads from this entry.
# *                The analyzer detects the CLSID subkey regardless.
# *  Admin       : REQUIRED (HKLM write).
# *  Logging     : Appends to create_test_L3_bho_V_01.log beside script.
# *  Options     : (default) Create  |  -Remove  |  -WhatIf
# * Copyright (c) 2026, Don Murdoch, Blue Team Handbook
# ***************************************************************************
[CmdletBinding(SupportsShouldProcess=$true)]
param([switch]$Remove)

$Clsid   = '{EEEEEEEE-0002-4302-8302-EEEEEEEEEEEE}'
$BhoBase = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects"
$BhoKey  = "$BhoBase\$Clsid"
$BhoReg  = "Registry::$BhoKey"
$LogFile = if ($PSCommandPath) { $PSCommandPath -replace '\.ps1$','.log' } else { "create_test_L3_bho_V_01.log" }

function Write-Log { param([string]$M)
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'; $tz = [TimeZoneInfo]::Local.StandardName
    Add-Content -LiteralPath $LogFile -Value "$ts | $tz | $M" -ErrorAction SilentlyContinue }

if ($Remove) {
    Write-Host "[*] Removing L3 BHO synthetic check..." -ForegroundColor Yellow
    if (Test-Path -LiteralPath $BhoReg) {
        if ($PSCmdlet.ShouldProcess($BhoKey,"Remove BHO key")) {
            Remove-Item -LiteralPath $BhoReg -Recurse -Force
            Write-Host "  [+] Removed $BhoKey" -ForegroundColor Green
            Write-Log "REMOVED | L3 BrowserHelperObjects | $BhoKey"
        }
    } else { Write-Host "  [-] Not present" -ForegroundColor Gray }
    return
}

Write-Host "[*] Creating L3 BHO synthetic check..." -ForegroundColor Yellow
if (Test-Path -LiteralPath $BhoReg) { Write-Warning "Already present. Run -Remove first."; return }
if ($PSCmdlet.ShouldProcess($BhoKey,"Create BHO CLSID subkey")) {
    New-Item -Path $BhoReg -Force | Out-Null
    New-ItemProperty -LiteralPath $BhoReg -Name "(Default)" -Value "ASEP Synthetic BHO (safe to delete)" -PropertyType String -Force | Out-Null
    Write-Host "  [+] Created $BhoKey" -ForegroundColor Green
    Write-Log "ENABLED | L3 BrowserHelperObjects | $BhoKey"
}
Write-Host "[+] Run analyzer at -Level 3; look for '$Clsid' in Browser Helper Objects." -ForegroundColor Cyan
Write-Host "    Remove: .\create_test_L3_bho_V_01.ps1 -Remove" -ForegroundColor DarkGray

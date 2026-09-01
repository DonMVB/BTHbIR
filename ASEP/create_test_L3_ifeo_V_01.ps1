#Requires -RunAsAdministrator
# ***************************************************************************
# *  Script      : create_test_L3_ifeo_V_01.ps1
# *  Version     : V_01
# *  Last Update : 2026-07-31 07:34 EST
# *  Purpose     : Level 3 synthetic check for Get-IFEOEntries (Image File
# *                Execution Options debugger hijack). Plants a Debugger value
# *                under a SYNTHETIC, MADE-UP executable name that nothing on
# *                the system uses. The fake debugger path is also non-existent.
# *                No real process is intercepted.
# *  Admin       : REQUIRED (HKLM write).
# *  Logging     : Appends to create_test_L3_ifeo_V_01.log beside script.
# *  Options     : (default) Create  |  -Remove  |  -WhatIf
# * Copyright (c) 2026, Don Murdoch, Blue Team Handbook
# ***************************************************************************
[CmdletBinding(SupportsShouldProcess=$true)]
param([switch]$Remove)

$FakeExe    = "ASEP_Synthetic_L3_Target.exe"   # does not exist; no real process is intercepted
$FakeDbg    = "C:\ASEP_SyntheticCheck\fake_debugger_l3.exe"   # non-existent
$IfeoBase   = "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
$IfeoKey    = "$IfeoBase\$FakeExe"
$IfeoReg    = "Registry::$IfeoKey"
$LogFile    = if ($PSCommandPath) { $PSCommandPath -replace '\.ps1$','.log' } else { "create_test_L3_ifeo_V_01.log" }

function Write-Log { param([string]$M)
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'; $tz = [TimeZoneInfo]::Local.StandardName
    Add-Content -LiteralPath $LogFile -Value "$ts | $tz | $M" -ErrorAction SilentlyContinue }

if ($Remove) {
    Write-Host "[*] Removing L3 IFEO synthetic check..." -ForegroundColor Yellow
    if (Test-Path -LiteralPath $IfeoReg) {
        if ($PSCmdlet.ShouldProcess($IfeoKey,"Remove IFEO key")) {
            Remove-Item -LiteralPath $IfeoReg -Recurse -Force
            Write-Host "  [+] Removed $IfeoKey" -ForegroundColor Green
            Write-Log "REMOVED | L3 IFEOEntries | $IfeoKey"
        }
    } else { Write-Host "  [-] Not present" -ForegroundColor Gray }
    return
}

Write-Host "[*] Creating L3 IFEO synthetic check..." -ForegroundColor Yellow
Write-Host "    Image = $FakeExe (synthetic, does not exist on system)" -ForegroundColor DarkGray
Write-Host "    Debugger = $FakeDbg (non-existent path, nothing runs)" -ForegroundColor DarkGray
if (Test-Path -LiteralPath $IfeoReg) { Write-Warning "Already present. Run -Remove first."; return }
if ($PSCmdlet.ShouldProcess($IfeoKey,"Create IFEO Debugger entry")) {
    New-Item -Path $IfeoReg -Force | Out-Null
    New-ItemProperty -LiteralPath $IfeoReg -Name "Debugger" -Value $FakeDbg -PropertyType String -Force | Out-Null
    Write-Host "  [+] Created $IfeoKey\Debugger = $FakeDbg" -ForegroundColor Green
    Write-Log "ENABLED | L3 IFEOEntries | $IfeoKey Debugger=$FakeDbg (fake exe + fake dbg, inert)"
}
Write-Host "[+] Run analyzer at -Level 3; look for '$FakeExe' in Image File Execution Options." -ForegroundColor Cyan
Write-Host "    Remove: .\create_test_L3_ifeo_V_01.ps1 -Remove" -ForegroundColor DarkGray

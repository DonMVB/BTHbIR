# ***************************************************************************
# *  Script      : create_test_L3_bootexecute_V_01.ps1
# *  Version     : V_01
# *  Last Update : 2026-07-31 07:34 EST
# *  Purpose     : Level 3 VERIFY-ONLY check for Get-BootExecuteEntries.
# *  WHY NO SEEDING: BootExecute always contains "autocheck autochk *" on a
# *    normal Windows system - the collector ALWAYS returns a result. Modifying
# *    this value risks filesystem corruption at next boot. This script verifies
# *    the value is present. No modification is made.
# *  Admin       : NOT required (read-only).
# *  Logging     : Appends to create_test_L3_bootexecute_V_01.log beside script.
# *  Options     : (default) Verify  |  -Remove (logs only)  |  -WhatIf
# * Copyright (c) 2026, Don Murdoch, Blue Team Handbook
# ***************************************************************************
[CmdletBinding(SupportsShouldProcess=$true)]
param([switch]$Remove)
$SmKey   = "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager"
$LogFile = if ($PSCommandPath) { $PSCommandPath -replace '\.ps1$','.log' } else { "create_test_L3_bootexecute_V_01.log" }
function Write-Log { param([string]$M)
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'; $tz = [TimeZoneInfo]::Local.StandardName
    Add-Content -LiteralPath $LogFile -Value "$ts | $tz | $M" -ErrorAction SilentlyContinue }
if ($Remove) {
    Write-Host "[*] BootExecute is verify-only - no artifact to remove." -ForegroundColor Yellow
    Write-Log "VERIFY-ONLY NOTED | L3 BootExecuteEntries | no artifact created/removed"
    return
}
Write-Host "[*] Verifying L3 BootExecute detection (read-only)..." -ForegroundColor Yellow
Write-Host "    NOTE: No seeding. Modifying BootExecute risks filesystem corruption." -ForegroundColor DarkGray
$k = Get-Item -LiteralPath "Registry::$SmKey" -ErrorAction SilentlyContinue
if ($k -and $k.Property -contains "BootExecute") {
    $val = $k.GetValue("BootExecute") -join "; "
    Write-Host "  [OK] BootExecute = $val" -ForegroundColor Green
    Write-Host "[+] Get-BootExecuteEntries WILL detect this at -Level 3." -ForegroundColor Cyan
    Write-Log "VERIFIED | L3 BootExecuteEntries | value present: $val (no seeding needed)"
} else {
    Write-Host "  [!] BootExecute value not found - unexpected." -ForegroundColor Red
    Write-Log "VERIFY FAILED | L3 BootExecuteEntries | value missing"
}

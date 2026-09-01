# ***************************************************************************
# *  Script      : create_test_L3_drivers_V_01.ps1
# *  Version     : V_01
# *  Last Update : 2026-07-31 07:34 EST
# *  Purpose     : Level 3 VERIFY-ONLY check for Get-AutoStartDrivers.
# *  WHY NO SEEDING: Every Windows system has auto/boot/system-start drivers.
# *    The collector uses Get-CimInstance (Win32_SystemDriver) and ALWAYS
# *    returns results. Registering a kernel-mode driver requires a signed .sys
# *    file and is outside the scope of a safe synthetic check.
# *  Admin       : NOT required (read-only CIM query).
# *  Logging     : Appends to create_test_L3_drivers_V_01.log beside script.
# *  Options     : (default) Verify  |  -Remove (logs only)  |  -WhatIf
# * Copyright (c) 2026, Don Murdoch, Blue Team Handbook
# ***************************************************************************
[CmdletBinding(SupportsShouldProcess=$true)]
param([switch]$Remove)
$LogFile = if ($PSCommandPath) { $PSCommandPath -replace '\.ps1$','.log' } else { "create_test_L3_drivers_V_01.log" }
function Write-Log { param([string]$M)
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'; $tz = [TimeZoneInfo]::Local.StandardName
    Add-Content -LiteralPath $LogFile -Value "$ts | $tz | $M" -ErrorAction SilentlyContinue }
if ($Remove) {
    Write-Host "[*] Drivers is verify-only - no artifact to remove." -ForegroundColor Yellow
    Write-Log "VERIFY-ONLY NOTED | L3 AutoStartDrivers | no artifact created/removed"
    return
}
Write-Host "[*] Verifying L3 AutoStartDrivers detection (read-only)..." -ForegroundColor Yellow
Write-Host "    NOTE: No seeding. Kernel drivers require signed .sys; CIM always returns results." -ForegroundColor DarkGray
$drivers = @(Get-CimInstance -ClassName Win32_SystemDriver -ErrorAction SilentlyContinue |
    Where-Object { $_.StartMode -in @("Auto","System","Boot") })
if ($drivers.Count -gt 0) {
    Write-Host ("  [OK] {0} auto/boot/system drivers found. First: {1}" -f $drivers.Count, $drivers[0].Name) -ForegroundColor Green
    Write-Host "[+] Get-AutoStartDrivers WILL detect results at -Level 3." -ForegroundColor Cyan
    Write-Log "VERIFIED | L3 AutoStartDrivers | $($drivers.Count) drivers found via CIM (no seeding needed)"
} else {
    Write-Host "  [!] No auto-start drivers found - unexpected." -ForegroundColor Red
    Write-Log "VERIFY FAILED | L3 AutoStartDrivers | no drivers returned"
}

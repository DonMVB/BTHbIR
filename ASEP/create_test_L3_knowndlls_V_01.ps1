# ***************************************************************************
# *  Script      : create_test_L3_knowndlls_V_01.ps1
# *  Version     : V_01
# *  Last Update : 2026-07-31 07:34 EST
# *  Purpose     : Level 3 VERIFY-ONLY check for Get-KnownDLLs.
# *  WHY NO SEEDING: KnownDLLs always contains ntdll, kernel32, and other core
# *    DLLs on every Windows system. The collector ALWAYS returns results.
# *    Adding entries to KnownDLLs affects system-wide DLL loading behavior
# *    and can cause process launch failures.
# *  Admin       : NOT required (read-only).
# *  Logging     : Appends to create_test_L3_knowndlls_V_01.log beside script.
# *  Options     : (default) Verify  |  -Remove (logs only)  |  -WhatIf
# * Copyright (c) 2026, Don Murdoch, Blue Team Handbook
# ***************************************************************************
[CmdletBinding(SupportsShouldProcess=$true)]
param([switch]$Remove)
$KdKey   = "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs"
$LogFile = if ($PSCommandPath) { $PSCommandPath -replace '\.ps1$','.log' } else { "create_test_L3_knowndlls_V_01.log" }
function Write-Log { param([string]$M)
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'; $tz = [TimeZoneInfo]::Local.StandardName
    Add-Content -LiteralPath $LogFile -Value "$ts | $tz | $M" -ErrorAction SilentlyContinue }
if ($Remove) {
    Write-Host "[*] KnownDLLs is verify-only - no artifact to remove." -ForegroundColor Yellow
    Write-Log "VERIFY-ONLY NOTED | L3 KnownDLLs | no artifact created/removed"
    return
}
Write-Host "[*] Verifying L3 KnownDLLs detection (read-only)..." -ForegroundColor Yellow
Write-Host "    NOTE: No seeding. Adding KnownDLLs entries affects system-wide DLL loading." -ForegroundColor DarkGray
$k = Get-Item -LiteralPath "Registry::$KdKey" -ErrorAction SilentlyContinue
if ($k -and $k.Property.Count -gt 0) {
    Write-Host ("  [OK] {0} KnownDLL entries found. Includes: {1}" -f $k.Property.Count, (($k.Property | Select-Object -First 3) -join ', ')) -ForegroundColor Green
    Write-Host "[+] Get-KnownDLLs WILL detect results at -Level 3." -ForegroundColor Cyan
    Write-Log "VERIFIED | L3 KnownDLLs | $($k.Property.Count) entries confirmed (no seeding needed)"
} else {
    Write-Host "  [!] KnownDLLs key empty or missing - unexpected." -ForegroundColor Red
    Write-Log "VERIFY FAILED | L3 KnownDLLs | key empty or missing"
}

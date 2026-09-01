# ***************************************************************************
# *  Script      : create_test_L3_lsa_V_01.ps1
# *  Version     : V_01
# *  Last Update : 2026-07-31 07:34 EST
# *  Purpose     : Level 3 VERIFY-ONLY check for Get-LSAProviders.
# *  WHY NO SEEDING: Authentication Packages, Security Packages, and
# *    Notification Packages are always present in HKLM LSA on Windows.
# *    The collector ALWAYS returns results. Adding a synthetic package name to
# *    these multi-string values could cause authentication failures at logon.
# *  Admin       : NOT required (read-only).
# *  Logging     : Appends to create_test_L3_lsa_V_01.log beside script.
# *  Options     : (default) Verify  |  -Remove (logs only)  |  -WhatIf
# * Copyright (c) 2026, Don Murdoch, Blue Team Handbook
# ***************************************************************************
[CmdletBinding(SupportsShouldProcess=$true)]
param([switch]$Remove)
$LsaKey  = "HKLM\SYSTEM\CurrentControlSet\Control\Lsa"
$Values  = @("Authentication Packages","Security Packages","Notification Packages")
$LogFile = if ($PSCommandPath) { $PSCommandPath -replace '\.ps1$','.log' } else { "create_test_L3_lsa_V_01.log" }
function Write-Log { param([string]$M)
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'; $tz = [TimeZoneInfo]::Local.StandardName
    Add-Content -LiteralPath $LogFile -Value "$ts | $tz | $M" -ErrorAction SilentlyContinue }
if ($Remove) {
    Write-Host "[*] LSA Providers is verify-only - no artifact to remove." -ForegroundColor Yellow
    Write-Log "VERIFY-ONLY NOTED | L3 LSAProviders | no artifact created/removed"
    return
}
Write-Host "[*] Verifying L3 LSAProviders detection (read-only)..." -ForegroundColor Yellow
Write-Host "    NOTE: No seeding. Modifying LSA packages risks authentication failures." -ForegroundColor DarkGray
$k = Get-Item -LiteralPath "Registry::$LsaKey" -ErrorAction SilentlyContinue
$found = 0
foreach ($vname in $Values) {
    if ($k -and $k.Property -contains $vname) {
        $val = ($k.GetValue($vname) -join ", ")
        Write-Host ("  [OK] {0,-28} = {1}" -f $vname, $val) -ForegroundColor Green
        $found++
    } else { Write-Host "  [--] $vname not present" -ForegroundColor Gray }
}
if ($found -gt 0) {
    Write-Host "[+] Get-LSAProviders WILL detect results at -Level 3." -ForegroundColor Cyan
    Write-Log "VERIFIED | L3 LSAProviders | $found LSA values confirmed (no seeding needed)"
} else {
    Write-Host "  [!] No LSA package values found - unexpected." -ForegroundColor Red
    Write-Log "VERIFY FAILED | L3 LSAProviders | no values found"
}

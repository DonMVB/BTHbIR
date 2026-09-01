# ***************************************************************************
# *  Script      : create_test_L3_netproviders_V_01.ps1
# *  Version     : V_01
# *  Last Update : 2026-07-31 07:34 EST
# *  Purpose     : Level 3 VERIFY-ONLY check for Get-NetworkProviders.
# *  WHY NO SEEDING: The NetworkProvider ProviderOrder value is always present
# *    on Windows. The collector ALWAYS returns a result. Modifying ProviderOrder
# *    risks network connectivity disruption.
# *  Admin       : NOT required (read-only).
# *  Logging     : Appends to create_test_L3_netproviders_V_01.log beside script.
# *  Options     : (default) Verify  |  -Remove (logs only)  |  -WhatIf
# * Copyright (c) 2026, Don Murdoch, Blue Team Handbook
# ***************************************************************************
[CmdletBinding(SupportsShouldProcess=$true)]
param([switch]$Remove)
$NpKey   = "HKLM\SYSTEM\CurrentControlSet\Control\NetworkProvider\Order"
$LogFile = if ($PSCommandPath) { $PSCommandPath -replace '\.ps1$','.log' } else { "create_test_L3_netproviders_V_01.log" }
function Write-Log { param([string]$M)
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'; $tz = [TimeZoneInfo]::Local.StandardName
    Add-Content -LiteralPath $LogFile -Value "$ts | $tz | $M" -ErrorAction SilentlyContinue }
if ($Remove) {
    Write-Host "[*] NetworkProviders is verify-only - no artifact to remove." -ForegroundColor Yellow
    Write-Log "VERIFY-ONLY NOTED | L3 NetworkProviders | no artifact created/removed"
    return
}
Write-Host "[*] Verifying L3 NetworkProviders detection (read-only)..." -ForegroundColor Yellow
Write-Host "    NOTE: No seeding. Modifying ProviderOrder risks network disruption." -ForegroundColor DarkGray
$k = Get-Item -LiteralPath "Registry::$NpKey" -ErrorAction SilentlyContinue
if ($k -and $k.Property -contains "ProviderOrder") {
    $val = $k.GetValue("ProviderOrder")
    Write-Host "  [OK] ProviderOrder = $val" -ForegroundColor Green
    Write-Host "[+] Get-NetworkProviders WILL detect results at -Level 3." -ForegroundColor Cyan
    Write-Log "VERIFIED | L3 NetworkProviders | ProviderOrder=$val (no seeding needed)"
} else {
    Write-Host "  [!] ProviderOrder not found - unexpected." -ForegroundColor Red
    Write-Log "VERIFY FAILED | L3 NetworkProviders | ProviderOrder missing"
}

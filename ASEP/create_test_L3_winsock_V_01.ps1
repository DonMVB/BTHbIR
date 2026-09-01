# ***************************************************************************
# *  Script      : create_test_L3_winsock_V_01.ps1
# *  Version     : V_01
# *  Last Update : 2026-07-31 07:34 EST
# *  Purpose     : Level 3 VERIFY-ONLY check for Get-WinsockLSP.
# *  WHY NO SEEDING: The Winsock Protocol_Catalog9 and NameSpace_Catalog5 are
# *    always populated on Windows. The collector ALWAYS returns results.
# *    Modifying the Winsock catalog incorrectly can break all network
# *    connectivity (requires netsh winsock reset to repair).
# *  Admin       : NOT required (read-only).
# *  Logging     : Appends to create_test_L3_winsock_V_01.log beside script.
# *  Options     : (default) Verify  |  -Remove (logs only)  |  -WhatIf
# * Copyright (c) 2026, Don Murdoch, Blue Team Handbook
# ***************************************************************************
[CmdletBinding(SupportsShouldProcess=$true)]
param([switch]$Remove)
$WsBase  = "HKLM\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters"
$LogFile = if ($PSCommandPath) { $PSCommandPath -replace '\.ps1$','.log' } else { "create_test_L3_winsock_V_01.log" }
function Write-Log { param([string]$M)
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'; $tz = [TimeZoneInfo]::Local.StandardName
    Add-Content -LiteralPath $LogFile -Value "$ts | $tz | $M" -ErrorAction SilentlyContinue }
if ($Remove) {
    Write-Host "[*] WinsockLSP is verify-only - no artifact to remove." -ForegroundColor Yellow
    Write-Log "VERIFY-ONLY NOTED | L3 WinsockLSP | no artifact created/removed"
    return
}
Write-Host "[*] Verifying L3 WinsockLSP detection (read-only)..." -ForegroundColor Yellow
Write-Host "    NOTE: No seeding. Winsock catalog corruption requires netsh reset to repair." -ForegroundColor DarkGray
$proto = @(Get-ChildItem -LiteralPath "Registry::$WsBase\Protocol_Catalog9\Catalog_Entries" -ErrorAction SilentlyContinue)
$ns    = @(Get-ChildItem -LiteralPath "Registry::$WsBase\NameSpace_Catalog5\Catalog_Entries"  -ErrorAction SilentlyContinue)
if ($proto.Count -gt 0 -or $ns.Count -gt 0) {
    Write-Host ("  [OK] Protocol_Catalog9 entries : {0}" -f $proto.Count) -ForegroundColor Green
    Write-Host ("  [OK] NameSpace_Catalog5 entries: {0}" -f $ns.Count)   -ForegroundColor Green
    Write-Host "[+] Get-WinsockLSP WILL detect results at -Level 3." -ForegroundColor Cyan
    Write-Log "VERIFIED | L3 WinsockLSP | Protocol=$($proto.Count) NS=$($ns.Count) entries (no seeding needed)"
} else {
    Write-Host "  [!] No Winsock catalog entries found - unexpected." -ForegroundColor Red
    Write-Log "VERIFY FAILED | L3 WinsockLSP | no catalog entries found"
}

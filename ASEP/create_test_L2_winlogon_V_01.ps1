# ***************************************************************************
# *  Script      : create_test_L2_winlogon_V_01.ps1
# *  Version     : V_01
# *  Last Update : 2026-07-31 07:34 EST
# *  Purpose     : Level 2 verify-only check for Get-WinlogonEntries.
# *
# *  WHY NO SEEDING:
# *    HKLM Winlogon always contains Shell=explorer.exe and
# *    Userinit=userinit.exe, on every normal Windows installation. The
# *    collector will ALWAYS return results without seeding. Modifying either
# *    value - or adding a Shell/Userinit override in HKCU - risks an
# *    unusable logon session. This script verifies those values are present
# *    and the collector will detect them; no modification is made.
# *
# *  Admin       : NOT required (read-only).
# *  Logging     : Appends to create_test_L2_winlogon_V_01.log beside script.
# *  Options     : (default) Verify  |  -Remove (cleans log note)  |  -WhatIf
# * Copyright (c) 2026, Don Murdoch, Blue Team Handbook
# ***************************************************************************
[CmdletBinding(SupportsShouldProcess=$true)]
param([switch]$Remove)

$WinlogonKey = "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
$WinlogonReg = "Registry::$WinlogonKey"
$ExpectedValues = @("Userinit","Shell")
$LogFile = if ($PSCommandPath) { $PSCommandPath -replace '\.ps1$','.log' } else { "create_test_L2_winlogon_V_01.log" }

function Write-Log { param([string]$M)
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'; $tz = [TimeZoneInfo]::Local.StandardName
    Add-Content -LiteralPath $LogFile -Value "$ts | $tz | $M" -ErrorAction SilentlyContinue }

if ($Remove) {
    Write-Host "[*] L2 Winlogon is verify-only - no artifact to remove." -ForegroundColor Yellow
    Write-Host "    HKLM Winlogon values were not modified; nothing to clean up." -ForegroundColor Gray
    if ($PSCmdlet.ShouldProcess($LogFile,"Log verification removal")) {
        Write-Log "VERIFY-ONLY NOTED | L2 WinlogonEntries | no artifact created/removed"
    }
    return
}

Write-Host "[*] Verifying L2 WinlogonEntries detection (read-only)..." -ForegroundColor Yellow
Write-Host "    NOTE: No seeding performed. HKLM Winlogon always has Shell/Userinit." -ForegroundColor DarkGray

$key = Get-Item -LiteralPath $WinlogonReg -ErrorAction SilentlyContinue
$allPresent = $true
foreach ($vname in $ExpectedValues) {
    if ($key -and $key.Property -contains $vname) {
        $val = $key.GetValue($vname)
        Write-Host ("  [OK] {0,-12} = {1}" -f $vname, $val) -ForegroundColor Green
    } else {
        Write-Host "  [!!] $vname not found - unexpected on this system" -ForegroundColor Red
        $allPresent = $false
    }
}

if ($allPresent) {
    Write-Host "[+] Winlogon values confirmed present. Get-WinlogonEntries will detect them at -Level 2." -ForegroundColor Cyan
    Write-Log "VERIFIED | L2 WinlogonEntries | HKLM Winlogon Shell+Userinit confirmed present (no seeding needed)"
} else {
    Write-Host "[!] One or more expected Winlogon values missing - investigate." -ForegroundColor Red
    Write-Log "VERIFY FAILED | L2 WinlogonEntries | expected values missing from HKLM Winlogon"
}

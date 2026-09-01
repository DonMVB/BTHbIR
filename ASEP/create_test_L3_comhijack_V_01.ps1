#Requires -RunAsAdministrator
# ***************************************************************************
# *  Script      : create_test_L3_comhijack_V_01.ps1
# *  Version     : V_01
# *  Last Update : 2026-07-31 07:34 EST
# *  Purpose     : Level 3 synthetic check for Get-COMHijacks.
# *                Plants a synthetic CLSID in BOTH HKLM (stand-in legitimate
# *                registration) and HKCU (the per-user hijack override), both
# *                InprocServer32 values pointing at NON-EXISTENT DLLs. The
# *                analyzer reports it with ShadowsHKLM=True. Nothing loads.
# *  Admin       : REQUIRED (HKLM write for stand-in registration).
# *  Logging     : Appends to create_test_L3_comhijack_V_01.log beside script.
# *  Options     : (default) Create  |  -Remove  |  -WhatIf
# * Copyright (c) 2026, Don Murdoch, Blue Team Handbook
# ***************************************************************************
[CmdletBinding(SupportsShouldProcess=$true)]
param([switch]$Remove)

$Clsid        = '{CCCCCCCC-0312-4312-8312-CCCCCCCCCCCC}'
$FriendlyName = 'ASEP Synthetic Level 3 COM Hijack (safe to delete)'
$HklmKey      = "HKLM\SOFTWARE\Classes\CLSID\$Clsid"
$HkcuKey      = "HKCU\SOFTWARE\Classes\CLSID\$Clsid"
$HklmDll      = 'C:\ASEP_SyntheticCheck\legit_com_l3.dll'    # non-existent
$HkcuDll      = 'C:\ASEP_SyntheticCheck\hijack_com_l3.dll'   # non-existent
$LogFile      = if ($PSCommandPath) { $PSCommandPath -replace '\.ps1$','.log' } else { "create_test_L3_comhijack_V_01.log" }

function Write-Log { param([string]$M)
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'; $tz = [TimeZoneInfo]::Local.StandardName
    Add-Content -LiteralPath $LogFile -Value "$ts | $tz | $M" -ErrorAction SilentlyContinue }

if ($Remove) {
    Write-Host "[*] Removing L3 COM hijack synthetic check..." -ForegroundColor Yellow
    $removed = $false
    foreach ($k in @("Registry::$HkcuKey","Registry::$HklmKey")) {
        if (Test-Path -LiteralPath $k) {
            if ($PSCmdlet.ShouldProcess($k,"Remove CLSID key")) {
                Remove-Item -LiteralPath $k -Recurse -Force
                Write-Host "  [+] Removed $k" -ForegroundColor Green; $removed = $true }
        } else { Write-Host "  [-] Not present: $k" -ForegroundColor Gray }
    }
    if ($removed) { Write-Log "REMOVED | L3 COMHijacks | CLSID $Clsid (HKLM+HKCU)" }
    return
}

Write-Host "[*] Creating L3 COM hijack synthetic check..." -ForegroundColor Yellow
if (Test-Path -LiteralPath "Registry::$HkcuKey") { Write-Warning "HKCU key already present. Run -Remove first."; return }
if (-not $PSCmdlet.ShouldProcess($Clsid,"Create HKLM stand-in + HKCU override")) { return }

foreach ($pair in @(
    @{ Key=$HklmKey; Dll=$HklmDll; Label="HKLM stand-in (legitimate)" },
    @{ Key=$HkcuKey; Dll=$HkcuDll; Label="HKCU override (hijack)" })) {
    $inproc = "$($pair.Key)\InprocServer32"
    New-Item -Path "Registry::$inproc" -Force | Out-Null
    Set-Item  -LiteralPath "Registry::$($pair.Key)" -Value $FriendlyName
    Set-Item  -LiteralPath "Registry::$inproc"      -Value $pair.Dll
    New-ItemProperty -LiteralPath "Registry::$inproc" -Name "ThreadingModel" -Value "Apartment" -PropertyType String -Force | Out-Null
    Write-Host "  [+] $($pair.Label): $($pair.Key)" -ForegroundColor Green
}
Write-Log "ENABLED | L3 COMHijacks | CLSID $Clsid HKCU=$HkcuDll shadows HKLM=$HklmDll"
Write-Host "[+] Run analyzer at -Level 3; look for CLSID '$Clsid' in COM Hijacking (ShadowsHKLM=True)." -ForegroundColor Cyan
Write-Host "    Remove: .\create_test_L3_comhijack_V_01.ps1 -Remove" -ForegroundColor DarkGray

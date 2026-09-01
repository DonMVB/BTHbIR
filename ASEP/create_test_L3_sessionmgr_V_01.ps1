#Requires -RunAsAdministrator
# ***************************************************************************
# *  Script      : create_test_L3_sessionmgr_V_01.ps1
# *  Version     : V_01
# *  Last Update : 2026-07-31 07:34 EST
# *  Purpose     : Level 3 synthetic check for Get-SessionManagerEntries.
# *                Plants one AppCertDlls value pointing at a NON-EXISTENT DLL.
# *                AppCertDlls are loaded into EVERY CreateProcess caller, so
# *                REMOVE PROMPTLY - before any new process is launched if
# *                possible, and certainly before reboot.
# *  Admin       : REQUIRED (HKLM write).
# *  Logging     : Appends to create_test_L3_sessionmgr_V_01.log beside script.
# *  Options     : (default) Create  |  -Remove  |  -WhatIf
# * Copyright (c) 2026, Don Murdoch, Blue Team Handbook
# ***************************************************************************
[CmdletBinding(SupportsShouldProcess=$true)]
param([switch]$Remove)

$SmKey     = "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager"
$AcKey     = "$SmKey\AppCertDlls"
$AcReg     = "Registry::$AcKey"
$ValueName = "ASEP_Synthetic_L3_SessionMgr"
$FakeDll   = "C:\ASEP_SyntheticCheck\appcert_l3.dll"   # non-existent
$LogFile   = if ($PSCommandPath) { $PSCommandPath -replace '\.ps1$','.log' } else { "create_test_L3_sessionmgr_V_01.log" }

function Write-Log { param([string]$M)
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'; $tz = [TimeZoneInfo]::Local.StandardName
    Add-Content -LiteralPath $LogFile -Value "$ts | $tz | $M" -ErrorAction SilentlyContinue }

if ($Remove) {
    Write-Host "[*] Removing L3 SessionManager synthetic check..." -ForegroundColor Yellow
    if (Test-Path -LiteralPath $AcReg) {
        $k = Get-Item -LiteralPath $AcReg
        if ($k.Property -contains $ValueName) {
            if ($PSCmdlet.ShouldProcess("$AcKey :: $ValueName","Remove")) {
                Remove-ItemProperty -LiteralPath $AcReg -Name $ValueName -Force
                Write-Host "  [+] Removed $ValueName from AppCertDlls" -ForegroundColor Green
                Write-Log "REMOVED | L3 SessionManagerEntries | $AcKey\$ValueName"
            }
            # Remove the key itself if now empty
            $k2 = Get-Item -LiteralPath $AcReg
            if (@($k2.Property).Count -eq 0) { Remove-Item -LiteralPath $AcReg -Force }
        } else { Write-Host "  [-] Value not present" -ForegroundColor Gray }
    } else { Write-Host "  [-] AppCertDlls key not present" -ForegroundColor Gray }
    return
}

Write-Host "[*] Creating L3 SessionManager synthetic check (AppCertDlls)..." -ForegroundColor Yellow
Write-Host "    *** REMOVE PROMPTLY - AppCertDlls load into every new process ***" -ForegroundColor Red
if (-not (Test-Path -LiteralPath $AcReg)) { New-Item -Path $AcReg -Force | Out-Null }
if ((Get-Item -LiteralPath $AcReg).Property -contains $ValueName) {
    Write-Warning "Already present. Run -Remove first."; return }
if ($PSCmdlet.ShouldProcess("$AcKey :: $ValueName","Add AppCertDlls value")) {
    New-ItemProperty -LiteralPath $AcReg -Name $ValueName -Value $FakeDll -PropertyType String -Force | Out-Null
    Write-Host "  [+] Added $ValueName = $FakeDll" -ForegroundColor Green
    Write-Log "ENABLED | L3 SessionManagerEntries | $AcKey\$ValueName = $FakeDll (non-existent, but REMOVE PROMPTLY)"
}
Write-Host "[+] Run analyzer at -Level 3; look for 'AppCertDlls' in Session Manager." -ForegroundColor Cyan
Write-Host "    Remove PROMPTLY: .\create_test_L3_sessionmgr_V_01.ps1 -Remove" -ForegroundColor DarkGray

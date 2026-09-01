#Requires -RunAsAdministrator
# ***************************************************************************
# *  Script      : create_test_L3_activesetup_V_01.ps1
# *  Version     : V_01
# *  Last Update : 2026-07-31 07:34 EST
# *  Purpose     : Level 3 synthetic check for Get-ActiveSetupEntries.
# *                Plants a fake Active Setup component in HKLM. The StubPath
# *                points at a NON-EXISTENT binary. Active Setup runs the
# *                StubPath once per user on logon when the per-machine version
# *                is newer than the per-user record - since the binary doesn't
# *                exist the run silently fails. Remove before next logon.
# *  Admin       : REQUIRED (HKLM write).
# *  Logging     : Appends to create_test_L3_activesetup_V_01.log beside script.
# *  Options     : (default) Create  |  -Remove  |  -WhatIf
# * Copyright (c) 2026, Don Murdoch, Blue Team Handbook
# ***************************************************************************
[CmdletBinding(SupportsShouldProcess=$true)]
param([switch]$Remove)

$CompId  = '{ASEP0000-ACTI-4304-8304-ASEPSYNTH0001}'
$AsBase  = "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components"
$CompKey = "$AsBase\$CompId"
$CompReg = "Registry::$CompKey"
$StubPath= "C:\ASEP_SyntheticCheck\active_setup_l3.exe"   # non-existent
$LogFile = if ($PSCommandPath) { $PSCommandPath -replace '\.ps1$','.log' } else { "create_test_L3_activesetup_V_01.log" }

function Write-Log { param([string]$M)
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'; $tz = [TimeZoneInfo]::Local.StandardName
    Add-Content -LiteralPath $LogFile -Value "$ts | $tz | $M" -ErrorAction SilentlyContinue }

if ($Remove) {
    Write-Host "[*] Removing L3 ActiveSetup synthetic check..." -ForegroundColor Yellow
    if (Test-Path -LiteralPath $CompReg) {
        if ($PSCmdlet.ShouldProcess($CompKey,"Remove Active Setup component")) {
            Remove-Item -LiteralPath $CompReg -Recurse -Force
            Write-Host "  [+] Removed $CompKey" -ForegroundColor Green
            Write-Log "REMOVED | L3 ActiveSetupEntries | $CompKey"
        }
    } else { Write-Host "  [-] Not present" -ForegroundColor Gray }
    return
}

Write-Host "[*] Creating L3 ActiveSetup synthetic check..." -ForegroundColor Yellow
if (Test-Path -LiteralPath $CompReg) { Write-Warning "Already present. Run -Remove first."; return }
if ($PSCmdlet.ShouldProcess($CompKey,"Create Active Setup component")) {
    New-Item -Path $CompReg -Force | Out-Null
    New-ItemProperty -LiteralPath $CompReg -Name "(Default)"  -Value "ASEP Synthetic Active Setup (safe to delete)" -PropertyType String -Force | Out-Null
    New-ItemProperty -LiteralPath $CompReg -Name "StubPath"   -Value $StubPath   -PropertyType String -Force | Out-Null
    New-ItemProperty -LiteralPath $CompReg -Name "Version"    -Value "1,0,0,0"   -PropertyType String -Force | Out-Null
    Write-Host "  [+] Created $CompKey" -ForegroundColor Green
    Write-Host "      StubPath = $StubPath" -ForegroundColor Green
    Write-Log "ENABLED | L3 ActiveSetupEntries | $CompKey StubPath=$StubPath"
}
Write-Host "[+] Run analyzer at -Level 3; look for ComponentID '$CompId' in Active Setup." -ForegroundColor Cyan
Write-Host "    Remove BEFORE next logon: .\create_test_L3_activesetup_V_01.ps1 -Remove" -ForegroundColor DarkGray

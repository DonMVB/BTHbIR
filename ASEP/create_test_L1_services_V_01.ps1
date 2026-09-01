#Requires -RunAsAdministrator
# ***************************************************************************
# *  Script      : create_test_L1_services_V_01.ps1
# *  Version     : V_01
# *  Last Update : 2026-07-31 07:34 EST
# *  Purpose     : Level 1 synthetic check for Get-AutoStartServices.
# *                Registers a synthetic Windows service (Start=Disabled, binary
# *                path is non-existent) so the analyzer lists it. The service
# *                will NEVER start automatically. Remove before reboot.
# *  Admin       : REQUIRED (service registration).
# *  Logging     : Appends to create_test_L1_services_V_01.log beside script.
# *  Options     : (default) Create  |  -Remove  |  -WhatIf
# * Copyright (c) 2026, Don Murdoch, Blue Team Handbook
# ***************************************************************************
[CmdletBinding(SupportsShouldProcess=$true)]
param([switch]$Remove)

$SvcName   = "ASEP_Synthetic_L1_Svc"
$SvcDisp   = "ASEP Synthetic Level 1 Service (safe to delete)"
$BinPath   = "C:\ASEP_SyntheticCheck\svc_synthetic_l1.exe"   # non-existent
$LogFile   = if ($PSCommandPath) { $PSCommandPath -replace '\.ps1$','.log' } else { "create_test_L1_services_V_01.log" }

function Write-Log { param([string]$M)
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'; $tz = [TimeZoneInfo]::Local.StandardName
    Add-Content -LiteralPath $LogFile -Value "$ts | $tz | $M" -ErrorAction SilentlyContinue }

if ($Remove) {
    Write-Host "[*] Removing L1 Services synthetic check ($SvcName)..." -ForegroundColor Yellow
    $svc = Get-Service -Name $SvcName -ErrorAction SilentlyContinue
    if ($svc) {
        if ($PSCmdlet.ShouldProcess($SvcName,"Delete service")) {
            sc.exe delete $SvcName | Out-Null
            Write-Host "  [+] Deleted service $SvcName" -ForegroundColor Green
            Write-Log "REMOVED | L1 Services | service $SvcName"
        }
    } else { Write-Host "  [-] Service not present" -ForegroundColor Gray }
    return
}

Write-Host "[*] Creating L1 Services synthetic check..." -ForegroundColor Yellow
if (Get-Service -Name $SvcName -ErrorAction SilentlyContinue) {
    Write-Warning "Service '$SvcName' already exists. Run -Remove first."; return }
if ($PSCmdlet.ShouldProcess($SvcName,"Create disabled service")) {
    $result = sc.exe create $SvcName binPath= $BinPath DisplayName= $SvcDisp start= disabled 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  [+] Registered service '$SvcName' (Disabled, binary non-existent)" -ForegroundColor Green
        Write-Log "ENABLED | L1 Services | service $SvcName binPath=$BinPath Start=Disabled"
    } else {
        Write-Warning "sc.exe create failed: $result"; return
    }
}
Write-Host "[+] Run analyzer at -Level 1; look for '$SvcName' in Services (StartMode=Disabled)." -ForegroundColor Cyan
Write-Host "    Remove: .\create_test_L1_services_V_01.ps1 -Remove" -ForegroundColor DarkGray

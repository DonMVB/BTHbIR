# ***************************************************************************
# *  Script      : create_test_L3_shellext_V_01.ps1
# *  Version     : V_01
# *  Last Update : 2026-07-31 07:34 EST
# *  Purpose     : Level 3 synthetic check for Get-ShellExtensions.
# *                Plants a ContextMenuHandler under HKCU\SOFTWARE\Classes\*
# *                (the all-files class). HKCU shell extensions load into
# *                explorer per-user without admin. The CLSID is synthetic and
# *                the DLL is non-existent, so nothing loads.
# *  Admin       : NOT required (HKCU only).
# *  Logging     : Appends to create_test_L3_shellext_V_01.log beside script.
# *  Options     : (default) Create  |  -Remove  |  -WhatIf
# * Copyright (c) 2026, Don Murdoch, Blue Team Handbook
# ***************************************************************************
[CmdletBinding(SupportsShouldProcess=$true)]
param([switch]$Remove)

$Clsid      = '{FFFFFFFF-0003-4303-8303-FFFFFFFFFFFF}'
$HandlerKey = "HKCU\SOFTWARE\Classes\*\shellex\ContextMenuHandlers\ASEP_Synthetic_L3_Shell"
$HandlerReg = "Registry::$HandlerKey"
$ClsidKey   = "HKCU\SOFTWARE\Classes\CLSID\$Clsid\InprocServer32"
$ClsidReg   = "Registry::$ClsidKey"
$FakeDll    = "C:\ASEP_SyntheticCheck\shell_ext_l3.dll"    # non-existent
$LogFile    = if ($PSCommandPath) { $PSCommandPath -replace '\.ps1$','.log' } else { "create_test_L3_shellext_V_01.log" }

function Write-Log { param([string]$M)
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'; $tz = [TimeZoneInfo]::Local.StandardName
    Add-Content -LiteralPath $LogFile -Value "$ts | $tz | $M" -ErrorAction SilentlyContinue }

if ($Remove) {
    Write-Host "[*] Removing L3 ShellExtensions synthetic check..." -ForegroundColor Yellow
    foreach ($r in @($HandlerReg, "Registry::HKCU\SOFTWARE\Classes\CLSID\$Clsid")) {
        if (Test-Path -LiteralPath $r) {
            if ($PSCmdlet.ShouldProcess($r,"Remove")) {
                Remove-Item -LiteralPath $r -Recurse -Force
                Write-Host "  [+] Removed $r" -ForegroundColor Green
            }
        }
    }
    Write-Log "REMOVED | L3 ShellExtensions | $HandlerKey + CLSID $Clsid"
    return
}

Write-Host "[*] Creating L3 ShellExtensions synthetic check..." -ForegroundColor Yellow
if (Test-Path -LiteralPath $HandlerReg) { Write-Warning "Already present. Run -Remove first."; return }
if (-not $PSCmdlet.ShouldProcess($HandlerKey,"Create ContextMenuHandler + CLSID registration")) { return }

# ContextMenuHandler entry (default value = CLSID)
New-Item -Path $HandlerReg -Force | Out-Null
Set-Item  -LiteralPath $HandlerReg -Value $Clsid
Write-Host "  [+] Created handler: $HandlerKey = $Clsid" -ForegroundColor Green

# CLSID registration with non-existent DLL so the analyzer can resolve a module
New-Item -Path $ClsidReg -Force | Out-Null
Set-Item  -LiteralPath $ClsidReg -Value $FakeDll
New-ItemProperty -LiteralPath $ClsidReg -Name "ThreadingModel" -Value "Apartment" -PropertyType String -Force | Out-Null
Write-Host "  [+] Created CLSID InprocServer32: $ClsidKey = $FakeDll" -ForegroundColor Green

Write-Log "ENABLED | L3 ShellExtensions | $HandlerKey (CLSID=$Clsid, DLL=$FakeDll)"
Write-Host "[+] Run analyzer at -Level 3; look for 'ASEP_Synthetic_L3_Shell' in Shell Extensions (Hive=HKCU, Class=*)." -ForegroundColor Cyan
Write-Host "    Remove: .\create_test_L3_shellext_V_01.ps1 -Remove" -ForegroundColor DarkGray

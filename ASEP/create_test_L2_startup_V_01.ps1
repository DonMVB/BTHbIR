# ***************************************************************************
# *  Script      : create_test_L2_startup_V_01.ps1
# *  Version     : V_01
# *  Last Update : 2026-07-31 07:34 EST
# *  Purpose     : Level 2 synthetic check for Get-StartupFolderItems.
# *                Drops a .lnk shortcut (-> notepad.exe) in the current user's
# *                Startup folder. Notepad WILL launch at next logon - remove
# *                when done. Run this and the analyzer as the SAME user.
# *  Admin       : NOT required (user Startup folder only).
# *  Logging     : Appends to create_test_L2_startup_V_01.log beside script.
# *  Options     : (default) Create  |  -Remove  |  -WhatIf
# * Copyright (c) 2026, Don Murdoch, Blue Team Handbook
# ***************************************************************************
[CmdletBinding(SupportsShouldProcess=$true)]
param([switch]$Remove)

$StartupDir = [Environment]::GetFolderPath('Startup')
$LnkName    = "ASEP_Synthetic_L2_Startup.lnk"
$LnkPath    = Join-Path $StartupDir $LnkName
$Target     = Join-Path $env:SystemRoot 'System32\notepad.exe'
$LogFile    = if ($PSCommandPath) { $PSCommandPath -replace '\.ps1$','.log' } else { "create_test_L2_startup_V_01.log" }

function Write-Log { param([string]$M)
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'; $tz = [TimeZoneInfo]::Local.StandardName
    Add-Content -LiteralPath $LogFile -Value "$ts | $tz | $M" -ErrorAction SilentlyContinue }

if ($Remove) {
    Write-Host "[*] Removing L2 StartupFolder synthetic check..." -ForegroundColor Yellow
    if (Test-Path -LiteralPath $LnkPath) {
        if ($PSCmdlet.ShouldProcess($LnkPath,"Delete shortcut")) {
            Remove-Item -LiteralPath $LnkPath -Force
            Write-Host "  [+] Removed $LnkPath" -ForegroundColor Green
            Write-Log "REMOVED | L2 StartupFolderItems | $LnkPath"
        }
    } else { Write-Host "  [-] Not present: $LnkPath" -ForegroundColor Gray }
    return
}

Write-Host "[*] Creating L2 StartupFolder synthetic check..." -ForegroundColor Yellow
if ([string]::IsNullOrEmpty($StartupDir) -or -not (Test-Path -LiteralPath $StartupDir)) {
    Write-Error "Cannot resolve user Startup folder."; return }
if (Test-Path -LiteralPath $LnkPath) {
    Write-Warning "Already exists. Run -Remove first."; return }
if ($PSCmdlet.ShouldProcess($LnkPath,"Create shortcut -> $Target")) {
    $shell = New-Object -ComObject WScript.Shell
    try {
        $sc = $shell.CreateShortcut($LnkPath)
        $sc.TargetPath  = $Target
        $sc.Description = "ASEP synthetic Level 2 check (safe to delete)"
        $sc.Save()
        Write-Host "  [+] Created $LnkPath -> $Target" -ForegroundColor Green
        Write-Log "ENABLED | L2 StartupFolderItems | $LnkPath -> $Target"
    } finally { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($shell) }
}
Write-Host "[+] Run analyzer at -Level 2; look for '$LnkName' in Startup Folders (Scope=User)." -ForegroundColor Cyan
Write-Host "    Remove: .\create_test_L2_startup_V_01.ps1 -Remove" -ForegroundColor DarkGray

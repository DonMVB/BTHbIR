#Requires -RunAsAdministrator

# ***************************************************************************
# *  Script      : create_test_modernapp_startup_V_01.ps1
# *  Version     : V_01
# *  Last Update : 2026-07-30 08:15 EST
# *  Purpose     : Creates (or removes) a single, deliberately harmless
# *                Modern/UWP startup-task registry artifact so you can verify
# *                that asep_analyzer (v2.05+, Get-ModernAppEntries) detects it.
# *
# *  IMPORTANT   : This writes only registry METADATA under a made-up package
# *                family that no installed app uses. There is no real package
# *                or executable behind it, so NOTHING can ever launch - the
# *                artifact is completely inert.
# *
# *                Run this in the SAME context (elevated, same user) as the
# *                analyzer. The value lives under HKCU; running both elevated
# *                as the same account guarantees they share one HKCU hive.
# *
# *  Command-line options:
# *     (no switch)   Create the test UWP startup-task state key.
# *     -Remove       Delete the test package key (and its task).
# *     -WhatIf       Show what would happen without making changes.
# * Copyright (c) 2026, Don Murdoch, Blue Team Handbook
# ***************************************************************************

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$Remove
)

# ---------------------------------------------------------------------------
# WHAT A UWP STARTUP TASK IS (and what the analyzer looks for)
# ---------------------------------------------------------------------------
# Packaged (UWP/MSIX) apps can declare a windows.startupTask that launches the
# app at logon. Its enable/disable STATE is stored per-user at:
#   HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\
#       CurrentVersion\AppModel\SystemAppData\<PackageFamily>\<TaskId>\State
# The analyzer enumerates that tree and reports each task key that carries a
# State value (State 2 = Enabled in the best-effort mapping).
#
# We create a fake <PackageFamily>\<TaskId> with State = 2. Because no real
# package is registered under this family name, Windows has nothing to launch;
# the key is inert metadata that exists only for the scanner to find.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# CONFIG - a distinctive, obviously-synthetic package family and task
# ---------------------------------------------------------------------------
$Base      = "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData"
$PkgFamily = "ASEP.SyntheticCheck_0000000000000"
$TaskId    = "ASEP_Synthetic_StartupTask"
$PkgKey    = "$Base\$PkgFamily"
$TaskKey   = "$PkgKey\$TaskId"
$State     = 2   # 2 = Enabled (best-effort StartupTaskState mapping)

# ===========================================================================
# REMOVE MODE
# ===========================================================================
if ($Remove) {
    Write-Host "[*] Removing synthetic UWP startup task ($PkgFamily)..." -ForegroundColor Yellow

    $reg = "Registry::$PkgKey"
    if (Test-Path $reg) {
        if ($PSCmdlet.ShouldProcess($PkgKey, "Remove synthetic package key")) {
            Remove-Item -Path $reg -Recurse -Force
            Write-Host "  [+] Removed $PkgKey" -ForegroundColor Green
        }
    } else {
        Write-Host "  [-] Not present: $PkgKey" -ForegroundColor Gray
    }

    Write-Host "[+] Cleanup complete." -ForegroundColor Cyan
    return
}

# ===========================================================================
# CREATE MODE
# ===========================================================================
Write-Host "[*] Creating synthetic UWP startup-task state key..." -ForegroundColor Yellow

# Refuse to stack duplicates.
if (Test-Path "Registry::$TaskKey") {
    Write-Warning "$TaskKey already exists. Run with -Remove first for a clean re-create."
    return
}

if (-not $PSCmdlet.ShouldProcess($TaskKey, "Create UWP startup-task state (State=$State)")) {
    return
}

New-Item -Path "Registry::$TaskKey" -Force | Out-Null
New-ItemProperty -Path "Registry::$TaskKey" -Name "State" -Value $State -PropertyType DWord -Force | Out-Null
Write-Host "  [+] Created $TaskKey (State=$State)" -ForegroundColor Green

# --- Read back so you can confirm it is really there -----------------------
Write-Host ""
Write-Host "[*] Verifying..." -ForegroundColor Yellow
Get-ItemProperty -Path "Registry::$TaskKey" -Name "State" | Select-Object -Property State | Format-List

Write-Host "[+] Done. Run asep_analyzer at -Level 3; look in the Modern Apps" -ForegroundColor Cyan
Write-Host "    category for package '$PkgFamily' / task '$TaskId' (Enabled)." -ForegroundColor Cyan
Write-Host "    When finished testing, remove it with:" -ForegroundColor DarkGray
Write-Host "      .\create_test_modernapp_startup_V_01.ps1 -Remove" -ForegroundColor DarkGray

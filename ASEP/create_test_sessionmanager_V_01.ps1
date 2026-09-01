#Requires -RunAsAdministrator

# ***************************************************************************
# *  Script      : create_test_sessionmanager_V_01.ps1
# *  Version     : V_01
# *  Last Update : 2026-07-30 08:15 EST
# *  Purpose     : Creates (or removes) a single, deliberately harmless
# *                Session Manager AppCertDlls entry so you can verify that
# *                asep_analyzer (v2.04+, Get-SessionManagerEntries) detects it.
# *
# *  IMPORTANT   : AppCertDlls is loaded into EVERY process that calls
# *                CreateProcess/WinExec/etc. This test value points at a
# *                NON-EXISTENT DLL, so the load attempt fails and nothing runs.
# *                Even so, this is the one artifact here with system-wide
# *                reach - REMOVE IT PROMPTLY after scanning, and before reboot.
# *                Only the AppCertDlls value we add is touched; the risky
# *                Execute / SetupExecute / S0InitialCommand /
# *                PendingFileRenameOperations values are deliberately NOT
# *                seeded (they carry boot-time execution or clobber risk).
# *
# *  Command-line options:
# *     (no switch)   Create the test AppCertDlls value.
# *     -Remove       Delete the test AppCertDlls value.
# *     -WhatIf       Show what would happen without making changes.
# * Copyright (c) 2026, Don Murdoch, Blue Team Handbook
# ***************************************************************************

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$Remove
)

# ---------------------------------------------------------------------------
# WHAT APPCERTDLLS IS (and why it is a persistence / injection ASEP)
# ---------------------------------------------------------------------------
# Any DLL listed under
#     HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls
# is loaded by apphelp into EVERY process that calls CreateProcess,
# CreateProcessAsUser, CreateProcessWithLoginW/TokenW, or WinExec. That makes
# it a classic code-injection + persistence point (MITRE T1546.009).
#
# We add ONE clearly-named value pointing at a fake, non-existent DLL. Windows
# will try to LoadLibrary it on the next process creation and simply fail
# (missing file), so no code executes - but the registry ARTIFACT is present
# for the scanner to find. A real attacker would point this at a real DLL.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# CONFIG - one clearly-named value pointing at a non-existent DLL
# ---------------------------------------------------------------------------
$SmKey     = "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager"
$AcKey     = "$SmKey\AppCertDlls"
$ValueName = "ASEP_SyntheticCheck"
$FakeDll   = 'C:\ASEP_SyntheticCheck\appcert_synthetic_2004.dll'   # non-existent

# ===========================================================================
# REMOVE MODE
# ===========================================================================
if ($Remove) {
    Write-Host "[*] Removing synthetic AppCertDlls value ($ValueName)..." -ForegroundColor Yellow

    $reg = "Registry::$AcKey"
    if (Test-Path $reg) {
        $key = Get-Item -Path $reg
        if ($key.Property -contains $ValueName) {
            if ($PSCmdlet.ShouldProcess("$AcKey :: $ValueName", "Remove value")) {
                Remove-ItemProperty -Path $reg -Name $ValueName -Force
                Write-Host "  [+] Removed value $ValueName" -ForegroundColor Green
            }
        } else {
            Write-Host "  [-] Value not present: $ValueName" -ForegroundColor Gray
        }

        # Clean up the AppCertDlls key itself only if WE left it empty.
        $key = Get-Item -Path $reg
        if (@($key.Property).Count -eq 0 -and @(Get-ChildItem -Path $reg -ErrorAction SilentlyContinue).Count -eq 0) {
            if ($PSCmdlet.ShouldProcess($AcKey, "Remove empty AppCertDlls key")) {
                Remove-Item -Path $reg -Force
                Write-Host "  [+] Removed now-empty AppCertDlls key" -ForegroundColor Green
            }
        }
    } else {
        Write-Host "  [-] AppCertDlls key not present" -ForegroundColor Gray
    }

    Write-Host "[+] Cleanup complete." -ForegroundColor Cyan
    return
}

# ===========================================================================
# CREATE MODE
# ===========================================================================
Write-Host "[*] Creating synthetic AppCertDlls value..." -ForegroundColor Yellow

# Create the AppCertDlls key if it does not already exist.
$reg = "Registry::$AcKey"
if (-not (Test-Path $reg)) {
    if (-not $PSCmdlet.ShouldProcess($AcKey, "Create AppCertDlls key")) { return }
    New-Item -Path $reg -Force | Out-Null
}

# Refuse to stack duplicates.
$key = Get-Item -Path $reg
if ($key.Property -contains $ValueName) {
    Write-Warning "$AcKey already has a '$ValueName' value. Run with -Remove first for a clean re-create."
    return
}

if ($PSCmdlet.ShouldProcess("$AcKey :: $ValueName", "Add value -> $FakeDll")) {
    New-ItemProperty -Path $reg -Name $ValueName -Value $FakeDll -PropertyType String -Force | Out-Null
    Write-Host "  [+] Added $ValueName = $FakeDll" -ForegroundColor Green
}

# --- Read back so you can confirm it is really there -----------------------
Write-Host ""
Write-Host "[*] Verifying..." -ForegroundColor Yellow
Get-ItemProperty -Path $reg -Name $ValueName | Select-Object -Property $ValueName | Format-List

Write-Host "[+] Done. Run asep_analyzer at -Level 3; look in the Session Manager" -ForegroundColor Cyan
Write-Host "    category for AppCertDlls value '$ValueName'." -ForegroundColor Cyan
Write-Host "    REMOVE IT PROMPTLY (system-wide reach) with:" -ForegroundColor DarkGray
Write-Host "      .\create_test_sessionmanager_V_01.ps1 -Remove" -ForegroundColor DarkGray

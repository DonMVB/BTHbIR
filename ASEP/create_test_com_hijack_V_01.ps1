#Requires -RunAsAdministrator

# ***************************************************************************
# *  Script      : create_test_com_hijack_V_01.ps1
# *  Version     : V_01
# *  Last Update : 2026-07-30 08:15 EST
# *  Purpose     : Creates (or removes) a single, deliberately harmless
# *                per-user COM CLSID override so you can verify that
# *                asep_analyzer (v2.03+, Get-COMHijacks) detects a COM hijack,
# *                including the ShadowsHKLM=True signal.
# *
# *  IMPORTANT   : Uses a SYNTHETIC, made-up CLSID that no real software uses.
# *                A matching HKLM registration is created ONLY so the per-user
# *                entry has something to "shadow" (mimicking the real attack
# *                pattern). Both InprocServer32 values point at NON-EXISTENT
# *                DLLs, so nothing is ever loaded - the artifact is inert. No
# *                real COM object is modified.
# *
# *  Command-line options:
# *     (no switch)   Create the test COM hijack (HKLM base + HKCU override).
# *     -Remove       Delete both the HKLM and HKCU test CLSID keys.
# *     -WhatIf       Show what would happen without making changes.
# * Copyright (c) 2026, Don Murdoch, Blue Team Handbook
# ***************************************************************************

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$Remove
)

# ---------------------------------------------------------------------------
# WHAT A COM HIJACK IS (and why we create two keys)
# ---------------------------------------------------------------------------
# Windows resolves a COM CLSID from the PER-USER store
#     HKCU\Software\Classes\CLSID\{guid}
# BEFORE the PER-MACHINE store
#     HKLM\Software\Classes\CLSID\{guid}.
# An attacker who writes a per-user InprocServer32 for a CLSID that a process
# loads gets THEIR DLL loaded instead of the legitimate one - no admin needed.
#
# To mimic that artifact safely we:
#   1. Create an HKLM CLSID (the stand-in "legitimate machine registration").
#   2. Create the SAME CLSID under HKCU (the "hijack" that shadows it).
# The analyzer sees the HKCU entry and, because the CLSID also exists in HKLM,
# reports ShadowsHKLM = True. Both DLL paths are fake/non-existent, so no code
# ever runs. A real attacker would only need step 2, against a REAL CLSID.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# CONFIG - a distinctive, obviously-synthetic CLSID and fake DLL paths
# ---------------------------------------------------------------------------
$Clsid        = '{AAAAAAAA-0203-4203-8203-AAAAAAAAAAAA}'
$FriendlyName = 'ASEP Synthetic Check - COM Hijack (safe to delete)'
$HklmClsidKey = "HKLM\SOFTWARE\Classes\CLSID\$Clsid"
$HkcuClsidKey = "HKCU\SOFTWARE\Classes\CLSID\$Clsid"
$HklmDll      = 'C:\ASEP_SyntheticCheck\legit_com_2003.dll'    # non-existent
$HkcuDll      = 'C:\ASEP_SyntheticCheck\hijack_com_2003.dll'   # non-existent

# ===========================================================================
# REMOVE MODE
# ===========================================================================
if ($Remove) {
    Write-Host "[*] Removing synthetic COM hijack ($Clsid)..." -ForegroundColor Yellow

    foreach ($key in @($HkcuClsidKey, $HklmClsidKey)) {
        $reg = "Registry::$key"
        if (Test-Path $reg) {
            if ($PSCmdlet.ShouldProcess($key, "Remove CLSID key")) {
                Remove-Item -Path $reg -Recurse -Force
                Write-Host "  [+] Removed $key" -ForegroundColor Green
            }
        } else {
            Write-Host "  [-] Not present: $key" -ForegroundColor Gray
        }
    }

    Write-Host "[+] Cleanup complete." -ForegroundColor Cyan
    return
}

# ===========================================================================
# CREATE MODE
# ===========================================================================
Write-Host "[*] Creating synthetic COM hijack..." -ForegroundColor Yellow

# Refuse to stack duplicates.
if (Test-Path "Registry::$HkcuClsidKey") {
    Write-Warning "$HkcuClsidKey already exists. Run with -Remove first for a clean re-create."
    return
}

if (-not $PSCmdlet.ShouldProcess($Clsid, "Create HKLM base + HKCU override CLSID")) {
    return
}

# --- 1. The stand-in "legitimate" machine registration (HKLM) --------------
$hklmInproc = "$HklmClsidKey\InprocServer32"
New-Item -Path "Registry::$hklmInproc" -Force | Out-Null
Set-Item  -Path "Registry::$HklmClsidKey" -Value $FriendlyName
Set-Item  -Path "Registry::$hklmInproc"   -Value $HklmDll
New-ItemProperty -Path "Registry::$hklmInproc" -Name "ThreadingModel" -Value "Apartment" -PropertyType String -Force | Out-Null
Write-Host "  [+] Created HKLM CLSID (legitimate stand-in) : $HklmClsidKey" -ForegroundColor Green

# --- 2. The per-user "hijack" that shadows it (HKCU) -----------------------
$hkcuInproc = "$HkcuClsidKey\InprocServer32"
New-Item -Path "Registry::$hkcuInproc" -Force | Out-Null
Set-Item  -Path "Registry::$HkcuClsidKey" -Value $FriendlyName
Set-Item  -Path "Registry::$hkcuInproc"   -Value $HkcuDll
New-ItemProperty -Path "Registry::$hkcuInproc" -Name "ThreadingModel" -Value "Apartment" -PropertyType String -Force | Out-Null
Write-Host "  [+] Created HKCU CLSID (hijack override)      : $HkcuClsidKey" -ForegroundColor Green

# --- Read back so you can confirm it is really there -----------------------
Write-Host ""
Write-Host "[*] Verifying..." -ForegroundColor Yellow
Write-Host "  HKLM InprocServer32 : $((Get-Item "Registry::$hklmInproc").GetValue(''))"
Write-Host "  HKCU InprocServer32 : $((Get-Item "Registry::$hkcuInproc").GetValue(''))"

Write-Host "[+] Done. Run asep_analyzer at -Level 3; look in the COM Hijacking" -ForegroundColor Cyan
Write-Host "    category for CLSID $Clsid with ShadowsHKLM = True." -ForegroundColor Cyan
Write-Host "    When finished testing, remove it with:" -ForegroundColor DarkGray
Write-Host "      .\create_test_com_hijack_V_01.ps1 -Remove" -ForegroundColor DarkGray

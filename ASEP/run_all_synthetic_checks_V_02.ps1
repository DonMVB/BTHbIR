# ***************************************************************************
# *  Script      : run_all_synthetic_checks_V_02.ps1
# *  Version     : V_02
# *  Last Update : 2026-08-03 16:49 EST
# *  Purpose     : Enables or disables all 20 ASEP synthetic artifact checks
# *                by calling each create_test_*.ps1 in the same folder.
# *                Prompts E (Enable) / D (Disable) / Q (Quit), runs every
# *                script in level order, and writes a session log.
# *
# *                Replaces run_all_synthetic_checks_V_01.cmd. The batch
# *                version had cmd.exe parsing issues with empty arguments,
# *                %ERRORLEVEL% capture after PowerShell, and variable
# *                expansion inside if-blocks that silently dropped scripts.
# *
# *  Run as      : Administrator recommended. Seven scripts require admin
# *                for HKLM writes; those will report [FAIL] if not elevated.
# *
# *  All 20 create_test_*.ps1 scripts must be in the SAME FOLDER as this
# *  script. Missing scripts are reported as [SKIP] - not silently dropped.
# *
# *  Logging     : Appends a session summary to run_all_synthetic_checks_V_02.log
# *                beside this script. Each individual .ps1 also writes its
# *                own per-script .log file.
# *
# *  Command-line options:
# *     -Action <Enable|Disable>   Run non-interactively (no menu prompt)
# *     -ShowScriptOutput          Show each script's full console output
# *                                (suppressed by default for cleaner display)
# * Copyright (c) 2026, Don Murdoch, Blue Team Handbook
# ***************************************************************************

[CmdletBinding()]
param(
    [ValidateSet("Enable","Disable")]
    [string]$Action,
    [switch]$ShowScriptOutput
)

# ---------------------------------------------------------------------------
# SCRIPT REGISTRY  -  ordered list, one entry per collector
#   Type: Seeder      = creates/removes a synthetic artifact
#         Admin       = Seeder that requires elevation
#         Verify      = read-only; always returns results; not safe to seed
# ---------------------------------------------------------------------------
$ScriptDefs = [ordered]@{

    # ---- Level 1 -----------------------------------------------------------
    "create_test_L1_runkeys_V_01.ps1"      = @{ Label = "L1  Run Keys              "; Type = "Seeder" }
    "create_test_L1_services_V_01.ps1"     = @{ Label = "L1  Auto-Start Services   "; Type = "Admin"  }
    "create_test_L1_tasks_V_01.ps1"        = @{ Label = "L1  Scheduled Tasks       "; Type = "Seeder" }

    # ---- Level 2 -----------------------------------------------------------
    "create_test_L2_startup_V_01.ps1"      = @{ Label = "L2  Startup Folder Items  "; Type = "Seeder" }
    "create_test_L2_winlogon_V_01.ps1"     = @{ Label = "L2  Winlogon Entries      "; Type = "Verify" }

    # ---- Level 3 -----------------------------------------------------------
    "create_test_L3_wmi_V_01.ps1"          = @{ Label = "L3  WMI Subscriptions     "; Type = "Admin"  }
    "create_test_L3_bho_V_01.ps1"          = @{ Label = "L3  Browser Helper Objects"; Type = "Admin"  }
    "create_test_L3_shellext_V_01.ps1"     = @{ Label = "L3  Shell Extensions      "; Type = "Seeder" }
    "create_test_L3_activesetup_V_01.ps1"  = @{ Label = "L3  Active Setup          "; Type = "Admin"  }
    "create_test_L3_ifeo_V_01.ps1"         = @{ Label = "L3  IFEO Entries          "; Type = "Admin"  }
    "create_test_L3_bootexecute_V_01.ps1"  = @{ Label = "L3  Boot Execute          "; Type = "Verify" }
    "create_test_L3_psprofile_V_01.ps1"    = @{ Label = "L3  PowerShell Profiles   "; Type = "Seeder" }
    "create_test_L3_drivers_V_01.ps1"      = @{ Label = "L3  Auto-Start Drivers    "; Type = "Verify" }
    "create_test_L3_lsa_V_01.ps1"          = @{ Label = "L3  LSA Providers         "; Type = "Verify" }
    "create_test_L3_netproviders_V_01.ps1" = @{ Label = "L3  Network Providers     "; Type = "Verify" }
    "create_test_L3_winsock_V_01.ps1"      = @{ Label = "L3  Winsock LSP           "; Type = "Verify" }
    "create_test_L3_comhijack_V_01.ps1"    = @{ Label = "L3  COM Hijack            "; Type = "Admin"  }
    "create_test_L3_sessionmgr_V_01.ps1"   = @{ Label = "L3  Session Manager       "; Type = "Admin"  }
    "create_test_L3_modernapp_V_01.ps1"    = @{ Label = "L3  Modern/UWP Apps       "; Type = "Seeder" }
    "create_test_L3_knowndlls_V_01.ps1"    = @{ Label = "L3  Known DLLs            "; Type = "Verify" }
}

# ---------------------------------------------------------------------------
# PATHS AND LOGGING
# ---------------------------------------------------------------------------
$ScriptDir = Split-Path -Parent $PSCommandPath
$LogFile   = Join-Path $ScriptDir "run_all_synthetic_checks_V_02.log"

function Write-Log {
    param([string]$Message)
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $tz = [TimeZoneInfo]::Local.StandardName
    Add-Content -LiteralPath $LogFile -Value "$ts | $tz | $Message" -ErrorAction SilentlyContinue
}

# ---------------------------------------------------------------------------
# ELEVATION CHECK
# ---------------------------------------------------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host ""
    Write-Host "  *** WARNING: Not running as Administrator ***" -ForegroundColor Yellow
    Write-Host "  Scripts marked [admin] will fail without elevation." -ForegroundColor Yellow
    Write-Host "  Re-run this script elevated for full coverage." -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
# MENU  (skipped when -Action is supplied on the command line)
# ---------------------------------------------------------------------------
if (-not $Action) {
    $lastLevel = ""
    do {
        Write-Host ""
        Write-Host "  ==============================================================" -ForegroundColor Cyan
        Write-Host "    ASEP Synthetic Check Suite  |  All 20 Collectors  |  V_02"   -ForegroundColor Cyan
        Write-Host "  ==============================================================" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "    Runs each create_test_*.ps1 to seed or remove a synthetic"
        Write-Host "    artifact for every analyzer collector (Levels 1, 2, and 3)."
        Write-Host "    Verify-only collectors are queried but not modified."
        Write-Host ""

        # Show script inventory with type tags
        $currentLevel = ""
        foreach ($name in $ScriptDefs.Keys) {
            $def   = $ScriptDefs[$name]
            $level = $def.Label.Substring(0,2)    # "L1", "L2", or "L3"
            if ($level -ne $currentLevel) {
                Write-Host ("    ---- Level {0} ----" -f $level.Substring(1)) -ForegroundColor DarkGray
                $currentLevel = $level
            }
            $tag  = switch ($def.Type) {
                "Admin"  { " [admin]"        }
                "Verify" { " [verify-only]"  }
                default  { ""                }
            }
            $exists = Test-Path -LiteralPath (Join-Path $ScriptDir $name)
            $marker = if ($exists) { "  " } else { "??" }
            Write-Host ("    {0} {1}{2}" -f $marker, $def.Label.TrimEnd(), $tag) -ForegroundColor $(
                if (-not $exists) { "DarkGray" } else { "Gray" })
        }
        $missingCount = ($ScriptDefs.Keys | Where-Object { -not (Test-Path -LiteralPath (Join-Path $ScriptDir $_)) }).Count
        if ($missingCount -gt 0) {
            Write-Host ""
            Write-Host ("    ?? = {0} script(s) not found in this folder - will be reported as SKIP" -f $missingCount) -ForegroundColor DarkGray
        }
        Write-Host ""
        Write-Host "    E - Enable   (create all synthetic artifacts)" -ForegroundColor Green
        Write-Host "    D - Disable  (remove all synthetic artifacts)"  -ForegroundColor Yellow
        Write-Host "    Q - Quit"
        Write-Host ""

        $choice = (Read-Host "    Select action [E/D/Q]").Trim().ToUpper()

        if ($choice -eq "E") { $Action = "Enable"  ; break }
        if ($choice -eq "D") { $Action = "Disable" ; break }
        if ($choice -eq "Q") { Write-Host ""; Write-Host "  Exiting." ; return }

        Write-Host "  Please enter E, D, or Q." -ForegroundColor Red
    } while ($true)
}

# ---------------------------------------------------------------------------
# RUN ALL SCRIPTS
# ---------------------------------------------------------------------------
$psSwitch   = if ($Action -eq "Disable") { @("-Remove") } else { @() }
$actionDesc = if ($Action -eq "Enable") { "Enabling  (creating)" } else { "Disabling (removing)" }

Write-Host ""
Write-Host ("  [*] {0} all synthetic artifacts..." -f $actionDesc) -ForegroundColor Cyan
Write-Host ""

Write-Log ("SESSION START | $Action all 20 synthetic checks" + $(if (-not $isAdmin) { " (NOT ELEVATED)" } else { " (elevated)" }))

$counts = @{ OK = 0; FAIL = 0; SKIP = 0 }
$currentLevel = ""

foreach ($name in $ScriptDefs.Keys) {
    $def       = $ScriptDefs[$name]
    $scriptPath= Join-Path $ScriptDir $name
    $level     = $def.Label.Substring(0,2)

    # Print level divider when the level changes
    if ($level -ne $currentLevel) {
        Write-Host ("  ---- Level {0} {1}" -f $level.Substring(1), ("-" * 50)) -ForegroundColor DarkGray
        $currentLevel = $level
    }

    # Type tag for the display line
    $tag = switch ($def.Type) {
        "Admin"  { " [admin]"       }
        "Verify" { " [verify-only]" }
        default  { ""               }
    }

    # Check the script exists before trying to run it
    if (-not (Test-Path -LiteralPath $scriptPath)) {
        Write-Host ("  [SKIP]  {0}{1}  -- script not found in {2}" -f $def.Label, $tag, $ScriptDir) -ForegroundColor DarkGray
        $counts.SKIP++
        Write-Log "SKIP | $Action | $name | not found in $ScriptDir"
        continue
    }

    Write-Host ("  Running: {0}{1}" -f $def.Label, $tag) -ForegroundColor Gray

    # Execute as a subprocess via powershell.exe so each script is fully
    # isolated and we capture a reliable exit code. -NoNewWindow keeps output
    # in the current console. WMI script also needs powershell.exe (PS 5.1).
    try {
        $pArgs = @("-NonInteractive", "-NoProfile", "-ExecutionPolicy", "Bypass",
                   "-File", $scriptPath) + $psSwitch

        $proc = Start-Process -FilePath "powershell.exe" `
                              -ArgumentList $pArgs `
                              -NoNewWindow -Wait -PassThru `
                              -RedirectStandardOutput $(if ($ShowScriptOutput) { $null } else { "NUL" }) `
                              -ErrorAction Stop

        if ($proc.ExitCode -eq 0) {
            Write-Host "  [OK]"  -ForegroundColor Green
            $counts.OK++
            Write-Log "OK   | $Action | $name"
        } else {
            Write-Host ("  [FAIL]  exit code {0}" -f $proc.ExitCode) -ForegroundColor Red
            $counts.FAIL++
            Write-Log "FAIL | $Action | $name | exit=$($proc.ExitCode)"
        }
    } catch {
        Write-Host ("  [FAIL]  could not start process: {0}" -f $_.Exception.Message) -ForegroundColor Red
        $counts.FAIL++
        Write-Log "FAIL | $Action | $name | error=$($_.Exception.Message)"
    }

    Write-Host ""
}

# ---------------------------------------------------------------------------
# SUMMARY
# ---------------------------------------------------------------------------
$total = $ScriptDefs.Count
Write-Host ("  {0}" -f ("=" * 62)) -ForegroundColor Cyan
Write-Host ("    {0} complete" -f $Action.ToUpper()) -ForegroundColor Cyan
Write-Host ("    OK: {0}   FAILED: {1}   SKIPPED (not found): {2}   of {3}" -f `
    $counts.OK, $counts.FAIL, $counts.SKIP, $total) -ForegroundColor $(
    if ($counts.FAIL -gt 0) { "Yellow" } elseif ($counts.SKIP -gt 0) { "Yellow" } else { "Green" })
Write-Host ("  {0}" -f ("=" * 62)) -ForegroundColor Cyan
Write-Host ""
if ($counts.SKIP -gt 0) {
    Write-Host ("    {0} script(s) were not found. Copy all create_test_*.ps1" -f $counts.SKIP) -ForegroundColor Yellow
    Write-Host ("    files to: {0}" -f $ScriptDir) -ForegroundColor Yellow
    Write-Host ""
}
Write-Host ("    Session log : {0}" -f $LogFile) -ForegroundColor DarkGray
Write-Host ("    Per-script logs also written beside each .ps1" )  -ForegroundColor DarkGray
Write-Host ""

Write-Log ("SESSION END   | $Action | OK=$($counts.OK) FAIL=$($counts.FAIL) SKIP=$($counts.SKIP) of $total")
Write-Log "----------------------------------------------------------------"

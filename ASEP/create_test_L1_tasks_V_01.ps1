# ***************************************************************************
# *  Script      : create_test_L1_tasks_V_01.ps1
# *  Version     : V_01
# *  Last Update : 2026-07-31 07:34 EST
# *  Purpose     : Level 1 synthetic check for Get-AutoStartTasks.
# *                Registers a scheduled task (AtLogon, current user, runs
# *                notepad.exe) so the analyzer lists it. Run this and the
# *                analyzer as the SAME user. Notepad WILL launch at next logon
# *                if left in place - remove when done.
# *  Admin       : NOT required (current-user task).
# *  Logging     : Appends to create_test_L1_tasks_V_01.log beside script.
# *  Options     : (default) Create  |  -Remove  |  -WhatIf
# * Copyright (c) 2026, Don Murdoch, Blue Team Handbook
# ***************************************************************************
[CmdletBinding(SupportsShouldProcess=$true)]
param([switch]$Remove)

$TaskName  = "ASEP_Synthetic_L1_Task"
$TaskPath  = "\"    # root folder
$Target    = Join-Path $env:SystemRoot 'System32\notepad.exe'
$LogFile   = if ($PSCommandPath) { $PSCommandPath -replace '\.ps1$','.log' } else { "create_test_L1_tasks_V_01.log" }

function Write-Log { param([string]$M)
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'; $tz = [TimeZoneInfo]::Local.StandardName
    Add-Content -LiteralPath $LogFile -Value "$ts | $tz | $M" -ErrorAction SilentlyContinue }

if ($Remove) {
    Write-Host "[*] Removing L1 Tasks synthetic check ($TaskName)..." -ForegroundColor Yellow
    $t = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($t) {
        if ($PSCmdlet.ShouldProcess($TaskName,"Unregister scheduled task")) {
            Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
            Write-Host "  [+] Removed task $TaskName" -ForegroundColor Green
            Write-Log "REMOVED | L1 Tasks | scheduled task $TaskName"
        }
    } else { Write-Host "  [-] Task not present" -ForegroundColor Gray }
    return
}

Write-Host "[*] Creating L1 Tasks synthetic check..." -ForegroundColor Yellow
if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    Write-Warning "Task '$TaskName' already exists. Run -Remove first."; return }
if ($PSCmdlet.ShouldProcess($TaskName,"Register AtLogon scheduled task -> $Target")) {
    $action  = New-ScheduledTaskAction  -Execute $Target
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
    $settings= New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 1)
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
        -Settings $settings -Description "ASEP synthetic Level 1 check (safe to delete)" `
        -RunLevel Limited -ErrorAction Stop | Out-Null
    Write-Host "  [+] Registered task '$TaskName' (AtLogon, $Target)" -ForegroundColor Green
    Write-Log "ENABLED | L1 Tasks | scheduled task $TaskName AtLogon -> $Target"
}
Write-Host "[+] Run analyzer at -Level 1; look for '$TaskName' in Scheduled Tasks." -ForegroundColor Cyan
Write-Host "    Remove: .\create_test_L1_tasks_V_01.ps1 -Remove" -ForegroundColor DarkGray
